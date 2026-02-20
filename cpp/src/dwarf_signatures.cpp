#include "dwarf_signatures.h"

#include "dwarf_utils.h"

#include <string>

#include <llvm/ADT/ArrayRef.h>
#include <llvm/ADT/StringExtras.h>
#include <llvm/Support/SHA1.h>

namespace kstructs {

namespace {
struct SigHasher {
  llvm::SHA1 sha;

  void mix_bytes(const uint8_t *data, size_t size) {
    sha.update(llvm::ArrayRef<uint8_t>(data, size));
  }

  void mix_byte(uint8_t byte) { mix_bytes(&byte, 1); }

  void mix_u64(uint64_t value) {
    uint8_t bytes[8];
    for (int i = 0; i < 8; ++i) {
      bytes[i] = static_cast<uint8_t>((value >> (i * 8)) & 0xFF);
    }
    mix_bytes(bytes, sizeof(bytes));
  }

  void mix_i64(int64_t value) { mix_u64(static_cast<uint64_t>(value)); }

  void mix_bool(bool value) { mix_byte(value ? 1 : 0); }

  void mix_str(const std::string &value) {
    mix_u64(static_cast<uint64_t>(value.size()));
    if (!value.empty()) {
      mix_bytes(reinterpret_cast<const uint8_t *>(value.data()), value.size());
    }
  }

  void mix_sig(const TypeSignature &sig) {
    mix_bytes(sig.bytes.data(), sig.bytes.size());
  }

  TypeSignature finish() {
    TypeSignature out;
    out.bytes = sha.final();
    return out;
  }
};

void mix_optional_i64(SigHasher &hasher, const std::optional<int64_t> &value) {
  hasher.mix_bool(value.has_value());
  if (value) {
    hasher.mix_i64(*value);
  }
}

void mix_qualifiers(SigHasher &hasher, const std::vector<std::string> &quals) {
  hasher.mix_u64(static_cast<uint64_t>(quals.size()));
  for (const auto &q : quals) {
    hasher.mix_str(q);
  }
}

TypeSignature signature_named(const std::string &ref_kind, const std::string &name,
                              const std::vector<std::string> &qualifiers) {
  SigHasher hasher;
  hasher.mix_byte('N');
  hasher.mix_str(ref_kind);
  hasher.mix_str(name);
  mix_qualifiers(hasher, qualifiers);
  return hasher.finish();
}

TypeSignature signature_rec(const std::string &ref_kind, const std::string &name,
                            const std::vector<std::string> &qualifiers) {
  SigHasher hasher;
  hasher.mix_byte('R');
  hasher.mix_str(ref_kind);
  hasher.mix_str(name);
  mix_qualifiers(hasher, qualifiers);
  return hasher.finish();
}

TypeSignature signature_pointer(const TypeSignature &target) {
  SigHasher hasher;
  hasher.mix_byte('P');
  hasher.mix_sig(target);
  return hasher.finish();
}

TypeSignature signature_array(const TypeSignature &target, const std::optional<int64_t> &count) {
  SigHasher hasher;
  hasher.mix_byte('A');
  mix_optional_i64(hasher, count);
  hasher.mix_sig(target);
  return hasher.finish();
}

TypeSignature signature_unknown() {
  SigHasher hasher;
  hasher.mix_byte('U');
  return hasher.finish();
}

TypeSignature signature_layout(const std::string &kind,
                               const TypeSignature &struct_sig,
                               const std::vector<std::string> &qualifiers) {
  SigHasher hasher;
  hasher.mix_byte('L');
  hasher.mix_str(kind);
  hasher.mix_sig(struct_sig);
  mix_qualifiers(hasher, qualifiers);
  return hasher.finish();
}

TypeSignature struct_signature_with(
    const TypeRegistry &registry,
    const StructDecl &decl,
    const std::function<TypeSignature(const CTypePtr &)> &type_sig_fn,
    bool include_member_names) {
  SigHasher hasher;
  hasher.mix_byte('S');
  hasher.mix_str(decl.kind);
  mix_optional_i64(hasher, decl.size);
  for (const auto &member : decl.members) {
    hasher.mix_byte('M');
    if (include_member_names) {
      hasher.mix_str(member.name);
    } else {
      hasher.mix_str("_");
    }
    hasher.mix_sig(type_sig_fn(member.type_ref));
    mix_optional_i64(hasher, member.offset);
    mix_optional_i64(hasher, member.bit_size);
    mix_optional_i64(hasher, member.bit_offset);
  }
  return hasher.finish();
}

} // namespace

std::string signature_hex(const TypeSignature &sig) {
  llvm::ArrayRef<uint8_t> bytes(sig.bytes.data(), sig.bytes.size());
  return llvm::toHex(bytes, true);
}

std::string signature_digest(const TypeSignature &sig) {
  std::string hex = signature_hex(sig);
  if (hex.size() <= 8) {
    return hex;
  }
  return hex.substr(0, 8);
}

TypeSignature normalized_type_signature(
    const TypeRegistry &registry,
    const CTypePtr &type_ref,
    std::unordered_map<std::string, TypeSignature> &cache,
    std::unordered_set<std::string> &stack,
    bool layout_for_named,
    bool include_member_names) {
  std::unordered_set<std::string> seen;
  CTypePtr resolved = resolve_typedef(registry, type_ref, seen);
  if (!resolved) {
    return signature_unknown();
  }

  if (resolved->kind == TypeKind::Named) {
    if ((resolved->ref_kind == "struct" || resolved->ref_kind == "union") &&
        !resolved->name.empty()) {
      KindNameKey key{resolved->ref_kind, resolved->name};
      auto it = registry.structs.find(key);
      if (it != registry.structs.end()) {
        const StructDecl &decl = it->second;
        if (!decl.opaque && (layout_for_named || decl.name_origin == "member" || decl.name_origin == "anon")) {
          std::string cache_key = "layout|" + resolved->ref_kind + "|" + resolved->name +
                                  "|" + (layout_for_named ? "1" : "0") +
                                  "|" + (include_member_names ? "1" : "0");
          auto cached = cache.find(cache_key);
          if (cached != cache.end()) {
            return cached->second;
          }
          std::string stack_key = resolved->ref_kind + "|" + resolved->name;
          if (stack.count(stack_key)) {
            return signature_rec(resolved->ref_kind, resolved->name, resolved->qualifiers);
          }
          stack.insert(stack_key);
          TypeSignature sig = struct_signature_with(
              registry,
              decl,
              [&](const CTypePtr &ref) {
                return normalized_type_signature(registry, ref, cache, stack,
                                                 layout_for_named, include_member_names);
              },
              include_member_names);
          stack.erase(stack_key);
          TypeSignature out = signature_layout(resolved->ref_kind, sig, resolved->qualifiers);
          cache[cache_key] = out;
          return out;
        }
      }
    }
    return signature_named(resolved->ref_kind, resolved->name, resolved->qualifiers);
  }

  if (resolved->kind == TypeKind::Pointer) {
    TypeSignature target = resolved->target
                               ? normalized_type_signature(registry, resolved->target, cache, stack,
                                                           layout_for_named, include_member_names)
                               : signature_named("base", "void", {});
    return signature_pointer(target);
  }

  if (resolved->kind == TypeKind::Array) {
    TypeSignature target = resolved->target
                               ? normalized_type_signature(registry, resolved->target, cache, stack,
                                                           layout_for_named, include_member_names)
                               : signature_named("base", "void", {});
    return signature_array(target, resolved->count);
  }

  return signature_unknown();
}

} // namespace kstructs
