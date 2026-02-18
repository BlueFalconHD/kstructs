#include "dwarf_signatures.h"

#include "dwarf_utils.h"

#include <sstream>

namespace kstructs {

static std::string opt_int(const std::optional<int64_t> &value) {
  if (value) {
    return std::to_string(*value);
  }
  return "null";
}

static std::string join_qualifiers(const std::vector<std::string> &quals) {
  if (quals.empty()) {
    return "";
  }
  std::ostringstream oss;
  bool first = true;
  for (const auto &q : quals) {
    if (!first) {
      oss << ",";
    }
    first = false;
    oss << q;
  }
  return oss.str();
}

static std::string struct_signature_with(
    const TypeRegistry &registry,
    const StructDecl &decl,
    const std::function<std::string(const CTypePtr &)> &type_sig_fn,
    bool include_member_names) {
  std::ostringstream oss;
  oss << "struct(" << decl.kind << "," << opt_int(decl.size) << ",[";
  bool first = true;
  for (const auto &member : decl.members) {
    if (!first) {
      oss << ",";
    }
    first = false;
    oss << "(";
    if (include_member_names) {
      oss << member.name;
    } else {
      oss << "_";
    }
    oss << "," << type_sig_fn(member.type_ref);
    oss << "," << opt_int(member.offset);
    oss << "," << opt_int(member.bit_size);
    oss << "," << opt_int(member.bit_offset);
    oss << ")";
  }
  oss << "])";
  return oss.str();
}

std::string normalized_type_signature(
    const TypeRegistry &registry,
    const CTypePtr &type_ref,
    std::unordered_map<std::string, std::string> &cache,
    std::unordered_set<std::string> &stack,
    bool layout_for_named,
    bool include_member_names) {
  std::unordered_set<std::string> seen;
  CTypePtr resolved = resolve_typedef(registry, type_ref, seen);
  if (!resolved) {
    return "unknown";
  }

  if (resolved->kind == TypeKind::Named) {
    std::string qualifiers = join_qualifiers(resolved->qualifiers);
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
            return "rec|" + resolved->ref_kind + "|" + resolved->name + "|" + qualifiers;
          }
          stack.insert(stack_key);
          std::string sig = struct_signature_with(
              registry,
              decl,
              [&](const CTypePtr &ref) {
                return normalized_type_signature(registry, ref, cache, stack,
                                                 layout_for_named, include_member_names);
              },
              include_member_names);
          stack.erase(stack_key);
          std::string out = "layout|" + resolved->ref_kind + "|" + sig + "|" + qualifiers;
          cache[cache_key] = out;
          return out;
        }
      }
    }
    return "named|" + resolved->ref_kind + "|" + resolved->name + "|" + qualifiers;
  }

  if (resolved->kind == TypeKind::Pointer) {
    CTypePtr target = resolved->target ? resolved->target : make_named("void", "base");
    return "ptr|" + normalized_type_signature(registry, target, cache, stack,
                                              layout_for_named, include_member_names);
  }

  if (resolved->kind == TypeKind::Array) {
    CTypePtr target = resolved->target ? resolved->target : make_named("void", "base");
    std::string count = resolved->count ? std::to_string(*resolved->count) : "null";
    return "arr|" + count + "|" +
           normalized_type_signature(registry, target, cache, stack,
                                     layout_for_named, include_member_names);
  }

  return "unknown";
}

} // namespace kstructs
