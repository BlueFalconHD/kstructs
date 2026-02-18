#include "dwarf_utils.h"

#include <llvm/ADT/ArrayRef.h>
#include <llvm/ADT/StringExtras.h>
#include <llvm/ADT/StringRef.h>
#include <llvm/Support/SHA1.h>

namespace kstructs {

std::string sanitize_identifier(const std::string &name) {
  if (name.empty()) {
    return name;
  }
  std::string out;
  out.reserve(name.size() + 1);
  for (char ch : name) {
    if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
        (ch >= '0' && ch <= '9') || ch == '_') {
      out.push_back(ch);
    } else {
      out.push_back('_');
    }
  }
  if (!out.empty() && (out[0] >= '0' && out[0] <= '9')) {
    out.insert(out.begin(), '_');
  }
  return out;
}

CTypePtr resolve_typedef(const TypeRegistry &registry, const CTypePtr &type_ref,
                         std::unordered_set<std::string> &seen) {
  if (!type_ref || type_ref->kind != TypeKind::Named ||
      type_ref->ref_kind != "typedef") {
    return type_ref;
  }
  if (type_ref->name.empty()) {
    return type_ref;
  }
  if (seen.count(type_ref->name)) {
    return type_ref;
  }
  seen.insert(type_ref->name);
  auto it = registry.typedefs.find(type_ref->name);
  if (it == registry.typedefs.end()) {
    return type_ref;
  }
  return resolve_typedef(registry, it->second.target, seen);
}

CTypePtr clone_type_ref(const CTypePtr &type_ref) {
  if (!type_ref) {
    return nullptr;
  }
  auto clone = std::make_shared<CType>();
  clone->kind = type_ref->kind;
  clone->name = type_ref->name;
  clone->ref_kind = type_ref->ref_kind;
  clone->count = type_ref->count;
  clone->qualifiers = type_ref->qualifiers;
  if (type_ref->target) {
    clone->target = clone_type_ref(type_ref->target);
  }
  return clone;
}

bool is_synthetic_member_name(const std::string &name) {
  return name.rfind("__anon_member", 0) == 0;
}

std::string sig_digest(const std::string &input) {
  llvm::SHA1 sha1;
  sha1.update(llvm::StringRef(input));
  auto hash = sha1.final();
  llvm::ArrayRef<uint8_t> bytes(hash.data(), hash.size());
  std::string hex = llvm::toHex(bytes, true);
  if (hex.size() <= 8) {
    return hex;
  }
  return hex.substr(0, 8);
}

} // namespace kstructs
