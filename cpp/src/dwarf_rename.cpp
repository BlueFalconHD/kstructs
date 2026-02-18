#include "dwarf_rename.h"

#include "dwarf_utils.h"

#include <algorithm>
#include <cctype>
#include <functional>
#include <map>

namespace kstructs {

static std::string trim(const std::string &value) {
  size_t start = 0;
  while (start < value.size() && std::isspace(static_cast<unsigned char>(value[start]))) {
    start++;
  }
  size_t end = value.size();
  while (end > start && std::isspace(static_cast<unsigned char>(value[end - 1]))) {
    end--;
  }
  return value.substr(start, end - start);
}

void apply_type_prefix(TypeRegistry &registry, const std::string &prefix_input) {
  std::string prefix = sanitize_identifier(trim(prefix_input));
  if (prefix.empty()) {
    return;
  }

  std::map<KindNameKey, std::string> renames;

  for (const auto &pair : registry.structs) {
    renames[{pair.first.kind, pair.first.name}] = prefix + pair.first.name;
  }
  for (const auto &pair : registry.enums) {
    renames[{"enum", pair.first}] = prefix + pair.first;
  }
  for (const auto &pair : registry.typedefs) {
    renames[{"typedef", pair.first}] = prefix + pair.first;
  }

  for (const auto &pair : registry.inline_members) {
    renames[{pair.first.kind, pair.first.name}] = prefix + pair.first.name;
  }
  for (const auto &pair : registry.inline_unions) {
    renames[{pair.first.kind, pair.first.name}] = prefix + pair.first.name;
  }
  for (const auto &pair : registry.inline_members) {
    renames[{pair.second.kind, pair.second.name}] = prefix + pair.second.name;
  }
  for (const auto &pair : registry.inline_unions) {
    renames[{pair.second.kind, pair.second.name}] = prefix + pair.second.name;
  }

  std::function<void(CTypePtr &)> rewrite_type_ref = [&](CTypePtr &type_ref) {
    if (!type_ref) {
      return;
    }
    if (type_ref->kind == TypeKind::Named) {
      if ((type_ref->ref_kind == "struct" || type_ref->ref_kind == "union" ||
           type_ref->ref_kind == "enum" || type_ref->ref_kind == "typedef") &&
          !type_ref->name.empty()) {
        KindNameKey key{type_ref->ref_kind, type_ref->name};
        auto it = renames.find(key);
        if (it != renames.end()) {
          type_ref->name = it->second;
        }
      }
      return;
    }
    if ((type_ref->kind == TypeKind::Pointer || type_ref->kind == TypeKind::Array) &&
        type_ref->target) {
      rewrite_type_ref(type_ref->target);
    }
  };

  for (auto &pair : registry.structs) {
    for (auto &member : pair.second.members) {
      rewrite_type_ref(member.type_ref);
    }
  }
  for (auto &pair : registry.inline_members) {
    for (auto &member : pair.second.members) {
      rewrite_type_ref(member.type_ref);
    }
  }
  for (auto &pair : registry.inline_unions) {
    for (auto &member : pair.second.members) {
      rewrite_type_ref(member.type_ref);
    }
  }
  for (auto &pair : registry.typedefs) {
    rewrite_type_ref(pair.second.target);
  }

  std::map<KindNameKey, StructDecl> new_structs;
  for (auto &pair : registry.structs) {
    KindNameKey key = pair.first;
    auto it = renames.find(key);
    if (it != renames.end()) {
      key.name = it->second;
    }
    StructDecl decl = pair.second;
    decl.name = key.name;
    new_structs[key] = decl;
  }
  registry.structs = std::move(new_structs);

  for (auto &pair : registry.inline_members) {
    StructDecl &decl = pair.second;
    auto it = renames.find({decl.kind, decl.name});
    if (it != renames.end()) {
      decl.name = it->second;
    }
  }
  for (auto &pair : registry.inline_unions) {
    StructDecl &decl = pair.second;
    auto it = renames.find({decl.kind, decl.name});
    if (it != renames.end()) {
      decl.name = it->second;
    }
  }

  std::map<std::string, EnumDecl> new_enums;
  for (auto &pair : registry.enums) {
    std::string name = pair.first;
    auto it = renames.find({"enum", name});
    if (it != renames.end()) {
      name = it->second;
    }
    EnumDecl decl = pair.second;
    decl.name = name;
    new_enums[name] = decl;
  }
  registry.enums = std::move(new_enums);

  std::map<std::string, TypedefDecl> new_typedefs;
  for (auto &pair : registry.typedefs) {
    std::string name = pair.first;
    auto it = renames.find({"typedef", name});
    if (it != renames.end()) {
      name = it->second;
    }
    TypedefDecl decl = pair.second;
    decl.name = name;
    new_typedefs[name] = decl;
  }
  registry.typedefs = std::move(new_typedefs);

  std::map<InlineKey, StructDecl> new_inline_members;
  for (auto &pair : registry.inline_members) {
    InlineKey key = pair.first;
    auto it = renames.find({key.kind, key.name});
    if (it != renames.end()) {
      key.name = it->second;
    } else {
      key.name = prefix + key.name;
    }
    new_inline_members[key] = pair.second;
  }
  registry.inline_members = std::move(new_inline_members);

  std::map<InlineKey, StructDecl> new_inline_unions;
  for (auto &pair : registry.inline_unions) {
    InlineKey key = pair.first;
    auto it = renames.find({key.kind, key.name});
    if (it != renames.end()) {
      key.name = it->second;
    } else {
      key.name = prefix + key.name;
    }
    new_inline_unions[key] = pair.second;
  }
  registry.inline_unions = std::move(new_inline_unions);
}

} // namespace kstructs
