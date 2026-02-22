#include "dwarf_corrections.h"

#include "dwarf_signatures.h"
#include "dwarf_utils.h"

#include <iostream>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>

#include <llvm/ADT/StringExtras.h>

namespace kstructs {

static std::set<KindNameKey> collect_used_types(const TypeRegistry &registry) {
  std::set<KindNameKey> used;

  std::function<void(const CTypePtr &)> visit = [&](const CTypePtr &type_ref) {
    std::unordered_set<std::string> seen;
    CTypePtr resolved = resolve_typedef(registry, type_ref, seen);
    if (!resolved) {
      return;
    }
    if (resolved->kind == TypeKind::Named) {
      if ((resolved->ref_kind == "struct" || resolved->ref_kind == "union" ||
           resolved->ref_kind == "enum") &&
          !resolved->name.empty()) {
        used.insert({resolved->ref_kind, resolved->name});
      }
      return;
    }
    if ((resolved->kind == TypeKind::Pointer || resolved->kind == TypeKind::Array) &&
        resolved->target) {
      visit(resolved->target);
    }
  };

  for (const auto &pair : registry.structs) {
    const StructDecl &decl = pair.second;
    for (const auto &member : decl.members) {
      visit(member.type_ref);
    }
  }

  for (const auto &pair : registry.typedefs) {
    const TypedefDecl &decl = pair.second;
    visit(decl.target);
  }

  return used;
}

static void prune_unused_synthetic(TypeRegistry &registry, const CorrectionLog &log) {
  int removed = 0;
  while (true) {
    auto used = collect_used_types(registry);
    std::set<KindNameKey> keep;
    for (const auto &pair : registry.structs) {
      const StructDecl &decl = pair.second;
      if (decl.name_origin != "member" && decl.name_origin != "anon") {
        keep.insert(pair.first);
      }
    }
    std::vector<KindNameKey> to_remove;
    for (const auto &pair : registry.structs) {
      const KindNameKey &key = pair.first;
      const StructDecl &decl = pair.second;
      if (used.count(key) == 0 && keep.count(key) == 0 &&
          (decl.name_origin == "member" || decl.name_origin == "anon")) {
        to_remove.push_back(key);
      }
    }
    if (to_remove.empty()) {
      break;
    }
    for (const auto &key : to_remove) {
      registry.structs.erase(key);
      removed += 1;
    }
  }
  if (log) {
    log("pruned " + std::to_string(removed) + " synthetic structs/unions");
  }
}

static void apply_xnu_struct_group_name(TypeRegistry &registry, const CorrectionLog &log) {
  std::map<KindNameKey, std::pair<CTypePtr, std::string>> collapse;
  std::unordered_map<std::string, TypeSignature> cache;

  auto log_msg = [&](const std::string &msg) {
    if (log) {
      log(msg);
    }
  };

  for (const auto &pair : registry.structs) {
    const KindNameKey &key = pair.first;
    const StructDecl &union_decl = pair.second;
    if (key.kind != "union" || union_decl.opaque) {
      continue;
    }
    if (union_decl.members.empty()) {
      continue;
    }
    bool has_bits = false;
    for (const auto &member : union_decl.members) {
      if (member.bit_size) {
        has_bits = true;
        break;
      }
    }
    if (has_bits) {
      log_msg("skip union " + key.name + ": bitfields present");
      continue;
    }

    std::vector<TypeSignature> sigs;
    for (const auto &member : union_decl.members) {
      std::unordered_set<std::string> stack;
      sigs.push_back(normalized_type_signature(registry, member.type_ref, cache, stack, true, false));
    }

    bool all_equal = true;
    for (size_t i = 1; i < sigs.size(); ++i) {
      if (sigs[i] != sigs[0]) {
        all_equal = false;
        break;
      }
    }
    if (!all_equal) {
      if (log) {
        std::string details;
        for (size_t i = 0; i < union_decl.members.size(); ++i) {
          if (!details.empty()) {
            details += ", ";
          }
          details += union_decl.members[i].name + ":" + signature_digest(sigs[i]);
        }
        log_msg("skip union " + key.name + ": member types differ (" + details + ")");
      } else {
        log_msg("skip union " + key.name + ": member types differ");
      }
      continue;
    }

    const MemberInfo *canonical = nullptr;
    for (const auto &member : union_decl.members) {
      if (!is_synthetic_member_name(member.name)) {
        canonical = &member;
        break;
      }
    }
    if (!canonical) {
      canonical = &union_decl.members[0];
    }
    collapse[key] = {clone_type_ref(canonical->type_ref), canonical->name};
    log_msg("collapse union " + key.name + " -> " + canonical->name);
  }

  if (collapse.empty()) {
    log_msg("no unions collapsed");
    return;
  }

  auto rewrite_type_ref = [&](CTypePtr &type_ref, const auto &self) -> void {
    if (!type_ref) {
      return;
    }
    std::unordered_set<std::string> seen;
    CTypePtr resolved = resolve_typedef(registry, type_ref, seen);
    if (resolved && resolved->kind == TypeKind::Named && resolved->ref_kind == "union" && !resolved->name.empty()) {
      KindNameKey ukey{"union", resolved->name};
      auto it = collapse.find(ukey);
      if (it != collapse.end()) {
        type_ref = clone_type_ref(it->second.first);
        return;
      }
    }
    if ((type_ref->kind == TypeKind::Pointer || type_ref->kind == TypeKind::Array) && type_ref->target) {
      self(type_ref->target, self);
    }
  };

  for (auto &pair : registry.structs) {
    StructDecl &decl = pair.second;
    for (auto &member : decl.members) {
      std::unordered_set<std::string> seen;
      CTypePtr resolved = resolve_typedef(registry, member.type_ref, seen);
      if (resolved && resolved->kind == TypeKind::Named && resolved->ref_kind == "union" && !resolved->name.empty()) {
        KindNameKey ukey{"union", resolved->name};
        auto it = collapse.find(ukey);
        if (it != collapse.end()) {
          member.type_ref = clone_type_ref(it->second.first);
          if (is_synthetic_member_name(member.name) && !is_synthetic_member_name(it->second.second)) {
            member.name = it->second.second;
          }
        }
      }
    }
  }

  for (auto &pair : registry.structs) {
    StructDecl &decl = pair.second;
    for (auto &member : decl.members) {
      rewrite_type_ref(member.type_ref, rewrite_type_ref);
    }
  }

  for (auto &pair : registry.typedefs) {
    rewrite_type_ref(pair.second.target, rewrite_type_ref);
  }

  for (const auto &pair : collapse) {
    registry.structs.erase(pair.first);
  }

  prune_unused_synthetic(registry, log);
}

static std::optional<std::string> pointer_to_named_struct(const TypeRegistry &registry,
                                                          const CTypePtr &type_ref,
                                                          int depth) {
  std::unordered_set<std::string> seen;
  CTypePtr current = resolve_typedef(registry, type_ref, seen);
  for (int i = 0; i < depth; ++i) {
    if (!current || current->kind != TypeKind::Pointer || !current->target) {
      return std::nullopt;
    }
    seen.clear();
    current = resolve_typedef(registry, current->target, seen);
  }
  if (current && current->kind == TypeKind::Named && current->ref_kind == "struct" && !current->name.empty()) {
    return current->name;
  }
  return std::nullopt;
}

static std::optional<std::string> is_list_entry_struct(const TypeRegistry &registry, const StructDecl &decl) {
  if (decl.kind != "struct" || decl.opaque) {
    return std::nullopt;
  }
  if (decl.members.size() != 2) {
    return std::nullopt;
  }
  const MemberInfo *next = nullptr;
  const MemberInfo *prev = nullptr;
  for (const auto &member : decl.members) {
    if (member.name == "le_next") {
      next = &member;
    } else if (member.name == "le_prev") {
      prev = &member;
    }
  }
  if (!next || !prev) {
    return std::nullopt;
  }
  auto target_next = pointer_to_named_struct(registry, next->type_ref, 1);
  auto target_prev = pointer_to_named_struct(registry, prev->type_ref, 2);
  if (!target_next || !target_prev) {
    return std::nullopt;
  }
  if (*target_next != *target_prev) {
    return std::nullopt;
  }
  return target_next;
}

static void apply_xnu_list_entry_inline(TypeRegistry &registry, const CorrectionLog &log) {
  std::unordered_map<std::string, StructDecl> list_structs;
  for (const auto &pair : registry.structs) {
    const KindNameKey &key = pair.first;
    const StructDecl &decl = pair.second;
    if (key.kind != "struct") {
      continue;
    }
    if (is_list_entry_struct(registry, decl)) {
      list_structs[key.name] = decl;
    }
  }
  if (list_structs.empty()) {
    if (log) {
      log("no LIST_ENTRY structs found");
    }
    return;
  }

  int inlined = 0;
  for (auto &pair : registry.structs) {
    const KindNameKey &key = pair.first;
    StructDecl &decl = pair.second;
    if (decl.opaque) {
      continue;
    }
    for (auto &member : decl.members) {
      std::unordered_set<std::string> seen;
      CTypePtr resolved = resolve_typedef(registry, member.type_ref, seen);
      if (!resolved || resolved->kind != TypeKind::Named || resolved->ref_kind != "struct" || resolved->name.empty()) {
        continue;
      }
      auto it = list_structs.find(resolved->name);
      if (it == list_structs.end()) {
        continue;
      }
      registry.inline_members[{key.kind, key.name, member.name}] = it->second;
      inlined += 1;
      if (log) {
        log("inline LIST_ENTRY " + resolved->name + " in " + key.name + "." + member.name);
      }
    }
  }

  if (log && inlined == 0) {
    log("no LIST_ENTRY usages inlined");
  }
}

static void apply_xnu_anonymous_union_inline(TypeRegistry &registry, const CorrectionLog &log) {
  int inlined = 0;

  for (auto &pair : registry.structs) {
    const KindNameKey &key = pair.first;
    StructDecl &decl = pair.second;
    if (decl.opaque) {
      continue;
    }
    for (auto &member : decl.members) {
      std::unordered_set<std::string> seen;
      CTypePtr resolved = resolve_typedef(registry, member.type_ref, seen);
      if (!resolved || resolved->kind != TypeKind::Named || resolved->ref_kind != "union" || resolved->name.empty()) {
        continue;
      }
      KindNameKey ukey{"union", resolved->name};
      auto it = registry.structs.find(ukey);
      if (it == registry.structs.end() || it->second.opaque) {
        if (log) {
          log("skip union " + resolved->name + " in " + key.name + "." + member.name + ": missing decl");
        }
        continue;
      }
      const StructDecl &union_decl = it->second;
      if (union_decl.name_origin != "member" && union_decl.name_origin != "anon") {
        if (log) {
          log("skip union " + resolved->name + " in " + key.name + "." + member.name + ": named union");
        }
        continue;
      }

      registry.inline_unions[{key.kind, key.name, member.name}] = union_decl;
      inlined += 1;
      if (log) {
        log("inline anonymous union " + resolved->name + " into " + key.name + "." + member.name);
      }
    }
  }

  if (log && inlined == 0) {
    log("no anonymous unions inlined");
  }
}

static void apply_inline_anonymous_structs(TypeRegistry &registry, const CorrectionLog &log) {
  int inlined = 0;

  for (auto &pair : registry.structs) {
    const KindNameKey &key = pair.first;
    StructDecl &decl = pair.second;
    if (decl.opaque) {
      continue;
    }
    for (auto &member : decl.members) {
      InlineKey inline_key{key.kind, key.name, member.name};
      if (registry.inline_members.count(inline_key) || registry.inline_unions.count(inline_key)) {
        continue;
      }
      std::unordered_set<std::string> seen;
      CTypePtr resolved = resolve_typedef(registry, member.type_ref, seen);
      if (!resolved || resolved->kind != TypeKind::Named || resolved->ref_kind != "struct" || resolved->name.empty()) {
        continue;
      }
      KindNameKey skey{"struct", resolved->name};
      auto it = registry.structs.find(skey);
      if (it == registry.structs.end() || it->second.opaque) {
        if (log) {
          log("skip struct " + resolved->name + " in " + key.name + "." + member.name + ": missing decl");
        }
        continue;
      }
      const StructDecl &struct_decl = it->second;
      if (struct_decl.name_origin != "anon" && struct_decl.name_origin != "member") {
        if (log) {
          log("skip struct " + resolved->name + " in " + key.name + "." + member.name + ": named struct");
        }
        continue;
      }
      registry.inline_members[inline_key] = struct_decl;
      inlined += 1;
      if (log) {
        log("inline anonymous struct " + resolved->name + " into " + key.name + "." + member.name);
      }
    }
  }

  if (log && inlined == 0) {
    log("no anonymous structs inlined");
  }
}

static std::optional<CTypePtr> enum_fixed_width_type(const EnumDecl &enum_decl) {
  if (!enum_decl.size || *enum_decl.size <= 0) {
    return std::nullopt;
  }
  bool signed_value = false;
  for (const auto &pair : enum_decl.enumerators) {
    if (pair.second < 0) {
      signed_value = true;
      break;
    }
  }
  int64_t size = *enum_decl.size;
  std::string name;
  if (size == 1) {
    name = signed_value ? "int8_t" : "uint8_t";
  } else if (size == 2) {
    name = signed_value ? "int16_t" : "uint16_t";
  } else if (size == 4) {
    name = signed_value ? "int32_t" : "uint32_t";
  } else if (size == 8) {
    name = signed_value ? "int64_t" : "uint64_t";
  } else {
    return std::nullopt;
  }
  return make_named(name, "base");
}

static void apply_xnu_enum_fixed_width(TypeRegistry &registry, const CorrectionLog &log) {
  int adjusted = 0;
  for (auto &pair : registry.enums) {
    EnumDecl &enum_decl = pair.second;
    if (enum_decl.opaque) {
      continue;
    }
    CTypePtr base_ref;
    if (enum_decl.underlying) {
      base_ref = make_named(*enum_decl.underlying, "base");
    } else {
      auto fixed = enum_fixed_width_type(enum_decl);
      if (!fixed) {
        continue;
      }
      base_ref = *fixed;
    }

    if (!enum_decl.underlying) {
      if (!enum_decl.size || *enum_decl.size >= 4) {
        continue;
      }
    }

    enum_decl.typedef_as = base_ref->name;

    for (auto &td_pair : registry.typedefs) {
      TypedefDecl &td = td_pair.second;
      std::unordered_set<std::string> seen;
      CTypePtr resolved = resolve_typedef(registry, td.target, seen);
      if (resolved && resolved->kind == TypeKind::Named && resolved->ref_kind == "enum" &&
          resolved->name == enum_decl.name) {
        td.target = make_named(base_ref->name, "base");
      }
    }

    if (registry.typedefs.find(enum_decl.name) == registry.typedefs.end()) {
      registry.typedefs[enum_decl.name] = TypedefDecl{
          enum_decl.name, make_named(base_ref->name, "base")};
    }

    adjusted += 1;
    if (log) {
      log("enum " + enum_decl.name + " size " +
          (enum_decl.size ? std::to_string(*enum_decl.size) : "?") +
          " -> typedef " + base_ref->name);
    }
  }

  if (log && adjusted == 0) {
    log("no enums adjusted");
  }
}

static const std::unordered_map<std::string, int64_t> BASE_SIZE_HINTS = {
    {"_Bool", 1},
    {"bool", 1},
    {"char", 1},
    {"signed char", 1},
    {"unsigned char", 1},
    {"int8_t", 1},
    {"uint8_t", 1},
    {"short", 2},
    {"short int", 2},
    {"signed short", 2},
    {"signed short int", 2},
    {"unsigned short", 2},
    {"unsigned short int", 2},
    {"int16_t", 2},
    {"uint16_t", 2},
    {"int", 4},
    {"signed", 4},
    {"signed int", 4},
    {"unsigned", 4},
    {"unsigned int", 4},
    {"int32_t", 4},
    {"uint32_t", 4},
    {"long long", 8},
    {"long long int", 8},
    {"signed long long", 8},
    {"signed long long int", 8},
    {"unsigned long long", 8},
    {"unsigned long long int", 8},
    {"int64_t", 8},
    {"uint64_t", 8},
    {"float", 4},
    {"double", 8},
    {"long double", 16},
    {"__int128", 16},
    {"unsigned __int128", 16},
};

static std::optional<int64_t> base_size(const TypeRegistry &registry, const std::string &name) {
  auto it = registry.base_sizes.find(name);
  if (it != registry.base_sizes.end()) {
    return it->second;
  }
  if (name == "long" || name == "long int" || name == "signed long" ||
      name == "signed long int" || name == "unsigned long" ||
      name == "unsigned long int" || name == "size_t" ||
      name == "uintptr_t" || name == "intptr_t" ||
      name == "ptrdiff_t") {
    if (registry.pointer_size) {
      return registry.pointer_size;
    }
  }
  auto hint = BASE_SIZE_HINTS.find(name);
  if (hint != BASE_SIZE_HINTS.end()) {
    return hint->second;
  }
  return std::nullopt;
}

static std::optional<int64_t> type_size(const TypeRegistry &registry, const CTypePtr &type_ref) {
  std::unordered_set<std::string> seen;
  CTypePtr resolved = resolve_typedef(registry, type_ref, seen);
  if (!resolved) {
    return std::nullopt;
  }
  if (resolved->kind == TypeKind::Named) {
    const std::string &name = resolved->name;
    if (resolved->ref_kind == "base") {
      return base_size(registry, name);
    }
    if (resolved->ref_kind == "enum") {
      auto it = registry.enums.find(name);
      if (it == registry.enums.end()) {
        return std::nullopt;
      }
      const EnumDecl &enum_decl = it->second;
      if (enum_decl.underlying) {
        return base_size(registry, *enum_decl.underlying);
      }
      return enum_decl.size;
    }
    if (resolved->ref_kind == "struct" || resolved->ref_kind == "union") {
      auto it = registry.structs.find({resolved->ref_kind, name});
      if (it == registry.structs.end()) {
        return std::nullopt;
      }
      return it->second.size;
    }
    return std::nullopt;
  }
  if (resolved->kind == TypeKind::Pointer) {
    return registry.pointer_size ? registry.pointer_size : 8;
  }
  if (resolved->kind == TypeKind::Array) {
    if (!resolved->target) {
      return std::nullopt;
    }
    auto elem_size = type_size(registry, resolved->target);
    if (!elem_size || !resolved->count) {
      return std::nullopt;
    }
    return *elem_size * *resolved->count;
  }
  return std::nullopt;
}

static std::optional<int64_t> type_alignment(const TypeRegistry &registry, const CTypePtr &type_ref,
                                            std::set<KindNameKey> *seen = nullptr) {
  std::unordered_set<std::string> seen_td;
  CTypePtr resolved = resolve_typedef(registry, type_ref, seen_td);
  if (!resolved) {
    return std::nullopt;
  }
  if (resolved->kind == TypeKind::Named) {
    const std::string &name = resolved->name;
    if (resolved->ref_kind == "base") {
      return base_size(registry, name);
    }
    if (resolved->ref_kind == "enum") {
      auto it = registry.enums.find(name);
      if (it == registry.enums.end()) {
        return std::nullopt;
      }
      const EnumDecl &enum_decl = it->second;
      if (enum_decl.underlying) {
        return base_size(registry, *enum_decl.underlying);
      }
      return enum_decl.size;
    }
    if (resolved->ref_kind == "struct" || resolved->ref_kind == "union") {
      auto it = registry.structs.find({resolved->ref_kind, name});
      if (it == registry.structs.end()) {
        return std::nullopt;
      }
      const StructDecl &decl = it->second;
      if (decl.packed) {
        return 1;
      }
      std::set<KindNameKey> local_seen;
      auto &current_seen = seen ? *seen : local_seen;
      KindNameKey key{resolved->ref_kind, name};
      if (current_seen.count(key)) {
        return std::nullopt;
      }
      current_seen.insert(key);
      int64_t max_align = 1;
      for (const auto &member : decl.members) {
        if (member.bit_size) {
          continue;
        }
        auto align = type_alignment(registry, member.type_ref, &current_seen);
        if (!align) {
          continue;
        }
        if (*align > max_align) {
          max_align = *align;
        }
      }
      current_seen.erase(key);
      if (decl.pack && *decl.pack > 1 && *decl.pack < max_align) {
        max_align = *decl.pack;
      }
      return max_align;
    }
    return std::nullopt;
  }
  if (resolved->kind == TypeKind::Pointer) {
    return registry.pointer_size ? registry.pointer_size : 8;
  }
  if (resolved->kind == TypeKind::Array) {
    if (!resolved->target) {
      return std::nullopt;
    }
    return type_alignment(registry, resolved->target, seen);
  }
  return std::nullopt;
}

static int64_t align_up(int64_t value, int64_t align) {
  if (align <= 1) {
    return value;
  }
  return (value + align - 1) / align * align;
}

static std::pair<std::optional<int64_t>, std::vector<std::string>>
max_member_alignment(const TypeRegistry &registry, const StructDecl &decl) {
  std::optional<int64_t> max_align;
  std::vector<std::string> unknown;
  for (const auto &member : decl.members) {
    if (member.bit_size) {
      continue;
    }
    auto align = type_alignment(registry, member.type_ref, nullptr);
    if (member.alignment) {
      if (!align) {
        align = member.alignment;
      } else if (*member.alignment > *align) {
        align = member.alignment;
      }
    }
    if (!align) {
      unknown.push_back(member.name);
      continue;
    }
    if (!max_align || *align > *max_align) {
      max_align = align;
    }
  }
  return {max_align, unknown};
}

static std::pair<bool, std::optional<int64_t>>
struct_layout_matches(const TypeRegistry &registry, const StructDecl &decl, bool packed) {
  int64_t offset = 0;
  int64_t max_align = 1;
  for (const auto &member : decl.members) {
    if (member.bit_size) {
      return {false, std::nullopt};
    }
    auto size = type_size(registry, member.type_ref);
    auto align = type_alignment(registry, member.type_ref, nullptr);
    if (!size || !align) {
      return {false, std::nullopt};
    }
    if (packed) {
      align = 1;
    }
    if (*align > max_align) {
      max_align = *align;
    }
    offset = align_up(offset, *align);
    if (member.offset && offset != *member.offset) {
      return {false, std::nullopt};
    }
    offset += *size;
  }
  int64_t struct_align = packed ? 1 : max_align;
  int64_t size = align_up(offset, struct_align);
  return {true, size};
}

static std::optional<int64_t> infer_alignment_for_offset(int64_t cursor,
                                                         int64_t offset,
                                                         int64_t min_align,
                                                         std::optional<int64_t> pack) {
  if (offset < cursor) {
    return std::nullopt;
  }
  int64_t limit = pack && *pack > 1 ? *pack : 64;
  int64_t align = std::max<int64_t>(1, min_align);
  for (; align <= limit; align <<= 1) {
    if (align_up(cursor, align) == offset) {
      return align;
    }
  }
  return std::nullopt;
}

static void apply_pack_from_alignment(TypeRegistry &registry, const CorrectionLog &log) {
  for (auto &pair : registry.structs) {
    StructDecl &decl = pair.second;
    if (decl.kind != "struct" || decl.opaque || decl.packed || !decl.alignment) {
      continue;
    }
    auto [max_align, unknown] = max_member_alignment(registry, decl);
    (void)unknown;
    if (!max_align) {
      continue;
    }
    if (*decl.alignment > 1 && *decl.alignment < *max_align) {
      decl.pack = decl.alignment;
      decl.alignment.reset();
      if (log) {
        log("pack struct " + decl.name + " to alignment " + std::to_string(*decl.pack));
      }
    }
  }
}

static void apply_infer_member_alignment(TypeRegistry &registry, const CorrectionLog &log) {
  for (auto &pair : registry.structs) {
    StructDecl &decl = pair.second;
    if (decl.kind != "struct" || decl.opaque) {
      continue;
    }
    bool has_bits = false;
    for (const auto &member : decl.members) {
      if (member.bit_size) {
        has_bits = true;
        break;
      }
    }
    if (has_bits) {
      continue;
    }
    int64_t cursor = 0;
    for (auto &member : decl.members) {
      if (!member.offset || member.bit_size) {
        continue;
      }
      auto size = type_size(registry, member.type_ref);
      auto align = type_alignment(registry, member.type_ref, nullptr);
      if (!size || !align) {
        continue;
      }
      if (member.alignment && *member.alignment > *align) {
        align = member.alignment;
      }
      if (decl.pack && *decl.pack > 1 && *align > *decl.pack) {
        align = decl.pack;
      }
      int64_t aligned_offset = align_up(cursor, *align);
      if (aligned_offset != *member.offset) {
        auto inferred = infer_alignment_for_offset(cursor, *member.offset, *align, decl.pack);
        if (inferred && (!member.alignment || *inferred > *member.alignment)) {
          member.alignment = inferred;
          if (log) {
            log("align member " + decl.name + "." + member.name + " to " +
                std::to_string(*inferred));
          }
          align = inferred;
          aligned_offset = *member.offset;
        }
      }
      cursor = aligned_offset + *size;
    }
  }
}

static void apply_infer_packed_structs(TypeRegistry &registry, const CorrectionLog &log) {
  bool changed_any = false;
  std::set<KindNameKey> visited;
  std::set<KindNameKey> visiting;

  std::function<void(const CTypePtr &)> walk_type;
  std::function<void(StructDecl &)> ensure_struct;

  walk_type = [&](const CTypePtr &type_ref) {
    std::unordered_set<std::string> seen;
    CTypePtr resolved = resolve_typedef(registry, type_ref, seen);
    if (!resolved) {
      return;
    }
    if (resolved->kind == TypeKind::Named &&
        (resolved->ref_kind == "struct" || resolved->ref_kind == "union") &&
        !resolved->name.empty()) {
      KindNameKey key{resolved->ref_kind, resolved->name};
      auto it = registry.structs.find(key);
      if (it == registry.structs.end()) {
        return;
      }
      if (resolved->ref_kind == "struct") {
        ensure_struct(it->second);
        return;
      }
      // recurse into member types to pack nested structs first.
      const StructDecl &union_decl = it->second;
      for (const auto &member : union_decl.members) {
        walk_type(member.type_ref);
      }
      return;
    }
    if (resolved->kind == TypeKind::Pointer) {
      return;
    }
    if (resolved->kind == TypeKind::Array && resolved->target) {
      walk_type(resolved->target);
    }
  };

  ensure_struct = [&](StructDecl &decl) {
    KindNameKey key{decl.kind, decl.name};
    if (visited.count(key)) {
      return;
    }
    if (visiting.count(key)) {
      return;
    }
    visiting.insert(key);
    for (const auto &member : decl.members) {
      std::unordered_set<std::string> seen;
      CTypePtr resolved = resolve_typedef(registry, member.type_ref, seen);
      if (!resolved) {
        continue;
      }
      if (resolved->kind == TypeKind::Named &&
          (resolved->ref_kind == "struct" || resolved->ref_kind == "union") &&
          !resolved->name.empty()) {
        KindNameKey dep{resolved->ref_kind, resolved->name};
        auto it = registry.structs.find(dep);
        if (it == registry.structs.end()) {
          continue;
        }
        if (resolved->ref_kind == "struct") {
          ensure_struct(it->second);
        } else {
          for (const auto &union_member : it->second.members) {
            walk_type(union_member.type_ref);
          }
        }
        continue;
      }
      if (resolved->kind == TypeKind::Array && resolved->target) {
        walk_type(resolved->target);
      }
    }
    visiting.erase(key);
    visited.insert(key);

    if (decl.opaque || decl.packed || decl.pack) {
      return;
    }
    if (decl.kind != "struct") {
      return;
    }
    if (!decl.size) {
      return;
    }
    bool has_bits = false;
    for (const auto &member : decl.members) {
      if (member.bit_size) {
        has_bits = true;
        break;
      }
    }
    if (has_bits) {
      return;
    }

    auto [ok, size] = struct_layout_matches(registry, decl, false);
    if (log) {
      if (ok && size) {
        log("struct " + decl.name + ": natural size 0x" +
            llvm::utohexstr(*size) + " (dwarf 0x" +
            llvm::utohexstr(*decl.size) + ")");
      } else {
        log("struct " + decl.name + ": natural layout unresolved (dwarf 0x" +
            llvm::utohexstr(*decl.size) + ")");
      }
    }
    if (ok && size && *size == *decl.size) {
      return;
    }

    auto [ok_packed, size_packed] = struct_layout_matches(registry, decl, true);
    if (log) {
      if (ok_packed && size_packed) {
        log("struct " + decl.name + ": packed size 0x" +
            llvm::utohexstr(*size_packed) + " (dwarf 0x" +
            llvm::utohexstr(*decl.size) + ")");
      } else {
        log("struct " + decl.name + ": packed layout unresolved (dwarf 0x" +
            llvm::utohexstr(*decl.size) + ")");
      }
    }
    if (ok_packed && size_packed && *size_packed == *decl.size) {
      decl.packed = true;
      changed_any = true;
      if (log) {
        log("pack struct " + decl.name);
      }
      return;
    }

    auto [max_align, unknown] = max_member_alignment(registry, decl);
    if (log) {
      if (max_align) {
        log("struct " + decl.name + ": max member alignment " + std::to_string(*max_align));
      }
      if (!unknown.empty()) {
        std::string members;
        for (size_t i = 0; i < unknown.size(); ++i) {
          if (i) {
            members += ", ";
          }
          members += unknown[i];
        }
        log("struct " + decl.name + ": missing alignment for " + members);
      }
    }
    if (max_align && *max_align > 1 && (*decl.size % *max_align) != 0) {
      decl.packed = true;
      changed_any = true;
      if (log) {
        log("pack struct " + decl.name + ": size 0x" +
            llvm::utohexstr(*decl.size) + " not multiple of align " +
            std::to_string(*max_align));
      }
    }
  };

  for (auto &pair : registry.structs) {
    if (pair.second.kind != "struct") {
      continue;
    }
    ensure_struct(pair.second);
  }

  if (log && !changed_any) {
    log("no packed structs inferred");
  }
}

void apply_corrections(TypeRegistry &registry,
                       const std::set<std::string> &disabled,
                       const std::set<std::string> *verbose) {
  struct Correction {
    std::string name;
    std::function<void(TypeRegistry &, const CorrectionLog &)> fn;
  };

  const std::vector<Correction> corrections = {
      {"xnu-enum-fixed-width", apply_xnu_enum_fixed_width},
      {"xnu-struct-group-name", apply_xnu_struct_group_name},
      {"xnu-list-entry-inline", apply_xnu_list_entry_inline},
      {"xnu-anon-union-inline", apply_xnu_anonymous_union_inline},
      {"inline-anon-structs", apply_inline_anonymous_structs},
      {"pack-from-alignment", apply_pack_from_alignment},
      {"infer-member-alignment", apply_infer_member_alignment},
      {"infer-packed-structs", apply_infer_packed_structs},
  };

  for (const auto &correction : corrections) {
    if (disabled.count(correction.name)) {
      continue;
    }
    CorrectionLog log_fn;
    if (verbose && (verbose->count(correction.name) || verbose->count("all"))) {
      log_fn = [name = correction.name](const std::string &msg) {
        std::cerr << "[kstructs:" << name << "] " << msg << "\n";
      };
    }
    correction.fn(registry, log_fn);
  }
}

} // namespace kstructs
