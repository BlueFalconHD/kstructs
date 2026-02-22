#include "dwarf_render.h"

#include "dwarf_utils.h"

#include <llvm/ADT/StringExtras.h>

#include <algorithm>
#include <optional>
#include <set>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace kstructs {

static constexpr int64_t kSignedIntMax = 0x7fffffff;

static std::string format_hex_const(int64_t value) {
  if (value < 0) {
    return "-0x" + llvm::utohexstr(static_cast<uint64_t>(-value));
  }
  std::string out = "0x" + llvm::utohexstr(static_cast<uint64_t>(value));
  if (value > kSignedIntMax) {
    out += "U";
  }
  return out;
}

static std::string format_int_const(int64_t value) {
  if (value > -16 && value < 16) {
    return std::to_string(value);
  }
  return format_hex_const(value);
}

static std::map<KindNameKey, int> count_named_type_refs(const TypeRegistry &registry) {
  std::map<KindNameKey, int> counts;

  auto visit = [&](const CTypePtr &type_ref,
                   const std::optional<KindNameKey> &owner,
                   const auto &self) -> void {
    if (!type_ref) {
      return;
    }
    std::unordered_set<std::string> seen;
    CTypePtr resolved = resolve_typedef(registry, type_ref, seen);
    if (!resolved) {
      return;
    }
    if (resolved->kind == TypeKind::Named) {
      if ((resolved->ref_kind == "struct" || resolved->ref_kind == "union" || resolved->ref_kind == "enum") &&
          !resolved->name.empty()) {
        KindNameKey key{resolved->ref_kind, resolved->name};
        if (!owner || *owner != key) {
          counts[key] += 1;
        }
      }
      return;
    }
    if ((resolved->kind == TypeKind::Pointer || resolved->kind == TypeKind::Array) && resolved->target) {
      self(resolved->target, owner, self);
    }
  };

  for (const auto &pair : registry.structs) {
    const KindNameKey &owner = pair.first;
    const StructDecl &decl = pair.second;
    for (const auto &member : decl.members) {
      visit(member.type_ref, owner, visit);
    }
  }

  for (const auto &pair : registry.typedefs) {
    visit(pair.second.target, std::nullopt, visit);
  }

  return counts;
}

struct DeclaratorInfo {
  CTypePtr base;
  std::string declarator;
  bool has_wrappers = false;
};

static DeclaratorInfo split_declarator(const TypeRegistry &registry,
                                       const CTypePtr &type_ref,
                                       const std::string &name,
                                       bool expand_typedefs) {
  DeclaratorInfo info;
  CTypePtr resolved = type_ref;
  if (expand_typedefs) {
    std::unordered_set<std::string> seen;
    resolved = resolve_typedef(registry, type_ref, seen);
  }
  if (!resolved) {
    info.base = make_named("void", "base");
    info.declarator = name;
    info.has_wrappers = false;
    return info;
  }

  if (resolved->kind == TypeKind::Named) {
    info.base = resolved;
    info.declarator = name;
    info.has_wrappers = false;
    return info;
  }

  if (resolved->kind == TypeKind::Pointer) {
    std::string quals;
    if (!resolved->qualifiers.empty()) {
      std::ostringstream oss;
      for (size_t i = 0; i < resolved->qualifiers.size(); ++i) {
        if (i) {
          oss << ' ';
        }
        oss << resolved->qualifiers[i];
      }
      quals = oss.str();
    }

    std::string inner;
    if (!name.empty()) {
      if (quals.empty()) {
        inner = "*" + name;
      } else {
        inner = "* " + quals + " " + name;
      }
    } else {
      inner = quals.empty() ? "*" : "* " + quals;
    }

    if (resolved->target) {
      CTypePtr target_for_parens = resolved->target;
      if (expand_typedefs) {
        std::unordered_set<std::string> seen;
        target_for_parens = resolve_typedef(registry, target_for_parens, seen);
      }
      if (target_for_parens && target_for_parens->needs_parens()) {
        inner = "(" + inner + ")";
      }
    }

    CTypePtr target = resolved->target ? resolved->target : make_named("void", "base");
    info = split_declarator(registry, target, inner, expand_typedefs);
    info.has_wrappers = true;
    return info;
  }

  if (resolved->kind == TypeKind::Array) {
    std::string count = resolved->count ? format_int_const(*resolved->count) : "";
    std::string inner;
    if (!name.empty()) {
      inner = name + "[" + count + "]";
    } else {
      inner = "[" + count + "]";
    }
    CTypePtr target = resolved->target ? resolved->target : make_named("void", "base");
    info = split_declarator(registry, target, inner, expand_typedefs);
    info.has_wrappers = true;
    return info;
  }

  info.base = make_named("void", "base");
  info.declarator = name;
  info.has_wrappers = false;
  return info;
}

std::string render_type(const TypeRegistry &registry,
                        const CTypePtr &type_ref,
                        const std::string &name,
                        bool expand_typedefs) {
  CTypePtr resolved = type_ref;
  if (expand_typedefs) {
    std::unordered_set<std::string> seen;
    resolved = resolve_typedef(registry, type_ref, seen);
  }
  if (!resolved) {
    return name.empty() ? "void" : "void " + name;
  }

  if (resolved->kind == TypeKind::Named) {
    std::string base = resolved->name.empty() ? "void" : resolved->name;
    if (resolved->ref_kind == "struct" || resolved->ref_kind == "union" ||
        resolved->ref_kind == "enum") {
      if (resolved->ref_kind == "enum" && !resolved->name.empty()) {
        auto it = registry.enums.find(resolved->name);
        if (it != registry.enums.end() && it->second.typedef_as) {
          base = *it->second.typedef_as;
        } else {
          base = resolved->ref_kind + " " + base;
        }
      } else {
        base = resolved->ref_kind + " " + base;
      }
    }
    if (!resolved->qualifiers.empty()) {
      std::ostringstream oss;
      for (size_t i = 0; i < resolved->qualifiers.size(); ++i) {
        if (i) {
          oss << ' ';
        }
        oss << resolved->qualifiers[i];
      }
      base = oss.str() + " " + base;
    }
    if (!name.empty()) {
      return base + " " + name;
    }
    return base;
  }

  if (resolved->kind == TypeKind::Pointer) {
    std::string quals;
    if (!resolved->qualifiers.empty()) {
      std::ostringstream oss;
      for (size_t i = 0; i < resolved->qualifiers.size(); ++i) {
        if (i) {
          oss << ' ';
        }
        oss << resolved->qualifiers[i];
      }
      quals = oss.str();
    }

    std::string inner;
    if (!name.empty()) {
      if (quals.empty()) {
        inner = "*" + name;
      } else {
        inner = "* " + quals + " " + name;
      }
    } else {
      inner = quals.empty() ? "*" : "* " + quals;
    }

    if (resolved->target) {
      CTypePtr target_for_parens = resolved->target;
      if (expand_typedefs) {
        std::unordered_set<std::string> seen;
        target_for_parens = resolve_typedef(registry, target_for_parens, seen);
      }
      if (target_for_parens && target_for_parens->needs_parens()) {
        inner = "(" + inner + ")";
      }
    }
    CTypePtr target = resolved->target ? resolved->target : make_named("void", "base");
    return render_type(registry, target, inner, expand_typedefs);
  }

  if (resolved->kind == TypeKind::Array) {
    std::string count = resolved->count ? format_int_const(*resolved->count) : "";
    std::string inner;
    if (!name.empty()) {
      inner = name + "[" + count + "]";
    } else {
      inner = "[" + count + "]";
    }
    CTypePtr target = resolved->target ? resolved->target : make_named("void", "base");
    return render_type(registry, target, inner, expand_typedefs);
  }

  return "void";
}

static std::set<KindNameKey> collect_value_deps(const TypeRegistry &registry, const CTypePtr &type_ref) {
  std::set<KindNameKey> deps;
  std::unordered_set<std::string> seen;
  CTypePtr resolved = resolve_typedef(registry, type_ref, seen);
  if (!resolved) {
    return deps;
  }
  if (resolved->kind == TypeKind::Named) {
    if ((resolved->ref_kind == "struct" || resolved->ref_kind == "union" ||
         resolved->ref_kind == "enum") &&
        !resolved->name.empty()) {
      deps.insert({resolved->ref_kind, resolved->name});
    }
    return deps;
  }
  if (resolved->kind == TypeKind::Pointer) {
    return deps;
  }
  if (resolved->kind == TypeKind::Array) {
    if (resolved->target) {
      return collect_value_deps(registry, resolved->target);
    }
  }
  return deps;
}

static void collect_decl_deps(const TypeRegistry &registry,
                              const StructDecl &decl,
                              std::set<KindNameKey> &refs,
                              std::set<InlineKey> &seen_inline) {
  for (const auto &member : decl.members) {
    InlineKey inline_union_key{decl.kind, decl.name, member.name};
    auto inline_union = registry.inline_unions.find(inline_union_key);
    if (inline_union != registry.inline_unions.end()) {
      const StructDecl &union_decl = inline_union->second;
      if (!union_decl.name.empty()) {
        refs.insert({union_decl.kind, union_decl.name});
      }
      for (const auto &submember : union_decl.members) {
        InlineKey inline_member_key{union_decl.kind, union_decl.name, submember.name};
        auto inline_member = registry.inline_members.find(inline_member_key);
        if (inline_member != registry.inline_members.end()) {
          if (seen_inline.insert(inline_member_key).second) {
            collect_decl_deps(registry, inline_member->second, refs, seen_inline);
          }
          continue;
        }
        InlineKey nested_union_key{union_decl.kind, union_decl.name, submember.name};
        auto nested_union = registry.inline_unions.find(nested_union_key);
        if (nested_union != registry.inline_unions.end()) {
          if (seen_inline.insert(nested_union_key).second) {
            collect_decl_deps(registry, nested_union->second, refs, seen_inline);
          }
          continue;
        }
        auto subdeps = collect_value_deps(registry, submember.type_ref);
        refs.insert(subdeps.begin(), subdeps.end());
      }
      continue;
    }

    InlineKey inline_member_key{decl.kind, decl.name, member.name};
    auto inline_member = registry.inline_members.find(inline_member_key);
    if (inline_member != registry.inline_members.end()) {
      if (seen_inline.insert(inline_member_key).second) {
        collect_decl_deps(registry, inline_member->second, refs, seen_inline);
      }
      continue;
    }

    auto subdeps = collect_value_deps(registry, member.type_ref);
    refs.insert(subdeps.begin(), subdeps.end());
  }
}

static std::vector<KindNameKey> sorted_decl_keys(const TypeRegistry &registry) {
  std::map<KindNameKey, bool> decls;
  for (const auto &pair : registry.structs) {
    decls[pair.first] = true;
  }
  for (const auto &pair : registry.enums) {
    decls[{"enum", pair.first}] = true;
  }

  std::map<KindNameKey, std::set<KindNameKey>> deps;
  for (const auto &pair : decls) {
    const KindNameKey &key = pair.first;
    auto it = registry.structs.find(key);
    if (it == registry.structs.end()) {
      deps[key] = {};
      continue;
    }
    const StructDecl &decl = it->second;
    if (decl.opaque) {
      deps[key] = {};
      continue;
    }
    std::set<KindNameKey> refs;
    std::set<InlineKey> seen_inline;
    collect_decl_deps(registry, decl, refs, seen_inline);
    std::set<KindNameKey> filtered;
    for (const auto &ref : refs) {
      if (decls.count(ref)) {
        filtered.insert(ref);
      }
    }
    deps[key] = filtered;
  }

  std::vector<KindNameKey> order;
  std::set<KindNameKey> visited;
  std::set<KindNameKey> visiting;

  std::function<void(const KindNameKey &)> visit = [&](const KindNameKey &node) {
    if (visited.count(node)) {
      return;
    }
    if (visiting.count(node)) {
      return;
    }
    visiting.insert(node);
    for (const auto &dep : deps[node]) {
      visit(dep);
    }
    visiting.erase(node);
    visited.insert(node);
    order.push_back(node);
  };

  for (const auto &pair : decls) {
    visit(pair.first);
  }

  return order;
}

std::string render_c(const TypeRegistry &registry,
                     const std::optional<std::string> &include_guard) {
  std::vector<std::string> lines;
  std::map<KindNameKey, int> ref_counts = count_named_type_refs(registry);

  std::set<std::string> suppressed_unions;
  std::set<std::string> suppressed_structs;
  for (const auto &pair : registry.structs) {
    const StructDecl &decl = pair.second;
    if (decl.name_origin != "anon" && decl.name_origin != "member") {
      continue;
    }
    if (decl.kind == "union") {
      suppressed_unions.insert(decl.name);
    } else if (decl.kind == "struct") {
      suppressed_structs.insert(decl.name);
    }
  }

  auto order = sorted_decl_keys(registry);

  int64_t emitted_structs = 0;
  int64_t emitted_unions = 0;
  int64_t emitted_enums = 0;
  int64_t emitted_typedefs = 0;

  for (const auto &key : order) {
    if (key.kind == "enum") {
      auto it = registry.enums.find(key.name);
      if (it != registry.enums.end() && !it->second.opaque) {
        emitted_enums += 1;
      }
      continue;
    }
    auto it = registry.structs.find(key);
    if (it == registry.structs.end() || it->second.opaque) {
      continue;
    }
    if (key.kind == "union" && suppressed_unions.count(key.name)) {
      continue;
    }
    if (key.kind == "struct" && suppressed_structs.count(key.name)) {
      continue;
    }
    if (key.kind == "union") {
      emitted_unions += 1;
    } else if (key.kind == "struct") {
      emitted_structs += 1;
    }
  }

  std::set<std::string> opaque_typedefs;
  std::vector<std::string> opaque_lines;
  for (const auto &pair : registry.structs) {
    const StructDecl &decl = pair.second;
    if (!decl.opaque) {
      continue;
    }
    opaque_lines.push_back(decl.kind + " " + decl.name + ";");
    opaque_lines.push_back("typedef " + decl.kind + " " + decl.name + " " + decl.name + ";");
    opaque_typedefs.insert(decl.name);
  }
  for (const auto &pair : registry.enums) {
    const EnumDecl &decl = pair.second;
    if (!decl.opaque) {
      continue;
    }
    opaque_lines.push_back("enum " + decl.name + ";");
    opaque_lines.push_back("typedef enum " + decl.name + " " + decl.name + ";");
    opaque_typedefs.insert(decl.name);
  }

  for (const auto &pair : registry.typedefs) {
    if (!opaque_typedefs.count(pair.first)) {
      emitted_typedefs += 1;
    }
  }

  int64_t emitted_total = emitted_structs + emitted_unions + emitted_enums + emitted_typedefs;
  int64_t source_total = registry.source_type_count;

  lines.emplace_back("/*");
  lines.emplace_back(" * Generated by kstructs");
  lines.emplace_back(" * Types emitted: " + std::to_string(emitted_total) + "/" +
                     std::to_string(source_total) + " types in source");
  lines.emplace_back(" * Structs: " + std::to_string(emitted_structs) +
                     ", Unions: " + std::to_string(emitted_unions) +
                     ", Enums: " + std::to_string(emitted_enums) +
                     ", Typedefs: " + std::to_string(emitted_typedefs));
  lines.emplace_back(" */");

  if (include_guard) {
    lines.emplace_back("#ifndef " + *include_guard);
    lines.emplace_back("#define " + *include_guard);
    lines.emplace_back("");
  }

  lines.emplace_back("#include <stddef.h>");
  lines.emplace_back("#include <stdint.h>");
  lines.emplace_back("#include <stdbool.h>");
  lines.emplace_back("");

  if (!opaque_lines.empty()) {
    lines.insert(lines.end(), opaque_lines.begin(), opaque_lines.end());
    lines.emplace_back("");
  }

  auto pack_value = [](const StructDecl &decl) -> std::optional<int64_t> {
    if (decl.pack && *decl.pack > 1) {
      return decl.pack;
    }
    return std::nullopt;
  };
  auto pack_push = [&](int indent, const StructDecl &decl) -> std::string {
    auto value = pack_value(decl);
    if (!value) {
      return "";
    }
    return std::string(indent, ' ') + "#pragma pack(push, " + std::to_string(*value) + ")";
  };
  auto pack_pop = [&](int indent, const StructDecl &decl) -> std::string {
    if (!pack_value(decl)) {
      return "";
    }
    return std::string(indent, ' ') + "#pragma pack(pop)";
  };
  auto packed_suffix_for = [&](const StructDecl &decl) -> std::string {
    if (pack_value(decl)) {
      return "";
    }
    return decl.packed ? " __attribute__((packed))" : "";
  };
  auto align_suffix_for = [&](const StructDecl &decl) -> std::string {
    if (pack_value(decl)) {
      return "";
    }
    if (decl.alignment) {
      return " __attribute__((aligned(" + std::to_string(*decl.alignment) + ")))";
    }
    return "";
  };

  auto is_anon_decl = [](const StructDecl &decl) {
    return decl.name_origin == "anon" || decl.name_origin == "member";
  };

  auto align_suffix_for_inline = [&](const StructDecl &decl, std::optional<int64_t> align_override) -> std::string {
    if (pack_value(decl)) {
      return "";
    }
    std::optional<int64_t> align_value = decl.alignment;
    if (align_override) {
      if (!align_value || *align_override > *align_value) {
        align_value = align_override;
      }
    }
    if (align_value) {
      return " __attribute__((aligned(" + std::to_string(*align_value) + ")))";
    }
    return "";
  };

  std::function<void(const StructDecl &, int)> emit_inline_members;
  std::function<void(const StructDecl &, int, const std::string &, std::optional<int64_t>)> emit_inline_decl;
  std::function<std::optional<bool>(const MemberInfo &, int, bool)> emit_inline_anonymous;

  emit_inline_decl = [&](const StructDecl &decl,
                         int indent,
                         const std::string &declarator,
                         std::optional<int64_t> align_override) {
    if (auto pack_line = pack_push(indent, decl); !pack_line.empty()) {
      lines.emplace_back(pack_line);
    }
    lines.emplace_back(std::string(indent, ' ') + decl.kind + " {");
    emit_inline_members(decl, indent + 4);
    std::string packed_suffix = packed_suffix_for(decl);
    std::string align_suffix = align_suffix_for_inline(decl, align_override);
    std::string line = std::string(indent, ' ') + "}" + packed_suffix;
    if (!declarator.empty()) {
      line += " " + declarator;
    }
    line += align_suffix + ";";
    lines.emplace_back(line);
    if (auto pack_line = pack_pop(indent, decl); !pack_line.empty()) {
      lines.emplace_back(pack_line);
    }
  };

  emit_inline_anonymous = [&](const MemberInfo &member,
                              int indent,
                              bool allow_anonymous) -> std::optional<bool> {
    DeclaratorInfo info = split_declarator(registry, member.type_ref, member.name, true);
    if (!info.base || info.base->kind != TypeKind::Named) {
      return std::nullopt;
    }
    if (info.base->ref_kind != "struct" && info.base->ref_kind != "union") {
      return std::nullopt;
    }
    auto it = registry.structs.find({info.base->ref_kind, info.base->name});
    if (it == registry.structs.end()) {
      return std::nullopt;
    }
    const StructDecl &decl = it->second;
    if (decl.opaque || !is_anon_decl(decl)) {
      return std::nullopt;
    }
    bool emit_anonymous = allow_anonymous && !info.has_wrappers && is_synthetic_member_name(member.name);
    std::string declarator = emit_anonymous ? "" : info.declarator;
    emit_inline_decl(decl, indent, declarator, member.alignment);
    return emit_anonymous;
  };

  emit_inline_members = [&](const StructDecl &decl, int indent) {
    for (const auto &member : decl.members) {
      InlineKey inline_union_key{decl.kind, decl.name, member.name};
      auto inline_union = registry.inline_unions.find(inline_union_key);
      if (inline_union != registry.inline_unions.end()) {
        const StructDecl &union_decl = inline_union->second;
        std::optional<int64_t> align_value = member.alignment;
        if (!pack_value(union_decl) && union_decl.alignment) {
          if (!align_value || *union_decl.alignment > *align_value) {
            align_value = union_decl.alignment;
          }
        }
        std::string declarator = is_synthetic_member_name(member.name) ? "" : member.name;
        emit_inline_decl(union_decl, indent, declarator, align_value);
        continue;
      }

      InlineKey inline_decl_key{decl.kind, decl.name, member.name};
      auto inline_decl = registry.inline_members.find(inline_decl_key);
      if (inline_decl != registry.inline_members.end()) {
        const StructDecl &nested_decl = inline_decl->second;
        std::optional<int64_t> align_value = member.alignment;
        if (!pack_value(nested_decl) && nested_decl.alignment) {
          if (!align_value || *nested_decl.alignment > *align_value) {
            align_value = nested_decl.alignment;
          }
        }
        std::string declarator = is_synthetic_member_name(member.name) ? "" : member.name;
        emit_inline_decl(nested_decl, indent, declarator, align_value);
        continue;
      }

      if (member.bit_size) {
        std::string decl_text = render_type(registry, member.type_ref, member.name, true);
        std::string line = std::string(indent, ' ') + decl_text + " : " + std::to_string(*member.bit_size);
        if (member.bit_offset) {
          line += "; /* bit offset " + std::to_string(*member.bit_offset) + " */";
        } else {
          line += ";";
        }
        lines.emplace_back(line);
        continue;
      }

      if (emit_inline_anonymous(member, indent, true).has_value()) {
        continue;
      }

      std::string decl_text = render_type(registry, member.type_ref, member.name, true);
      if (member.alignment) {
        lines.emplace_back(std::string(indent, ' ') + decl_text + " __attribute__((aligned(" +
                           std::to_string(*member.alignment) + ")));");
      } else {
        lines.emplace_back(std::string(indent, ' ') + decl_text + ";");
      }
    }
  };

  for (const auto &key : order) {
    const std::string &kind = key.kind;
    const std::string &name = key.name;

    if (kind == "union" && suppressed_unions.count(name)) {
      continue;
    }
    if (kind == "struct" && suppressed_structs.count(name)) {
      continue;
    }
    if (kind == "enum") {
      auto it = registry.enums.find(name);
      if (it == registry.enums.end()) {
        continue;
      }
      const EnumDecl &enum_decl = it->second;
      if (enum_decl.opaque) {
        continue;
      }
      if (enum_decl.typedef_as) {
        lines.emplace_back("enum {");
      } else {
        lines.emplace_back("enum " + enum_decl.name + " {");
      }
      for (const auto &entry : enum_decl.enumerators) {
        lines.emplace_back("    " + entry.first + " = " + format_int_const(entry.second) + ",");
      }
      lines.emplace_back("};");
      lines.emplace_back("");
      continue;
    }

    auto it = registry.structs.find(key);
    if (it == registry.structs.end()) {
      continue;
    }
    const StructDecl &decl = it->second;
    if (decl.opaque) {
      continue;
    }

    int refs = 0;
    auto ref_it = ref_counts.find({kind, name});
    if (ref_it != ref_counts.end()) {
      refs = ref_it->second;
    }
    lines.emplace_back("/* refs: " + std::to_string(refs) + " */");
    if (auto pack_line = pack_push(0, decl); !pack_line.empty()) {
      lines.emplace_back(pack_line);
    }
    lines.emplace_back(decl.kind + " " + decl.name + " {");
    std::vector<std::pair<std::string, int64_t>> extra_asserts;
    std::set<std::string> skip_members;

    for (const auto &member : decl.members) {
      InlineKey inline_union_key{decl.kind, decl.name, member.name};
      auto inline_union = registry.inline_unions.find(inline_union_key);
      if (inline_union != registry.inline_unions.end()) {
        std::string align_suffix;
        std::optional<int64_t> align_value = member.alignment;
        if (!pack_value(inline_union->second) && inline_union->second.alignment) {
          if (!align_value || *inline_union->second.alignment > *align_value) {
            align_value = inline_union->second.alignment;
          }
        }
        if (align_value) {
          align_suffix = " __attribute__((aligned(" + std::to_string(*align_value) + ")))";
        }
        std::string packed_suffix = packed_suffix_for(inline_union->second);
        bool emit_union_anonymous = is_synthetic_member_name(member.name);
        if (emit_union_anonymous) {
          skip_members.insert(member.name);
        }
        if (auto pack_line = pack_push(4, inline_union->second); !pack_line.empty()) {
          lines.emplace_back(pack_line);
        }
        lines.emplace_back("    union {");
        emit_inline_members(inline_union->second, 8);
        if (emit_union_anonymous) {
          lines.emplace_back("    }" + packed_suffix + align_suffix + ";");
        } else {
          lines.emplace_back("    }" + packed_suffix + " " + member.name + align_suffix + ";");
        }
        if (auto pack_line = pack_pop(4, inline_union->second); !pack_line.empty()) {
          lines.emplace_back(pack_line);
        }
        continue;
      }

      InlineKey inline_decl_key{decl.kind, decl.name, member.name};
      auto inline_decl = registry.inline_members.find(inline_decl_key);
      if (inline_decl != registry.inline_members.end()) {
        const StructDecl &nested_decl = inline_decl->second;
        std::string align_suffix;
        std::optional<int64_t> align_value = member.alignment;
        if (!pack_value(nested_decl) && nested_decl.alignment) {
          if (!align_value || *nested_decl.alignment > *align_value) {
            align_value = nested_decl.alignment;
          }
        }
        if (align_value) {
          align_suffix = " __attribute__((aligned(" + std::to_string(*align_value) + ")))";
        }
        std::string packed_suffix = packed_suffix_for(nested_decl);
        bool emit_anonymous = (nested_decl.name_origin == "anon" || nested_decl.name_origin == "member") &&
                              is_synthetic_member_name(member.name);
        if (emit_anonymous) {
          skip_members.insert(member.name);
        }
        if (auto pack_line = pack_push(4, nested_decl); !pack_line.empty()) {
          lines.emplace_back(pack_line);
        }
        lines.emplace_back("    struct {");
        emit_inline_members(nested_decl, 8);
        if (emit_anonymous) {
          lines.emplace_back("    }" + packed_suffix + align_suffix + ";");
        } else {
          lines.emplace_back("    }" + packed_suffix + " " + member.name + align_suffix + ";");
        }
        if (auto pack_line = pack_pop(4, nested_decl); !pack_line.empty()) {
          lines.emplace_back(pack_line);
        }
        continue;
      }

      if (member.bit_size) {
        std::string decl_text = render_type(registry, member.type_ref, member.name, true);
        if (member.bit_offset) {
          lines.emplace_back("    " + decl_text + " : " + std::to_string(*member.bit_size) +
                             "; /* bit offset " + std::to_string(*member.bit_offset) + " */");
        } else {
          lines.emplace_back("    " + decl_text + " : " + std::to_string(*member.bit_size) + ";");
        }
      } else {
        auto emitted = emit_inline_anonymous(member, 4, true);
        if (emitted.has_value()) {
          if (*emitted) {
            skip_members.insert(member.name);
          }
          continue;
        }
        std::string decl_text = render_type(registry, member.type_ref, member.name, true);
        if (member.alignment) {
          lines.emplace_back("    " + decl_text + " __attribute__((aligned(" +
                             std::to_string(*member.alignment) + ")));");
        } else {
          lines.emplace_back("    " + decl_text + ";");
        }
      }
    }

    std::string packed_suffix = packed_suffix_for(decl);
    std::string align_suffix = align_suffix_for(decl);
    lines.emplace_back("}" + packed_suffix + align_suffix + ";");
    if (auto pack_line = pack_pop(0, decl); !pack_line.empty()) {
      lines.emplace_back(pack_line);
    }

    std::string type_name = decl.kind + " " + decl.name;
    for (const auto &member : decl.members) {
      if (skip_members.count(member.name)) {
        continue;
      }
      if (!member.offset || member.bit_size) {
        continue;
      }
      std::ostringstream oss;
      oss << "_Static_assert(offsetof(" << type_name << ", " << member.name
          << ") == " << format_hex_const(*member.offset) << ", \""
          << decl.name << "." << member.name << " offset\");";
      lines.emplace_back(oss.str());
    }
    for (const auto &assert_pair : extra_asserts) {
      std::ostringstream oss;
      oss << "_Static_assert(offsetof(" << type_name << ", " << assert_pair.first
          << ") == " << format_hex_const(assert_pair.second) << ", \""
          << decl.name << "." << assert_pair.first << " offset\");";
      lines.emplace_back(oss.str());
    }
    if (decl.kind == "struct" && decl.size) {
      std::ostringstream oss;
      oss << "_Static_assert(sizeof(" << type_name << ") == " << format_hex_const(*decl.size)
          << ", \"" << decl.name << " size\");";
      lines.emplace_back(oss.str());
    }
    lines.emplace_back("");
  }

  if (!registry.typedefs.empty()) {
    for (const auto &pair : registry.typedefs) {
      const std::string &name = pair.first;
      if (opaque_typedefs.count(name)) {
        continue;
      }
      const TypedefDecl &decl = pair.second;
      DeclaratorInfo info = split_declarator(registry, decl.target, decl.name, true);
      if (info.base && info.base->kind == TypeKind::Named &&
          (info.base->ref_kind == "struct" || info.base->ref_kind == "union")) {
        auto it = registry.structs.find({info.base->ref_kind, info.base->name});
        if (it != registry.structs.end()) {
          const StructDecl &base_decl = it->second;
          if (!base_decl.opaque && is_anon_decl(base_decl)) {
            if (auto pack_line = pack_push(0, base_decl); !pack_line.empty()) {
              lines.emplace_back(pack_line);
            }
            lines.emplace_back("typedef " + base_decl.kind + " {");
            emit_inline_members(base_decl, 4);
            std::string packed_suffix = packed_suffix_for(base_decl);
            std::string align_suffix = align_suffix_for_inline(base_decl, std::nullopt);
            std::string line = "}" + packed_suffix + " " + info.declarator + align_suffix + ";";
            lines.emplace_back(line);
            if (auto pack_line = pack_pop(0, base_decl); !pack_line.empty()) {
              lines.emplace_back(pack_line);
            }
            continue;
          }
        }
      }
      std::string decl_text = render_type(registry, decl.target, decl.name, true);
      lines.emplace_back("typedef " + decl_text + ";");
    }
  }

  if (include_guard) {
    lines.emplace_back("");
    lines.emplace_back("#endif /* " + *include_guard + " */");
  }

  std::ostringstream oss;
  for (size_t i = 0; i < lines.size(); ++i) {
    oss << lines[i];
    if (i + 1 < lines.size()) {
      oss << '\n';
    }
  }
  std::string output = oss.str();
  if (!output.empty() && output.back() != '\n') {
    output.push_back('\n');
  }
  return output;
}

} // namespace kstructs
