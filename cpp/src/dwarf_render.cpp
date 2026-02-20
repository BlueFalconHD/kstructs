#include "dwarf_render.h"

#include "dwarf_utils.h"

#include <llvm/ADT/StringExtras.h>

#include <algorithm>
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

static std::set<KindNameKey> collect_named_refs(const TypeRegistry &registry) {
  std::set<KindNameKey> refs;

  std::function<void(const CTypePtr &)> visit = [&](const CTypePtr &type_ref) {
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
        refs.insert({resolved->ref_kind, resolved->name});
      }
      return;
    }
    if ((resolved->kind == TypeKind::Pointer || resolved->kind == TypeKind::Array) && resolved->target) {
      visit(resolved->target);
    }
  };

  for (const auto &pair : registry.structs) {
    const StructDecl &decl = pair.second;
    for (const auto &member : decl.members) {
      visit(member.type_ref);
    }
  }

  for (const auto &pair : registry.enums) {
    (void)pair;
  }

  for (const auto &pair : registry.typedefs) {
    visit(pair.second.target);
  }

  return refs;
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

std::string render_c(const TypeRegistry &registry) {
  std::vector<std::string> lines;
  lines.emplace_back("/* Generated by kstructs */");
  lines.emplace_back("#include <stddef.h>");
  lines.emplace_back("#include <stdint.h>");
  lines.emplace_back("#include <stdbool.h>");
  lines.emplace_back("");

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

  std::set<std::string> suppressed_unions;
  for (const auto &pair : registry.inline_unions) {
    if (pair.second.kind == "union") {
      suppressed_unions.insert(pair.second.name);
    }
  }
  std::set<std::string> suppressed_structs;
  for (const auto &pair : registry.inline_members) {
    const StructDecl &decl = pair.second;
    if (decl.kind == "struct" && (decl.name_origin == "anon" || decl.name_origin == "member")) {
      suppressed_structs.insert(decl.name);
    }
  }

  std::set<KindNameKey> referenced = collect_named_refs(registry);

  auto order = sorted_decl_keys(registry);
  for (const auto &key : order) {
    const std::string &kind = key.kind;
    const std::string &name = key.name;

    if (kind == "union" && suppressed_unions.count(name) && !referenced.count({kind, name})) {
      continue;
    }
    if (kind == "struct" && suppressed_structs.count(name) && !referenced.count({kind, name})) {
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
        skip_members.insert(member.name);
        if (auto pack_line = pack_push(4, inline_union->second); !pack_line.empty()) {
          lines.emplace_back(pack_line);
        }
        lines.emplace_back("    union {");
        for (const auto &submember : inline_union->second.members) {
          InlineKey inline_decl_key{inline_union->second.kind, inline_union->second.name, submember.name};
          auto inline_decl = registry.inline_members.find(inline_decl_key);
          if (inline_decl != registry.inline_members.end()) {
            const StructDecl &nested_decl = inline_decl->second;
            bool emit_anonymous = (nested_decl.name_origin == "anon" || nested_decl.name_origin == "member") &&
                                  is_synthetic_member_name(submember.name);
            if (member.offset && submember.offset) {
              if (emit_anonymous) {
                for (const auto &inline_member : nested_decl.members) {
                  if (!inline_member.offset || inline_member.bit_size) {
                    continue;
                  }
                  extra_asserts.emplace_back(
                      inline_member.name,
                      *member.offset + *submember.offset + *inline_member.offset);
                }
              } else {
                extra_asserts.emplace_back(submember.name, *member.offset + *submember.offset);
              }
            }
            lines.emplace_back("        struct {");
            for (const auto &inline_member : nested_decl.members) {
              if (inline_member.bit_size) {
                std::string decl_text = render_type(registry, inline_member.type_ref, inline_member.name, true);
                if (inline_member.bit_offset) {
                  lines.emplace_back("            " + decl_text + " : " +
                                     std::to_string(*inline_member.bit_size) +
                                     "; /* bit offset " + std::to_string(*inline_member.bit_offset) + " */");
                } else {
                  lines.emplace_back("            " + decl_text + " : " +
                                     std::to_string(*inline_member.bit_size) + ";");
                }
              } else {
                std::string decl_text = render_type(registry, inline_member.type_ref, inline_member.name, true);
                lines.emplace_back("            " + decl_text + ";");
              }
            }
            if (emit_anonymous) {
              lines.emplace_back("        };");
            } else {
              lines.emplace_back("        } " + submember.name + ";");
            }
            continue;
          }

          if (member.offset && submember.offset && !submember.bit_size) {
            extra_asserts.emplace_back(submember.name, *member.offset + *submember.offset);
          }
          if (submember.bit_size) {
            std::string decl_text = render_type(registry, submember.type_ref, submember.name, true);
            if (submember.bit_offset) {
              lines.emplace_back("        " + decl_text + " : " +
                                 std::to_string(*submember.bit_size) +
                                 "; /* bit offset " + std::to_string(*submember.bit_offset) + " */");
            } else {
              lines.emplace_back("        " + decl_text + " : " + std::to_string(*submember.bit_size) + ";");
            }
          } else {
            std::string decl_text = render_type(registry, submember.type_ref, submember.name, true);
            lines.emplace_back("        " + decl_text + ";");
          }
        }
        lines.emplace_back("    }" + packed_suffix + align_suffix + ";");
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
          if (member.offset) {
            for (const auto &submember : nested_decl.members) {
              if (!submember.offset || submember.bit_size) {
                continue;
              }
              if (is_synthetic_member_name(submember.name)) {
                continue;
              }
              extra_asserts.emplace_back(submember.name, *member.offset + *submember.offset);
            }
          }
        }
        if (auto pack_line = pack_push(4, nested_decl); !pack_line.empty()) {
          lines.emplace_back(pack_line);
        }
        lines.emplace_back("    struct {");
        for (const auto &submember : nested_decl.members) {
          InlineKey nested_union_key{nested_decl.kind, nested_decl.name, submember.name};
          auto nested_union = registry.inline_unions.find(nested_union_key);
          if (nested_union != registry.inline_unions.end()) {
            std::string nested_align_suffix;
            if (submember.alignment) {
              nested_align_suffix = " __attribute__((aligned(" + std::to_string(*submember.alignment) + ")))";
            }
            std::string nested_packed_suffix = packed_suffix_for(nested_union->second);
            std::optional<int64_t> base_offset;
            if (member.offset && submember.offset) {
              base_offset = *member.offset + *submember.offset;
            }
            if (auto pack_line = pack_push(8, nested_union->second); !pack_line.empty()) {
              lines.emplace_back(pack_line);
            }
            lines.emplace_back("        union {");
            for (const auto &union_member : nested_union->second.members) {
              InlineKey union_inline_key{nested_union->second.kind, nested_union->second.name, union_member.name};
              auto union_inline_decl = registry.inline_members.find(union_inline_key);
              if (union_inline_decl != registry.inline_members.end()) {
                const StructDecl &union_struct = union_inline_decl->second;
                bool emit_union_anonymous = (union_struct.name_origin == "anon" || union_struct.name_origin == "member") &&
                                            is_synthetic_member_name(union_member.name);
                if (emit_anonymous && base_offset && union_member.offset) {
                  if (emit_union_anonymous) {
                    for (const auto &inline_member : union_struct.members) {
                      if (!inline_member.offset || inline_member.bit_size) {
                        continue;
                      }
                      extra_asserts.emplace_back(
                          inline_member.name,
                          *base_offset + *union_member.offset + *inline_member.offset);
                    }
                  } else {
                    extra_asserts.emplace_back(union_member.name, *base_offset + *union_member.offset);
                  }
                }
                lines.emplace_back("            struct {");
                for (const auto &inline_member : union_struct.members) {
                  if (inline_member.bit_size) {
                    std::string decl_text = render_type(registry, inline_member.type_ref, inline_member.name, true);
                    if (inline_member.bit_offset) {
                      lines.emplace_back("                " + decl_text + " : " +
                                         std::to_string(*inline_member.bit_size) +
                                         "; /* bit offset " + std::to_string(*inline_member.bit_offset) + " */");
                    } else {
                      lines.emplace_back("                " + decl_text + " : " +
                                         std::to_string(*inline_member.bit_size) + ";");
                    }
                  } else {
                    std::string decl_text = render_type(registry, inline_member.type_ref, inline_member.name, true);
                    lines.emplace_back("                " + decl_text + ";");
                  }
                }
                if (emit_union_anonymous) {
                  lines.emplace_back("            };");
                } else {
                  lines.emplace_back("            } " + union_member.name + ";");
                }
                continue;
              }

              if (emit_anonymous && base_offset && union_member.offset && !union_member.bit_size) {
                extra_asserts.emplace_back(union_member.name, *base_offset + *union_member.offset);
              }
              if (union_member.bit_size) {
                std::string decl_text = render_type(registry, union_member.type_ref, union_member.name, true);
                if (union_member.bit_offset) {
                  lines.emplace_back("            " + decl_text + " : " +
                                     std::to_string(*union_member.bit_size) +
                                     "; /* bit offset " + std::to_string(*union_member.bit_offset) + " */");
                } else {
                  lines.emplace_back("            " + decl_text + " : " + std::to_string(*union_member.bit_size) + ";");
                }
              } else {
                std::string decl_text = render_type(registry, union_member.type_ref, union_member.name, true);
                lines.emplace_back("            " + decl_text + ";");
              }
            }
            lines.emplace_back("        }" + nested_packed_suffix + nested_align_suffix + ";");
            if (auto pack_line = pack_pop(8, nested_union->second); !pack_line.empty()) {
              lines.emplace_back(pack_line);
            }
            continue;
          }

          bool fallback_inlined_union = false;
          if (is_synthetic_member_name(submember.name) && !submember.bit_size) {
            std::unordered_set<std::string> seen;
            CTypePtr resolved_union = resolve_typedef(registry, submember.type_ref, seen);
            if (resolved_union && resolved_union->kind == TypeKind::Named &&
                resolved_union->ref_kind == "union" && !resolved_union->name.empty()) {
              auto union_it = registry.structs.find({resolved_union->ref_kind, resolved_union->name});
              if (union_it != registry.structs.end()) {
                const StructDecl &union_decl = union_it->second;
                if (!union_decl.opaque &&
                    (union_decl.name_origin == "anon" || union_decl.name_origin == "member")) {
                  std::string nested_align_suffix;
                  if (submember.alignment) {
                    nested_align_suffix = " __attribute__((aligned(" + std::to_string(*submember.alignment) + ")))";
                  }
                  std::string nested_packed_suffix = packed_suffix_for(union_decl);
                  std::optional<int64_t> base_offset;
                  if (member.offset && submember.offset) {
                    base_offset = *member.offset + *submember.offset;
                  }
                  if (auto pack_line = pack_push(8, union_decl); !pack_line.empty()) {
                    lines.emplace_back(pack_line);
                  }
                  lines.emplace_back("        union {");
                  for (const auto &union_member : union_decl.members) {
                    InlineKey union_inline_key{union_decl.kind, union_decl.name, union_member.name};
                    auto union_inline_decl = registry.inline_members.find(union_inline_key);
                    if (union_inline_decl != registry.inline_members.end()) {
                      const StructDecl &union_struct = union_inline_decl->second;
                      bool emit_union_anonymous =
                          (union_struct.name_origin == "anon" || union_struct.name_origin == "member") &&
                          is_synthetic_member_name(union_member.name);
                      if (emit_anonymous && base_offset && union_member.offset) {
                        if (emit_union_anonymous) {
                          for (const auto &inline_member : union_struct.members) {
                            if (!inline_member.offset || inline_member.bit_size) {
                              continue;
                            }
                            extra_asserts.emplace_back(
                                inline_member.name,
                                *base_offset + *union_member.offset + *inline_member.offset);
                          }
                        } else {
                          extra_asserts.emplace_back(union_member.name, *base_offset + *union_member.offset);
                        }
                      }
                      lines.emplace_back("            struct {");
                      for (const auto &inline_member : union_struct.members) {
                        if (inline_member.bit_size) {
                          std::string decl_text = render_type(registry, inline_member.type_ref, inline_member.name, true);
                          if (inline_member.bit_offset) {
                            lines.emplace_back("                " + decl_text + " : " +
                                               std::to_string(*inline_member.bit_size) +
                                               "; /* bit offset " + std::to_string(*inline_member.bit_offset) + " */");
                          } else {
                            lines.emplace_back("                " + decl_text + " : " +
                                               std::to_string(*inline_member.bit_size) + ";");
                          }
                        } else {
                          std::string decl_text = render_type(registry, inline_member.type_ref, inline_member.name, true);
                          lines.emplace_back("                " + decl_text + ";");
                        }
                      }
                      if (emit_union_anonymous) {
                        lines.emplace_back("            };");
                      } else {
                        lines.emplace_back("            } " + union_member.name + ";");
                      }
                      continue;
                    }

                    if (emit_anonymous && base_offset && union_member.offset && !union_member.bit_size) {
                      extra_asserts.emplace_back(union_member.name, *base_offset + *union_member.offset);
                    }
                    if (union_member.bit_size) {
                      std::string decl_text = render_type(registry, union_member.type_ref, union_member.name, true);
                      if (union_member.bit_offset) {
                        lines.emplace_back("            " + decl_text + " : " +
                                           std::to_string(*union_member.bit_size) +
                                           "; /* bit offset " + std::to_string(*union_member.bit_offset) + " */");
                      } else {
                        lines.emplace_back("            " + decl_text + " : " + std::to_string(*union_member.bit_size) + ";");
                      }
                    } else {
                      std::string decl_text = render_type(registry, union_member.type_ref, union_member.name, true);
                      lines.emplace_back("            " + decl_text + ";");
                    }
                  }
                  lines.emplace_back("        }" + nested_packed_suffix + nested_align_suffix + ";");
                  if (auto pack_line = pack_pop(8, union_decl); !pack_line.empty()) {
                    lines.emplace_back(pack_line);
                  }
                  fallback_inlined_union = true;
                }
              }
            }
          }
          if (fallback_inlined_union) {
            continue;
          }

          InlineKey nested_inline_key{nested_decl.kind, nested_decl.name, submember.name};
          auto nested_inline = registry.inline_members.find(nested_inline_key);
          if (nested_inline != registry.inline_members.end()) {
            const StructDecl &inline_struct = nested_inline->second;
            bool emit_nested_anonymous = (inline_struct.name_origin == "anon" || inline_struct.name_origin == "member") &&
                                         is_synthetic_member_name(submember.name);
            std::optional<int64_t> base_offset;
            if (member.offset && submember.offset) {
              base_offset = *member.offset + *submember.offset;
            }
            lines.emplace_back("        struct {");
            for (const auto &inline_member : inline_struct.members) {
              if (emit_anonymous && emit_nested_anonymous && base_offset && inline_member.offset && !inline_member.bit_size) {
                extra_asserts.emplace_back(inline_member.name, *base_offset + *inline_member.offset);
              }
              if (inline_member.bit_size) {
                std::string decl_text = render_type(registry, inline_member.type_ref, inline_member.name, true);
                if (inline_member.bit_offset) {
                  lines.emplace_back("            " + decl_text + " : " +
                                     std::to_string(*inline_member.bit_size) +
                                     "; /* bit offset " + std::to_string(*inline_member.bit_offset) + " */");
                } else {
                  lines.emplace_back("            " + decl_text + " : " +
                                     std::to_string(*inline_member.bit_size) + ";");
                }
              } else {
                std::string decl_text = render_type(registry, inline_member.type_ref, inline_member.name, true);
                lines.emplace_back("            " + decl_text + ";");
              }
            }
            if (emit_nested_anonymous) {
              lines.emplace_back("        };");
            } else {
              lines.emplace_back("        } " + submember.name + ";");
            }
            continue;
          }

          if (submember.bit_size) {
            std::string decl_text = render_type(registry, submember.type_ref, submember.name, true);
            if (submember.bit_offset) {
              lines.emplace_back("        " + decl_text + " : " +
                                 std::to_string(*submember.bit_size) +
                                 "; /* bit offset " + std::to_string(*submember.bit_offset) + " */");
            } else {
              lines.emplace_back("        " + decl_text + " : " + std::to_string(*submember.bit_size) + ";");
            }
          } else {
            std::string decl_text = render_type(registry, submember.type_ref, submember.name, true);
            lines.emplace_back("        " + decl_text + ";");
          }
        }
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
      std::string decl_text = render_type(registry, decl.target, decl.name, true);
      lines.emplace_back("typedef " + decl_text + ";");
    }
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
