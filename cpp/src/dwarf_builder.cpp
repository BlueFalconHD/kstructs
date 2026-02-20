#include "dwarf_builder.h"

#include "dwarf_utils.h"

#include <llvm/ADT/SmallString.h>
#include <llvm/BinaryFormat/Dwarf.h>
#include <llvm/DebugInfo/DIContext.h>
#include <llvm/DebugInfo/DWARF/LowLevel/DWARFExpression.h>
#include <llvm/DebugInfo/DWARF/DWARFFormValue.h>
#include <llvm/DebugInfo/DWARF/DWARFUnit.h>
#include <llvm/Support/FormatVariadic.h>

#include <algorithm>
#include <iostream>
#include <map>
#include <set>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace kstructs {

namespace {
constexpr const char *STRUCT_TAG = "DW_TAG_structure_type";
constexpr const char *UNION_TAG = "DW_TAG_union_type";
constexpr const char *CLASS_TAG = "DW_TAG_class_type";
constexpr const char *ENUM_TAG = "DW_TAG_enumeration_type";
constexpr const char *TYPEDEF_TAG = "DW_TAG_typedef";
constexpr const char *BASE_TAG = "DW_TAG_base_type";
constexpr const char *POINTER_TAG = "DW_TAG_pointer_type";
constexpr const char *REFERENCE_TAG = "DW_TAG_reference_type";
constexpr const char *RV_REFERENCE_TAG = "DW_TAG_rvalue_reference_type";
constexpr const char *ARRAY_TAG = "DW_TAG_array_type";
constexpr const char *CONST_TAG = "DW_TAG_const_type";
constexpr const char *VOLATILE_TAG = "DW_TAG_volatile_type";
constexpr const char *RESTRICT_TAG = "DW_TAG_restrict_type";
constexpr const char *ATOMIC_TAG = "DW_TAG_atomic_type";
constexpr const char *UNSPEC_TAG = "DW_TAG_unspecified_type";
constexpr const char *SUBROUTINE_TAG = "DW_TAG_subroutine_type";

const std::set<std::string> STRUCT_TAGS = {STRUCT_TAG, UNION_TAG, CLASS_TAG};
const std::set<std::string> INDEX_TAGS = {STRUCT_TAG, UNION_TAG, CLASS_TAG, ENUM_TAG, TYPEDEF_TAG, BASE_TAG};

} // namespace

TypeBuilder::TypeBuilder(llvm::DWARFContext &ctx, int max_depth, const std::set<std::string> &verbose)
    : ctx_(ctx), max_depth_(max_depth), verbose_(verbose) {
  registry.pointer_size = ctx_.getCUAddrSize();
  build_type_index();
}

void TypeBuilder::log_null_member(const std::string &struct_name, const std::string &member_name,
                                  const std::string &message) {
  if (verbose_.count("null-members") || verbose_.count("all")) {
    std::cerr << "[kstructs:dwarf-null-members] " << struct_name << "." << member_name << ": "
              << message << "\n";
  }
}

std::string TypeBuilder::tag_name(llvm::dwarf::Tag tag) const {
  llvm::StringRef name = llvm::dwarf::TagString(tag);
  if (!name.empty()) {
    return name.str();
  }
  return llvm::formatv("0x{0:x}", static_cast<unsigned>(tag)).str();
}

std::string TypeBuilder::die_debug_detail(const llvm::DWARFDie &die) const {
  std::vector<std::string> parts;
  parts.push_back("tag=" + tag_name(die.getTag()));
  if (die.isValid()) {
    parts.push_back("offset=0x" + llvm::utohexstr(die.getOffset()));
  }
  if (auto name = die.getName(llvm::DINameKind::ShortName)) {
    parts.push_back(std::string("name=") + name);
  }
  if (auto type_form = die.find(llvm::dwarf::DW_AT_type)) {
    std::string value;
    if (auto ref = type_form->getAsReferenceUVal()) {
      value = "0x" + llvm::utohexstr(*ref);
    } else {
      value = "?";
    }
    parts.push_back("type.form=" + std::string(llvm::dwarf::FormEncodingString(type_form->getForm())) +
                    " value=" + value);
  }
  if (auto size = die.find(llvm::dwarf::DW_AT_byte_size)) {
    if (auto uval = size->getAsUnsignedConstant()) {
      parts.push_back("byte_size=" + std::to_string(*uval));
    }
  }
  std::string out;
  for (size_t i = 0; i < parts.size(); ++i) {
    if (i) {
      out += ", ";
    }
    out += parts[i];
  }
  return out;
}

std::string TypeBuilder::null_member_reason(const llvm::DWARFDie &die) const {
  auto tag = die.getTag();
  std::string tag_str = tag_name(tag);
  if (tag == llvm::dwarf::DW_TAG_unspecified_type || tag == llvm::dwarf::DW_TAG_subroutine_type) {
    return tag_str;
  }
  if ((tag == llvm::dwarf::DW_TAG_pointer_type || tag == llvm::dwarf::DW_TAG_reference_type ||
       tag == llvm::dwarf::DW_TAG_rvalue_reference_type) && !die.find(llvm::dwarf::DW_AT_type)) {
    return tag_str + " missing DW_AT_type";
  }
  if ((tag == llvm::dwarf::DW_TAG_const_type || tag == llvm::dwarf::DW_TAG_volatile_type ||
       tag == llvm::dwarf::DW_TAG_restrict_type || tag == llvm::dwarf::DW_TAG_atomic_type) &&
      !die.find(llvm::dwarf::DW_AT_type)) {
    return tag_str + " missing DW_AT_type";
  }
  if (tag == llvm::dwarf::DW_TAG_base_type) {
    auto name = die.getName(llvm::DINameKind::ShortName);
    if (!name || std::string(name).empty() || std::string(name) == "void") {
      return "base type void";
    }
  }
  if (tag == llvm::dwarf::DW_TAG_typedef) {
    auto name = die.getName(llvm::DINameKind::ShortName);
    if ((!name || std::string(name).empty()) && !die.find(llvm::dwarf::DW_AT_type)) {
      return "typedef missing name and DW_AT_type";
    }
  }
  return tag_str + " resolved to void";
}

void TypeBuilder::build_type_index() {
  auto score = [](const llvm::DWARFDie &die) {
    int value = 0;
    if (auto decl = die.find(llvm::dwarf::DW_AT_declaration)) {
      if (auto flag = decl->getAsUnsignedConstant()) {
        if (*flag) {
          value -= 5;
        } else {
          value += 5;
        }
      }
    } else {
      value += 5;
    }
    if (die.find(llvm::dwarf::DW_AT_byte_size)) {
      value += 2;
    }
    if (die.hasChildren()) {
      value += 1;
    }
    return value;
  };

  for (auto &cu : ctx_.compile_units()) {
    for (const auto &entry : cu->dies()) {
      llvm::DWARFDie die{cu.get(), &entry};
      std::string tag = tag_name(die.getTag());
      if (INDEX_TAGS.count(tag) == 0) {
        continue;
      }
      auto name = die.getName(llvm::DINameKind::ShortName);
      if (!name || std::string(name).empty()) {
        continue;
      }
      std::string name_str(name);
      name_index_[name_str].push_back(die);

      std::pair<std::string, std::string> key{name_str, tag};
      auto it = best_by_name_tag_.find(key);
      if (it == best_by_name_tag_.end() || score(die) > score(it->second)) {
        best_by_name_tag_[key] = die;
      }
    }
  }
}

llvm::DWARFDie TypeBuilder::canonical_die(const llvm::DWARFDie &die) {
  auto name = die.getName(llvm::DINameKind::ShortName);
  if (!name) {
    return die;
  }
  std::string tag = tag_name(die.getTag());
  if (STRUCT_TAGS.count(tag) || tag == ENUM_TAG) {
    auto it = best_by_name_tag_.find({std::string(name), tag});
    if (it != best_by_name_tag_.end()) {
      return it->second;
    }
  }
  return die;
}

std::optional<std::string> TypeBuilder::die_name(const llvm::DWARFDie &die) const {
  auto name = die.getName(llvm::DINameKind::ShortName);
  if (!name) {
    return std::nullopt;
  }
  std::string out(name);
  if (out.empty()) {
    return std::nullopt;
  }
  return out;
}

std::string TypeBuilder::anon_type_name(const std::string &kind) {
  anon_type_counter_ += 1;
  return "__anon_" + kind + "_" + std::to_string(anon_type_counter_);
}

std::string TypeBuilder::assign_name(const std::string &kind, const std::string &base, const llvm::DWARFDie &die,
                                     std::string *name_origin) {
  auto cached = die_assigned_names_.find(die.getOffset());
  if (cached != die_assigned_names_.end()) {
    if (name_origin) {
      *name_origin = cached->second.second;
    }
    return cached->second.first;
  }
  std::string sanitized = sanitize_identifier(base);
  if (sanitized.empty()) {
    sanitized = anon_type_name(kind);
  }
  if (kind == "typedef") {
    die_assigned_names_[die.getOffset()] = {sanitized, name_origin ? *name_origin : std::string()};
    return sanitized;
  }
  std::pair<std::string, std::string> key{kind, sanitized};
  auto owner = name_owner_.find(key);
  if (owner == name_owner_.end() || owner->second == die.getOffset()) {
    name_owner_[key] = die.getOffset();
    die_assigned_names_[die.getOffset()] = {sanitized, name_origin ? *name_origin : std::string()};
    return sanitized;
  }
  int idx = 2;
  while (true) {
    std::string candidate = sanitized + "_" + std::to_string(idx);
    std::pair<std::string, std::string> ckey{kind, candidate};
    auto it = name_owner_.find(ckey);
    if (it == name_owner_.end() || it->second == die.getOffset()) {
      name_owner_[ckey] = die.getOffset();
      die_assigned_names_[die.getOffset()] = {candidate, name_origin ? *name_origin : std::string()};
      return candidate;
    }
    idx += 1;
  }
}

llvm::DWARFDie TypeBuilder::find_root_die(const std::string &type_name) {
  std::string name = type_name;
  auto strip_prefix = [&](const std::string &prefix) {
    if (name.rfind(prefix, 0) == 0) {
      name = name.substr(prefix.size());
      while (!name.empty() && name.front() == ' ') {
        name.erase(name.begin());
      }
      return true;
    }
    return false;
  };
  strip_prefix("struct ");
  strip_prefix("union ");
  strip_prefix("enum ");
  strip_prefix("class ");

  auto it = name_index_.find(name);
  if (it == name_index_.end()) {
    throw std::runtime_error("Type '" + type_name + "' not found in DWARF.");
  }

  if (name.size() >= 2 && name.compare(name.size() - 2, 2, "_t") == 0) {
    for (const auto &die : it->second) {
      if (tag_name(die.getTag()) == TYPEDEF_TAG) {
        auto best = best_by_name_tag_.find({name, TYPEDEF_TAG});
        if (best != best_by_name_tag_.end()) {
          return best->second;
        }
        return die;
      }
    }
  }

  const std::vector<std::string> preferred = {STRUCT_TAG, CLASS_TAG, UNION_TAG, ENUM_TAG, TYPEDEF_TAG, BASE_TAG};
  for (const auto &pref : preferred) {
    for (const auto &die : it->second) {
      if (tag_name(die.getTag()) == pref) {
        auto best = best_by_name_tag_.find({name, pref});
        if (best != best_by_name_tag_.end()) {
          return best->second;
        }
        return die;
      }
    }
  }

  return it->second.front();
}

CTypePtr TypeBuilder::build_from_root(const llvm::DWARFDie &root_die) {
  return build_type_ref(root_die, 0, std::nullopt);
}

CTypePtr TypeBuilder::build_type_ref(const llvm::DWARFDie &die, int depth,
                                    const std::optional<std::string> &suggested_name) {
  if (!die.isValid()) {
    return type_factory_.named("void", "base");
  }

  llvm::DWARFDie current = canonical_die(die);
  std::string tag = tag_name(current.getTag());

  if (tag == TYPEDEF_TAG) {
    auto name_opt = die_name(current);
    if (!name_opt) {
      llvm::DWARFDie target = current.getAttributeValueAsReferencedDie(llvm::dwarf::DW_AT_type);
      return build_type_ref(target, depth, std::nullopt);
    }
    std::string name_origin = "typedef";
    const std::string name = assign_name("typedef", *name_opt, current, &name_origin);
    if (registry.typedefs.find(name) == registry.typedefs.end()) {
      llvm::DWARFDie target = current.getAttributeValueAsReferencedDie(llvm::dwarf::DW_AT_type);
      if (target.isValid() && (STRUCT_TAGS.count(tag_name(target.getTag())) || tag_name(target.getTag()) == ENUM_TAG)) {
        if (!die_name(target)) {
          anon_name_overrides_[target.getOffset()] = {name, "typedef"};
        }
      }
      CTypePtr target_ref;
      if (!target.isValid()) {
        target_ref = type_factory_.named("void", "base");
      } else {
        target_ref = build_type_ref(target, depth, std::nullopt);
      }
      registry.typedefs[name] = TypedefDecl{name, target_ref};
    }
    return type_factory_.named(name, "typedef");
  }

  if (STRUCT_TAGS.count(tag)) {
    return build_struct_union(current, depth, suggested_name);
  }

  if (tag == ENUM_TAG) {
    return build_enum(current, depth, suggested_name);
  }

  if (tag == BASE_TAG) {
    std::string name = die_name(current).value_or("uint8_t");
    auto size_form = current.find(llvm::dwarf::DW_AT_byte_size);
    if (size_form) {
      if (auto size = size_form->getAsUnsignedConstant()) {
        if (!name.empty()) {
          registry.base_sizes.emplace(name, static_cast<int64_t>(*size));
        }
      }
    }
    return type_factory_.named(name, "base");
  }

  if (tag == POINTER_TAG || tag == REFERENCE_TAG || tag == RV_REFERENCE_TAG) {
    llvm::DWARFDie target = current.getAttributeValueAsReferencedDie(llvm::dwarf::DW_AT_type);
    CTypePtr target_ref;
    if (target.isValid()) {
      target_ref = build_type_ref(target, depth + 1, std::nullopt);
    } else {
      target_ref = type_factory_.named("void", "base");
    }
    return type_factory_.pointer(target_ref);
  }

  if (tag == ARRAY_TAG) {
    return build_array(current, depth, suggested_name);
  }

  if (tag == CONST_TAG || tag == VOLATILE_TAG || tag == RESTRICT_TAG || tag == ATOMIC_TAG) {
    llvm::DWARFDie target = current.getAttributeValueAsReferencedDie(llvm::dwarf::DW_AT_type);
    CTypePtr target_ref = target.isValid() ? build_type_ref(target, depth, suggested_name)
                                           : type_factory_.named("void", "base");
    std::string qualifier;
    if (tag == CONST_TAG) {
      qualifier = "const";
    } else if (tag == VOLATILE_TAG) {
      qualifier = "volatile";
    } else if (tag == RESTRICT_TAG) {
      qualifier = "restrict";
    } else {
      qualifier = "_Atomic";
    }
    return apply_qualifier(target_ref, qualifier);
  }

  if (current.find(llvm::dwarf::DW_AT_type)) {
    llvm::DWARFDie target = current.getAttributeValueAsReferencedDie(llvm::dwarf::DW_AT_type);
    if (target.isValid() && target.getOffset() != current.getOffset()) {
      return build_type_ref(target, depth, std::nullopt);
    }
  }

  if (tag == UNSPEC_TAG || tag == SUBROUTINE_TAG) {
    return type_factory_.named("void", "base");
  }

  auto name_opt = die_name(current);
  if (name_opt) {
    std::string name_origin = "typedef";
    const std::string name = assign_name("typedef", *name_opt, current, &name_origin);
    if (registry.typedefs.find(name) == registry.typedefs.end()) {
      auto size_form = current.find(llvm::dwarf::DW_AT_byte_size);
      int64_t size = 1;
      if (size_form) {
        if (auto val = size_form->getAsUnsignedConstant()) {
          size = static_cast<int64_t>(*val);
        }
      }
      CTypePtr opaque = opaque_type_for_size(size);
      registry.typedefs[name] = TypedefDecl{name, opaque};
    }
    return type_factory_.named(name, "typedef");
  }

  return type_factory_.named("void", "base");
}

CTypePtr TypeBuilder::apply_qualifier(const CTypePtr &type_ref, const std::string &qualifier) {
  return type_factory_.qualify(type_ref, qualifier);
}

CTypePtr TypeBuilder::build_array(const llvm::DWARFDie &die, int depth,
                                 const std::optional<std::string> &suggested_name) {
  llvm::DWARFDie element = die.getAttributeValueAsReferencedDie(llvm::dwarf::DW_AT_type);
  CTypePtr element_ref = element.isValid() ? build_type_ref(element, depth, suggested_name)
                                           : type_factory_.named("uint8_t", "base");

  std::vector<std::optional<int64_t>> counts;
  for (const auto &child : die.children()) {
    if (child.getTag() != llvm::dwarf::DW_TAG_subrange_type) {
      continue;
    }
    std::optional<int64_t> count;
    if (auto count_form = child.find(llvm::dwarf::DW_AT_count)) {
      if (auto val = count_form->getAsUnsignedConstant()) {
        count = static_cast<int64_t>(*val);
      }
    }
    if (!count) {
      if (auto upper_form = child.find(llvm::dwarf::DW_AT_upper_bound)) {
        if (auto val = upper_form->getAsSignedConstant()) {
          if (*val >= 0) {
            count = static_cast<int64_t>(*val) + 1;
          }
        } else if (auto uval = upper_form->getAsUnsignedConstant()) {
          count = static_cast<int64_t>(*uval) + 1;
        }
      }
    }
    counts.push_back(count);
  }

  if (counts.empty()) {
    return type_factory_.array(element_ref, std::nullopt);
  }

  CTypePtr current = element_ref;
  for (auto it = counts.rbegin(); it != counts.rend(); ++it) {
    current = type_factory_.array(current, *it);
  }
  return current;
}

CTypePtr TypeBuilder::build_struct_union(const llvm::DWARFDie &die, int depth,
                                        const std::optional<std::string> &suggested_name) {
  std::string kind = "struct";
  if (die.getTag() == llvm::dwarf::DW_TAG_union_type) {
    kind = "union";
  }
  std::string name_origin = "dwarf";
  std::string name = die_name(die).value_or("");
  if (name.empty()) {
    auto override = anon_name_overrides_.find(die.getOffset());
    if (override != anon_name_overrides_.end()) {
      name = override->second.first;
      name_origin = override->second.second;
    } else if (suggested_name) {
      name = *suggested_name;
      name_origin = "member";
    } else {
      name = anon_type_name(kind);
      name_origin = "anon";
    }
  }
  name = assign_name(kind, name, die, &name_origin);
  KindNameKey key{kind, name};

  if (expanding_.count({kind, name})) {
    return type_factory_.named(name, kind);
  }

  auto existing = registry.structs.find(key);
  if (existing != registry.structs.end() && (!existing->second.opaque || depth > max_depth_)) {
    return type_factory_.named(name, kind);
  }

  std::optional<int64_t> size;
  std::optional<int64_t> alignment;
  if (auto size_form = die.find(llvm::dwarf::DW_AT_byte_size)) {
    if (auto val = size_form->getAsUnsignedConstant()) {
      size = static_cast<int64_t>(*val);
    }
  }
  if (auto align_form = die.find(llvm::dwarf::DW_AT_alignment)) {
    if (auto val = align_form->getAsUnsignedConstant()) {
      if (*val > 1) {
        alignment = static_cast<int64_t>(*val);
      }
    }
  }

  if (depth > max_depth_) {
    registry.structs[key] = StructDecl{kind, name, size, {}, true, name_origin, false, std::nullopt, alignment};
    return type_factory_.named(name, kind);
  }

  expanding_.insert({kind, name});

  StructDecl decl{kind, name, size, {}, false, name_origin, false, std::nullopt, alignment};
  registry.structs[key] = decl;

  std::unordered_map<std::string, int> member_names;
  for (const auto &child : die.children()) {
    if (child.getTag() != llvm::dwarf::DW_TAG_member) {
      continue;
    }
    if (auto artificial = child.find(llvm::dwarf::DW_AT_artificial)) {
      if (auto val = artificial->getAsUnsignedConstant()) {
        if (*val) {
          continue;
        }
      }
    }

    std::string raw_name = die_name(child).value_or("");
    if (raw_name.empty()) {
      raw_name = anon_type_name("member");
    }
    raw_name = sanitize_identifier(raw_name);
    int count = member_names[raw_name]++;
    if (count) {
      raw_name += "_" + std::to_string(count);
    }

    llvm::DWARFDie member_type_die = child.getAttributeValueAsReferencedDie(llvm::dwarf::DW_AT_type);
    CTypePtr member_type_ref;
    if (!member_type_die.isValid()) {
      int64_t member_size = 1;
      if (auto size_form = child.find(llvm::dwarf::DW_AT_byte_size)) {
        if (auto val = size_form->getAsUnsignedConstant()) {
          member_size = static_cast<int64_t>(*val);
        }
      }
      log_null_member(name, raw_name, "missing DW_AT_type, using opaque size " + std::to_string(member_size) + " bytes");
      member_type_ref = opaque_type_for_size(member_size);
    } else {
      std::optional<std::string> suggested;
      std::string member_tag = tag_name(member_type_die.getTag());
      if (STRUCT_TAGS.count(member_tag) || member_tag == ENUM_TAG) {
        if (!die_name(member_type_die)) {
          suggested = name + "_" + raw_name;
        }
      }
      member_type_ref = build_type_ref(member_type_die, depth, suggested);
      std::optional<int64_t> member_size;
      if (auto size_form = child.find(llvm::dwarf::DW_AT_byte_size)) {
        if (auto val = size_form->getAsUnsignedConstant()) {
          member_size = static_cast<int64_t>(*val);
        }
      }
      if (member_size && is_void_type(member_type_ref)) {
        log_null_member(name, raw_name,
                        "type resolved to void (" + null_member_reason(member_type_die) + "); using opaque size " +
                            std::to_string(*member_size) + " bytes; " + die_debug_detail(member_type_die));
        member_type_ref = opaque_type_for_size(*member_size);
      } else if (is_void_type(member_type_ref)) {
        std::string reason = null_member_reason(member_type_die);
        std::optional<int64_t> size_hint;
        if (auto size_form = child.find(llvm::dwarf::DW_AT_byte_size)) {
          if (auto val = size_form->getAsUnsignedConstant()) {
            size_hint = static_cast<int64_t>(*val);
          }
        }
        if (!size_hint) {
          log_null_member(name, raw_name,
                          "type resolved to void (" + reason + "); no DW_AT_byte_size available, leaving as void; " +
                              die_debug_detail(member_type_die));
        } else {
          log_null_member(name, raw_name,
                          "type resolved to void (" + reason + "); DW_AT_byte_size=" +
                              std::to_string(*size_hint) + " but not applied; " + die_debug_detail(member_type_die));
        }
      }
    }

    auto offset = member_offset(child, kind);
    std::optional<int64_t> bit_size;
    if (auto bit_form = child.find(llvm::dwarf::DW_AT_bit_size)) {
      if (auto val = bit_form->getAsUnsignedConstant()) {
        bit_size = static_cast<int64_t>(*val);
      }
    }
    std::optional<int64_t> bit_offset;
    if (auto bit_form = child.find(llvm::dwarf::DW_AT_data_bit_offset)) {
      if (auto val = bit_form->getAsUnsignedConstant()) {
        bit_offset = static_cast<int64_t>(*val);
      }
    }
    if (!bit_offset) {
      if (auto bit_form = child.find(llvm::dwarf::DW_AT_bit_offset)) {
        if (auto val = bit_form->getAsUnsignedConstant()) {
          bit_offset = static_cast<int64_t>(*val);
        }
      }
    }
    std::optional<int64_t> alignment;
    if (auto align_form = child.find(llvm::dwarf::DW_AT_alignment)) {
      if (auto val = align_form->getAsUnsignedConstant()) {
        if (*val > 1) {
          alignment = static_cast<int64_t>(*val);
        }
      }
    }

    MemberInfo member{raw_name, member_type_ref, offset, bit_size, bit_offset, alignment};
    registry.structs[key].members.push_back(member);
  }

  expanding_.erase({kind, name});
  return type_factory_.named(name, kind);
}

CTypePtr TypeBuilder::build_enum(const llvm::DWARFDie &die, int depth,
                                const std::optional<std::string> &suggested_name) {
  std::string name_origin = "dwarf";
  std::string name = die_name(die).value_or("");
  if (name.empty()) {
    auto override = anon_name_overrides_.find(die.getOffset());
    if (override != anon_name_overrides_.end()) {
      name = override->second.first;
      name_origin = override->second.second;
    } else if (suggested_name) {
      name = *suggested_name;
      name_origin = "member";
    } else {
      name = anon_type_name("enum");
      name_origin = "anon";
    }
  }
  name = assign_name("enum", name, die, &name_origin);

  auto existing = registry.enums.find(name);
  if (existing != registry.enums.end() && (!existing->second.opaque || depth > max_depth_)) {
    return type_factory_.named(name, "enum");
  }

  std::optional<int64_t> size;
  if (auto size_form = die.find(llvm::dwarf::DW_AT_byte_size)) {
    if (auto val = size_form->getAsUnsignedConstant()) {
      size = static_cast<int64_t>(*val);
    }
  }

  std::optional<std::string> underlying;
  llvm::DWARFDie target = die.getAttributeValueAsReferencedDie(llvm::dwarf::DW_AT_type);
  if (target.isValid()) {
    CTypePtr target_ref = build_type_ref(target, depth, std::nullopt);
    std::unordered_set<std::string> seen;
    CTypePtr resolved = resolve_typedef(registry, target_ref, seen);
    if (resolved && resolved->kind == TypeKind::Named && resolved->ref_kind == "base" && !resolved->name.empty()) {
      underlying = resolved->name;
    }
  }

  if (depth > max_depth_) {
    registry.enums[name] = EnumDecl{name, size, {}, true, std::nullopt, underlying};
    return type_factory_.named(name, "enum");
  }

  std::vector<std::pair<std::string, int64_t>> enumerators;
  for (const auto &child : die.children()) {
    if (child.getTag() != llvm::dwarf::DW_TAG_enumerator) {
      continue;
    }
    std::string enum_name = die_name(child).value_or("");
    if (enum_name.empty()) {
      enum_name = anon_type_name("enum_value");
    }
    enum_name = sanitize_identifier(enum_name);
    int64_t value = 0;
    if (auto val_form = child.find(llvm::dwarf::DW_AT_const_value)) {
      if (auto sval = val_form->getAsSignedConstant()) {
        value = static_cast<int64_t>(*sval);
      } else if (auto uval = val_form->getAsUnsignedConstant()) {
        value = static_cast<int64_t>(*uval);
      }
    }
    enumerators.emplace_back(enum_name, value);
  }

  registry.enums[name] = EnumDecl{name, size, enumerators, false, std::nullopt, underlying};
  return type_factory_.named(name, "enum");
}

bool TypeBuilder::is_void_type(const CTypePtr &type_ref) const {
  std::unordered_set<std::string> seen;
  CTypePtr resolved = resolve_typedef(registry, type_ref, seen);
  return resolved && resolved->kind == TypeKind::Named && resolved->name == "void";
}

CTypePtr TypeBuilder::opaque_type_for_size(int64_t size) {
  if (size == 1) {
    return type_factory_.named("uint8_t", "base");
  }
  if (size == 2) {
    return type_factory_.named("uint16_t", "base");
  }
  if (size == 4) {
    return type_factory_.named("uint32_t", "base");
  }
  if (size == 8) {
    return type_factory_.named("uint64_t", "base");
  }
  if (size == 16) {
    return type_factory_.named("unsigned __int128", "base");
  }
  return type_factory_.array(type_factory_.named("uint8_t", "base"), size);
}

std::optional<int64_t> TypeBuilder::member_offset(const llvm::DWARFDie &member_die,
                                                  const std::string &parent_kind) const {
  auto attr = member_die.find(llvm::dwarf::DW_AT_data_member_location);
  if (!attr) {
    if (parent_kind == "union") {
      return 0;
    }
    return std::nullopt;
  }

  if (auto val = attr->getAsUnsignedConstant()) {
    return static_cast<int64_t>(*val);
  }
  if (auto block = attr->getAsBlock()) {
    llvm::DWARFUnit *unit = member_die.getDwarfUnit();
    llvm::DataExtractor extractor(llvm::StringRef(reinterpret_cast<const char *>(block->data()), block->size()),
                                  unit->isLittleEndian(), unit->getAddressByteSize());
    llvm::DWARFExpression expr(extractor, unit->getAddressByteSize(), unit->getFormParams().Format);
    for (const auto &op : expr) {
      if (op.isError()) {
        break;
      }
      if (op.getCode() == llvm::dwarf::DW_OP_plus_uconst || op.getCode() == llvm::dwarf::DW_OP_constu ||
          op.getCode() == llvm::dwarf::DW_OP_consts) {
        if (op.getNumOperands() == 1) {
          return static_cast<int64_t>(op.getRawOperand(0));
        }
      }
      break;
    }
  }
  return std::nullopt;
}

} // namespace kstructs
