#ifndef KSTRUCTS_DWARF_BUILDER_H
#define KSTRUCTS_DWARF_BUILDER_H

#include "dwarf_types.h"

#include <llvm/DebugInfo/DWARF/DWARFContext.h>
#include <llvm/DebugInfo/DWARF/DWARFDie.h>
#include <llvm/DebugInfo/DWARF/DWARFFormValue.h>
#include <llvm/Support/DataExtractor.h>

#include <optional>
#include <set>
#include <string>
#include <unordered_map>

namespace kstructs {

class TypeBuilder {
public:
  TypeBuilder(llvm::DWARFContext &ctx, int max_depth, const std::set<std::string> &verbose);

  llvm::DWARFDie find_root_die(const std::string &type_name);
  CTypePtr build_from_root(const llvm::DWARFDie &root_die);

  TypeRegistry registry;

private:
  llvm::DWARFContext &ctx_;
  int max_depth_;
  std::set<std::string> verbose_;
  std::unordered_map<std::string, std::vector<llvm::DWARFDie>> name_index_;
  std::map<std::pair<std::string, std::string>, llvm::DWARFDie> best_by_name_tag_;
  int anon_type_counter_ = 0;
  std::set<std::pair<std::string, std::string>> expanding_;
  std::unordered_map<uint64_t, std::pair<std::string, std::string>> anon_name_overrides_;
  std::map<std::pair<std::string, std::string>, uint64_t> name_owner_;
  std::unordered_map<uint64_t, std::pair<std::string, std::string>> die_assigned_names_;
  TypeFactory type_factory_;

  void log_null_member(const std::string &struct_name, const std::string &member_name, const std::string &message);

  std::string tag_name(llvm::dwarf::Tag tag) const;
  std::string die_debug_detail(const llvm::DWARFDie &die) const;
  std::string null_member_reason(const llvm::DWARFDie &die) const;

  void build_type_index();
  llvm::DWARFDie canonical_die(const llvm::DWARFDie &die);
  std::optional<std::string> die_name(const llvm::DWARFDie &die) const;
  std::string anon_type_name(const std::string &kind);
  std::string assign_name(const std::string &kind, const std::string &base, const llvm::DWARFDie &die,
                          std::string *name_origin);

  CTypePtr build_type_ref(const llvm::DWARFDie &die, int depth, const std::optional<std::string> &suggested_name);
  CTypePtr build_struct_union(const llvm::DWARFDie &die, int depth, const std::optional<std::string> &suggested_name);
  CTypePtr build_enum(const llvm::DWARFDie &die, int depth, const std::optional<std::string> &suggested_name);
  CTypePtr build_array(const llvm::DWARFDie &die, int depth, const std::optional<std::string> &suggested_name);
  CTypePtr apply_qualifier(const CTypePtr &type_ref, const std::string &qualifier);

  bool is_void_type(const CTypePtr &type_ref) const;
  CTypePtr opaque_type_for_size(int64_t size);
  std::optional<int64_t> member_offset(const llvm::DWARFDie &member_die, const std::string &parent_kind) const;
};

} // namespace kstructs

#endif // KSTRUCTS_DWARF_BUILDER_H
