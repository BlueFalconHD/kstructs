#ifndef KSTRUCTS_DWARF_TYPES_H
#define KSTRUCTS_DWARF_TYPES_H

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <unordered_map>
#include <vector>
#include <map>

namespace kstructs {

enum class TypeKind {
  Named,
  Pointer,
  Array,
};

struct CType;
using CTypePtr = std::shared_ptr<CType>;

struct CType {
  TypeKind kind = TypeKind::Named;
  std::string name;
  std::string ref_kind;
  CTypePtr target;
  std::optional<int64_t> count;
  std::vector<std::string> qualifiers;

  bool needs_parens() const { return kind == TypeKind::Array; }
};

struct MemberInfo {
  std::string name;
  CTypePtr type_ref;
  std::optional<int64_t> offset;
  std::optional<int64_t> bit_size;
  std::optional<int64_t> bit_offset;
  std::optional<int64_t> alignment;
};

struct StructDecl {
  std::string kind;
  std::string name;
  std::optional<int64_t> size;
  std::vector<MemberInfo> members;
  bool opaque = false;
  std::string name_origin = "dwarf";
  bool packed = false;
  std::optional<int64_t> alignment;
};

struct EnumDecl {
  std::string name;
  std::optional<int64_t> size;
  std::vector<std::pair<std::string, int64_t>> enumerators;
  bool opaque = false;
  std::optional<std::string> typedef_as;
  std::optional<std::string> underlying;
};

struct TypedefDecl {
  std::string name;
  CTypePtr target;
};

struct KindNameKey {
  std::string kind;
  std::string name;

  bool operator<(const KindNameKey &other) const {
    return std::tie(kind, name) < std::tie(other.kind, other.name);
  }

  bool operator==(const KindNameKey &other) const {
    return kind == other.kind && name == other.name;
  }
};

struct InlineKey {
  std::string kind;
  std::string name;
  std::string member;

  bool operator<(const InlineKey &other) const {
    return std::tie(kind, name, member) < std::tie(other.kind, other.name, other.member);
  }

  bool operator==(const InlineKey &other) const {
    return kind == other.kind && name == other.name && member == other.member;
  }
};

struct TypeRegistry {
  std::map<KindNameKey, StructDecl> structs;
  std::map<std::string, EnumDecl> enums;
  std::map<std::string, TypedefDecl> typedefs;
  std::map<InlineKey, StructDecl> inline_members;
  std::map<InlineKey, StructDecl> inline_unions;
  std::unordered_map<std::string, int64_t> base_sizes;
  int64_t pointer_size = 8;
};

inline CTypePtr make_named(const std::string &name, const std::string &ref_kind) {
  auto ref = std::make_shared<CType>();
  ref->kind = TypeKind::Named;
  ref->name = name;
  ref->ref_kind = ref_kind;
  return ref;
}

inline CTypePtr make_pointer(const CTypePtr &target) {
  auto ref = std::make_shared<CType>();
  ref->kind = TypeKind::Pointer;
  ref->target = target;
  return ref;
}

inline CTypePtr make_array(const CTypePtr &target, std::optional<int64_t> count) {
  auto ref = std::make_shared<CType>();
  ref->kind = TypeKind::Array;
  ref->target = target;
  ref->count = count;
  return ref;
}

} // namespace kstructs

#endif // KSTRUCTS_DWARF_TYPES_H
