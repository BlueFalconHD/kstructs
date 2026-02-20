#ifndef KSTRUCTS_DWARF_SIGNATURES_H
#define KSTRUCTS_DWARF_SIGNATURES_H

#include "dwarf_types.h"

#include <array>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace kstructs {

struct TypeSignature {
  std::array<uint8_t, 20> bytes{};

  bool operator==(const TypeSignature &other) const {
    return bytes == other.bytes;
  }

  bool operator!=(const TypeSignature &other) const {
    return !(*this == other);
  }
};

std::string signature_hex(const TypeSignature &sig);
std::string signature_digest(const TypeSignature &sig);

TypeSignature normalized_type_signature(
    const TypeRegistry &registry,
    const CTypePtr &type_ref,
    std::unordered_map<std::string, TypeSignature> &cache,
    std::unordered_set<std::string> &stack,
    bool layout_for_named,
    bool include_member_names);

} // namespace kstructs

#endif // KSTRUCTS_DWARF_SIGNATURES_H
