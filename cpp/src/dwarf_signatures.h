#ifndef KSTRUCTS_DWARF_SIGNATURES_H
#define KSTRUCTS_DWARF_SIGNATURES_H

#include "dwarf_types.h"

#include <string>
#include <unordered_map>
#include <unordered_set>

namespace kstructs {

std::string normalized_type_signature(
    const TypeRegistry &registry,
    const CTypePtr &type_ref,
    std::unordered_map<std::string, std::string> &cache,
    std::unordered_set<std::string> &stack,
    bool layout_for_named,
    bool include_member_names);

} // namespace kstructs

#endif // KSTRUCTS_DWARF_SIGNATURES_H
