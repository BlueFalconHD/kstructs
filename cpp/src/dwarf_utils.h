#ifndef KSTRUCTS_DWARF_UTILS_H
#define KSTRUCTS_DWARF_UTILS_H

#include "dwarf_types.h"

#include <optional>
#include <string>
#include <unordered_set>

namespace kstructs {

std::string sanitize_identifier(const std::string &name);

CTypePtr resolve_typedef(const TypeRegistry &registry, const CTypePtr &type_ref,
                         std::unordered_set<std::string> &seen);

CTypePtr clone_type_ref(const CTypePtr &type_ref);

bool is_synthetic_member_name(const std::string &name);

std::string sig_digest(const std::string &input);

} // namespace kstructs

#endif // KSTRUCTS_DWARF_UTILS_H
