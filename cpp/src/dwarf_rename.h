#ifndef KSTRUCTS_DWARF_RENAME_H
#define KSTRUCTS_DWARF_RENAME_H

#include "dwarf_types.h"

#include <string>

namespace kstructs {

void apply_type_prefix(TypeRegistry &registry, const std::string &prefix);

} // namespace kstructs

#endif // KSTRUCTS_DWARF_RENAME_H
