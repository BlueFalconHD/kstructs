#ifndef KSTRUCTS_DWARF_RENDER_H
#define KSTRUCTS_DWARF_RENDER_H

#include "dwarf_types.h"

#include <string>

namespace kstructs {

std::string render_type(const TypeRegistry &registry,
                        const CTypePtr &type_ref,
                        const std::string &name,
                        bool expand_typedefs);

std::string render_c(const TypeRegistry &registry);

} // namespace kstructs

#endif // KSTRUCTS_DWARF_RENDER_H
