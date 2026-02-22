#ifndef KSTRUCTS_DWARF_CORRECTIONS_H
#define KSTRUCTS_DWARF_CORRECTIONS_H

#include "dwarf_types.h"

#include <functional>
#include <set>
#include <string>

namespace kstructs {

using CorrectionLog = std::function<void(const std::string &)>;

void apply_corrections(TypeRegistry &registry,
                       const std::set<std::string> &disabled,
                       const std::set<std::string> *verbose);

} // namespace kstructs

#endif // KSTRUCTS_DWARF_CORRECTIONS_H
