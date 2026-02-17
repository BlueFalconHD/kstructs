from elftools.elf.elffile import ELFFile

from .dsym import dwarfinfo_from_macho
from .dwarf_emit import generate_c_for_type
from .dwarf_types import build_types_summary, load_types_summary


macho_magics = {
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
}


def detect_container_magic(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read(4)


def monkeypatch() -> None:
    import elftools.dwarf.dwarfinfo

    if getattr(elftools.dwarf.dwarfinfo, "_kstructs_strx_patch", False):
        return

    old_create_structs = elftools.dwarf.dwarfinfo.DWARFStructs._create_structs

    def _create_structs(self):
        old_create_structs(self)
        self.Dwarf_dw_form["DW_FORM_strx"] = self.the_Dwarf_uleb128
        if "DW_FORM_strx4" in self.Dwarf_dw_form:
            self.Dwarf_dw_form["DW_FORM_strx4"] = self.the_Dwarf_uint32

    elftools.dwarf.dwarfinfo.DWARFStructs._create_structs = _create_structs
    elftools.dwarf.dwarfinfo._kstructs_strx_patch = True


def dwarfinfo_from_path(filename: str, arch: str | None):
    monkeypatch()
    magic = detect_container_magic(filename)
    if magic == b"\x7fELF":
        with open(filename, "rb") as f:
            elf = ELFFile(f)
            if not elf.has_dwarf_info():
                raise ValueError("ELF file does not contain DWARF information.")
            return elf.get_dwarf_info()
    if magic in macho_magics:
        return dwarfinfo_from_macho(filename, arch=arch)
    raise ValueError("Unsupported file format: expected ELF or Mach-O.")


def print_types(filename: str, arch: str | None = None, name_filter: str | None = None, limit: int | None = None):
    if limit is None:
        limit = 100
    if limit < 0:
        raise ValueError("--limit must be >= 0")

    cached = load_types_summary(filename, arch, name_filter, limit)
    if cached is not None:
        total, counts, sample = cached
        print(f"{total} named types found in DWARF.")
        for tag in sorted(counts):
            print(f"{tag}: {counts[tag]}")
        if limit == 0:
            return
        print("Sample types:")
        for tag, name in sample:
            print(f"{tag} {name}")
        return

    dwarfinfo = dwarfinfo_from_path(filename, arch=arch)
    total, counts, sample = build_types_summary(filename=filename, arch=arch, dwarfinfo=dwarfinfo, name_filter=name_filter, limit=limit)

    print(f"{total} named types found in DWARF.")
    for tag in sorted(counts):
        print(f"{tag}: {counts[tag]}")

    if limit == 0:
        return

    print("Sample types:")
    for tag, name in sample:
        print(f"{tag} {name}")


# Backwards compat with earlier CLI name.
typestuff = print_types


def emit_c_types(
    filename: str,
    type_name: str,
    arch: str | None = None,
    max_depth: int = 1,
    correction_disable: set[str] | None = None,
    correction_verbose: set[str] | None = None,
    dwarf_verbose: set[str] | None = None,
) -> str:
    dwarfinfo = dwarfinfo_from_path(filename, arch=arch)
    return generate_c_for_type(
        dwarfinfo,
        type_name=type_name,
        max_depth=max_depth,
        correction_disable=correction_disable,
        correction_verbose=correction_verbose,
        dwarf_verbose=dwarf_verbose,
    )
