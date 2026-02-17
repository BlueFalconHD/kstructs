from elftools.elf.elffile import ELFFile

from .dsym import dwarfinfo_from_macho
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


def dwarfinfo_from_path(filename: str, arch: str | None):
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

    if name_filter is None:
        cached = load_types_summary(filename, arch, limit)
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
