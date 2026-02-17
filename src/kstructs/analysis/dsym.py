import io
from typing import Dict, Iterable, Optional

from elftools.dwarf.dwarfinfo import DWARFInfo, DebugSectionDescriptor, DwarfConfig
from macholib import mach_o
from macholib.MachO import MachO


DWARF_SECTION_NAMES = {
    "__debug_info",
    "__debug_aranges",
    "__debug_abbrev",
    "__debug_frame",
    "__eh_frame",
    "__debug_str",
    "__debug_loc",
    "__debug_ranges",
    "__debug_line",
    "__debug_pubtypes",
    "__debug_pubnames",
    "__debug_addr",
    "__debug_str_offs",
    "__debug_line_str",
    "__debug_loclists",
    "__debug_rnglists",
    "__debug_sup",
    "__gnu_debugaltlink",
    "__debug_types",
}

ARCH_SYNONYMS = {
    "x86_64": {"x86_64", "x64", "amd64", "x8664"},
    "x86": {"x86", "i386", "i686"},
    "arm64": {"arm64", "aarch64"},
    "arm64e": {"arm64e"},
    "arm": {"arm", "armv7", "armv7s"},
    "ppc": {"ppc", "powerpc"},
    "ppc64": {"ppc64", "powerpc64"},
}

DWARF_MACHINE_ARCH = {
    "x86": "x86",
    "x86_64": "x64",
    "arm": "ARM",
    "arm64": "AArch64",
    "arm64e": "AArch64",
    "ppc": "PPC",
    "ppc64": "PPC64",
}


def strip_cstr(value: bytes) -> str:
    return value.split(b"\x00", 1)[0].decode("utf-8", "replace")


def normalize_arch(value: str) -> str:
    return value.lower().replace("-", "").replace("_", "")


def arch_name_for_header(header) -> str:
    cputype = header.header.cputype
    cpusubtype = header.header.cpusubtype
    cpu_name = mach_o.CPU_TYPE_NAMES.get(cputype, "unknown").lower()
    if cpu_name in {"x86_64"}:
        return "x86_64"
    if cpu_name in {"i386"}:
        return "x86"
    if cpu_name in {"arm64"}:
        if cpusubtype == 2:
            return "arm64e"
        return "arm64"
    if cpu_name in {"arm"}:
        return "arm"
    if cpu_name in {"powerpc"}:
        return "ppc"
    if cpu_name in {"powerpc64"}:
        return "ppc64"
    return cpu_name


def header_arch_info(header) -> Dict[str, object]:
    name = arch_name_for_header(header)
    magic = header.header.magic
    little_endian = magic in (mach_o.MH_MAGIC, mach_o.MH_MAGIC_64)
    is_64 = magic in (mach_o.MH_MAGIC_64, mach_o.MH_CIGAM_64) or "64" in name
    default_address_size = 8 if is_64 else 4
    return {
        "name": name,
        "default_address_size": default_address_size,
        "little_endian": little_endian,
    }


def arch_matches(requested: str, candidate: str) -> bool:
    if not requested:
        return False
    requested_norm = normalize_arch(requested)
    candidate_norm = normalize_arch(candidate)
    if requested_norm == candidate_norm:
        return True
    for canonical, aliases in ARCH_SYNONYMS.items():
        if candidate == canonical and requested_norm in {normalize_arch(a) for a in aliases}:
            return True
    return False


def iter_section_descriptors(
    fileobj,
    header,
    desired_names: Iterable[str],
) -> Dict[str, DebugSectionDescriptor]:
    desired = set(desired_names)
    sections: Dict[str, DebugSectionDescriptor] = {}
    for load_cmd, cmd, data in header.commands:
        if load_cmd.cmd not in (mach_o.LC_SEGMENT, mach_o.LC_SEGMENT_64):
            continue
        for section in data:
            name = strip_cstr(section.sectname)
            if name not in desired:
                continue
            if name in sections:
                continue
            offset = header.offset + section.offset
            size = section.size
            address = getattr(section, "addr", 0)
            fileobj.seek(offset)
            payload = fileobj.read(size)
            sections[name] = DebugSectionDescriptor(
                io.BytesIO(payload),
                name,
                offset,
                size,
                address,
            )
    return sections


def select_header(macho: MachO, arch: Optional[str]) -> Optional[object]:
    if not macho.headers:
        return None
    if arch:
        available = []
        for header in macho.headers:
            name = arch_name_for_header(header)
            available.append(name)
            if arch_matches(arch, name):
                return header
        available_str = ", ".join(sorted(set(available))) or "unknown"
        raise ValueError(f"Requested arch '{arch}' not found. Available: {available_str}.")
    for header in macho.headers:
        for load_cmd, cmd, data in header.commands:
            if load_cmd.cmd in (mach_o.LC_SEGMENT, mach_o.LC_SEGMENT_64):
                if strip_cstr(cmd.segname) == "__DWARF":
                    return header
    return macho.headers[0]


def dwarfinfo_from_macho(path: str, arch: Optional[str] = None) -> DWARFInfo:
    macho = MachO(path)
    header = select_header(macho, arch)
    if header is None:
        raise ValueError(f"No Mach-O headers found in {path}.")

    arch_info = header_arch_info(header)
    machine_arch = DWARF_MACHINE_ARCH.get(arch_info["name"])
    if machine_arch is None:
        machine_arch = "x64" if arch_info["default_address_size"] == 8 else "x86"

    with open(path, "rb") as fileobj:
        sections = iter_section_descriptors(fileobj, header, DWARF_SECTION_NAMES)

    debug_info = sections.get("__debug_info")
    if debug_info is None:
        raise ValueError("Mach-O file does not contain a __debug_info section.")

    return DWARFInfo(
        config=DwarfConfig(
            little_endian=arch_info["little_endian"],
            default_address_size=arch_info["default_address_size"],
            machine_arch=machine_arch,
        ),
        debug_info_sec=debug_info,
        debug_aranges_sec=sections.get("__debug_aranges"),
        debug_abbrev_sec=sections.get("__debug_abbrev"),
        debug_frame_sec=sections.get("__debug_frame"),
        eh_frame_sec=sections.get("__eh_frame"),
        debug_str_sec=sections.get("__debug_str"),
        debug_loc_sec=sections.get("__debug_loc"),
        debug_ranges_sec=sections.get("__debug_ranges"),
        debug_line_sec=sections.get("__debug_line"),
        debug_pubtypes_sec=sections.get("__debug_pubtypes"),
        debug_pubnames_sec=sections.get("__debug_pubnames"),
        debug_addr_sec=sections.get("__debug_addr"),
        debug_str_offsets_sec=sections.get("__debug_str_offs"),
        debug_line_str_sec=sections.get("__debug_line_str"),
        debug_loclists_sec=sections.get("__debug_loclists"),
        debug_rnglists_sec=sections.get("__debug_rnglists"),
        debug_sup_sec=sections.get("__debug_sup"),
        gnu_debugaltlink_sec=sections.get("__gnu_debugaltlink"),
        debug_types_sec=sections.get("__debug_types"),
    )
