import hashlib
from pathlib import Path
import struct

from elftools.dwarf.enums import ENUM_DW_AT, ENUM_DW_FORM, ENUM_DW_TAG


TYPE_TAG_NAMES = [
    "DW_TAG_structure_type",
    "DW_TAG_union_type",
    "DW_TAG_enumeration_type",
    "DW_TAG_typedef",
    "DW_TAG_class_type",
    "DW_TAG_base_type",
]

DW_AT = {name: value for name, value in ENUM_DW_AT.items() if isinstance(value, int)}
DW_FORM = {name: value for name, value in ENUM_DW_FORM.items() if isinstance(value, int)}
DW_TAG = {name: value for name, value in ENUM_DW_TAG.items() if isinstance(value, int)}

TYPE_TAG_VALUES = {DW_TAG[name] for name in TYPE_TAG_NAMES}

DW_AT_name = DW_AT["DW_AT_name"]
DW_AT_str_offsets_base = DW_AT.get("DW_AT_str_offsets_base")
DW_AT_sibling = DW_AT.get("DW_AT_sibling")

DW_FORM_implicit_const = DW_FORM.get("DW_FORM_implicit_const", 0x21)
DW_FORM_indirect = DW_FORM.get("DW_FORM_indirect", 0x16)

# DWARF v5 base form (pyelftools 0.32 doesn't list it, but compilers emit it)
DW_FORM_strx = DW_FORM.get("DW_FORM_strx", 0x1A)

SKIP_CHILDREN_TAG_VALUES = {
    value
    for value in [
        DW_TAG.get("DW_TAG_subprogram"),
        DW_TAG.get("DW_TAG_inlined_subroutine"),
        DW_TAG.get("DW_TAG_lexical_block"),
        DW_TAG.get("DW_TAG_try_block"),
        DW_TAG.get("DW_TAG_catch_block"),
    ]
    if value is not None
}

CACHE_MAGIC = b"KSTY"
CACHE_VERSION = 1
CACHE_FLAG_LITTLE_ENDIAN = 1


def read_section_bytes(section) -> bytes | None:
    if section is None:
        return None
    stream = section.stream
    try:
        pos = stream.tell()
    except Exception:
        pos = None
    try:
        stream.seek(0)
        data = stream.read()
    finally:
        if pos is not None:
            stream.seek(pos)
    return data


def read_uleb128(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, offset
        shift += 7


def read_sleb128(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if byte < 0x80:
            if byte & 0x40:
                value |= -(1 << shift)
            return value, offset


def read_cstring(data: bytes, offset: int) -> tuple[str, int]:
    end = data.find(b"\x00", offset)
    if end < 0:
        end = len(data)
    return data[offset:end].decode("utf-8", "replace"), end + 1


def read_uint(data: bytes, offset: int, size: int, little_endian: bool) -> tuple[int, int]:
    order = "little" if little_endian else "big"
    return int.from_bytes(data[offset:offset + size], order), offset + size


def parse_abbrev_table(
    abbrev_data: bytes, abbrev_offset: int
) -> dict[int, tuple[int, bool, list[tuple[int, int, int | None]]]]:
    table: dict[int, tuple[int, bool, list[tuple[int, int, int | None]]]] = {}
    offset = abbrev_offset
    while offset < len(abbrev_data):
        code, offset = read_uleb128(abbrev_data, offset)
        if code == 0:
            break
        tag_value, offset = read_uleb128(abbrev_data, offset)
        has_children = abbrev_data[offset] != 0
        offset += 1
        specs: list[tuple[int, int, int | None]] = []
        while True:
            attr, offset = read_uleb128(abbrev_data, offset)
            form, offset = read_uleb128(abbrev_data, offset)
            if attr == 0 and form == 0:
                break
            implicit_const = None
            if form == DW_FORM_implicit_const:
                implicit_const, offset = read_sleb128(abbrev_data, offset)
            specs.append((attr, form, implicit_const))
        table[code] = (tag_value, has_children, specs)
    return table


def skip_form(
    form: int,
    info_data: bytes,
    offset: int,
    little_endian: bool,
    addr_size: int,
    offset_size: int,
    dwarf_version: int,
) -> int:
    if form == DW_FORM_indirect:
        actual_form, offset = read_uleb128(info_data, offset)
        return skip_form(actual_form, info_data, offset, little_endian, addr_size, offset_size, dwarf_version)

    if form == DW_FORM_implicit_const or form == DW_FORM.get("DW_FORM_flag_present", 0x19):
        return offset

    fixed_sizes = {
        DW_FORM.get("DW_FORM_data1", 0x0B): 1,
        DW_FORM.get("DW_FORM_ref1", 0x11): 1,
        DW_FORM.get("DW_FORM_flag", 0x0C): 1,
        DW_FORM.get("DW_FORM_data2", 0x05): 2,
        DW_FORM.get("DW_FORM_ref2", 0x12): 2,
        DW_FORM.get("DW_FORM_data4", 0x06): 4,
        DW_FORM.get("DW_FORM_ref4", 0x13): 4,
        DW_FORM.get("DW_FORM_data8", 0x07): 8,
        DW_FORM.get("DW_FORM_ref8", 0x14): 8,
        DW_FORM.get("DW_FORM_ref_sig8", 0x20): 8,
        DW_FORM.get("DW_FORM_data16", 0x1E): 16,
        DW_FORM.get("DW_FORM_strx1", 0x25): 1,
        DW_FORM.get("DW_FORM_addrx1", 0x29): 1,
        DW_FORM.get("DW_FORM_strx2", 0x26): 2,
        DW_FORM.get("DW_FORM_addrx2", 0x2A): 2,
        DW_FORM.get("DW_FORM_strx3", 0x27): 3,
        DW_FORM.get("DW_FORM_addrx3", 0x2B): 3,
        DW_FORM.get("DW_FORM_strx4", 0x28): 4,
        DW_FORM.get("DW_FORM_addrx4", 0x2C): 4,
    }
    if form in fixed_sizes:
        return offset + fixed_sizes[form]

    if form == DW_FORM.get("DW_FORM_addr", 0x01):
        return offset + addr_size
    if form == DW_FORM.get("DW_FORM_sdata", 0x0D):
        _, offset = read_sleb128(info_data, offset)
        return offset
    if form in (DW_FORM.get("DW_FORM_udata", 0x0F), DW_FORM.get("DW_FORM_ref_udata", 0x15)):
        _, offset = read_uleb128(info_data, offset)
        return offset
    if form in (
        DW_FORM.get("DW_FORM_sec_offset", 0x17),
        DW_FORM.get("DW_FORM_strp", 0x0E),
        DW_FORM.get("DW_FORM_strp_sup", 0x1D),
        DW_FORM.get("DW_FORM_line_strp", 0x1F),
    ):
        return offset + offset_size
    if form == DW_FORM_strx:
        _, offset = read_uleb128(info_data, offset)
        return offset
    if form == DW_FORM.get("DW_FORM_string", 0x08):
        _, offset = read_cstring(info_data, offset)
        return offset
    if form == DW_FORM.get("DW_FORM_block1", 0x0A):
        size = info_data[offset]
        return offset + 1 + size
    if form == DW_FORM.get("DW_FORM_block2", 0x03):
        size, offset = read_uint(info_data, offset, 2, little_endian)
        return offset + size
    if form == DW_FORM.get("DW_FORM_block4", 0x04):
        size, offset = read_uint(info_data, offset, 4, little_endian)
        return offset + size
    if form in (DW_FORM.get("DW_FORM_block", 0x09), DW_FORM.get("DW_FORM_exprloc", 0x18)):
        size, offset = read_uleb128(info_data, offset)
        return offset + size
    if form == DW_FORM.get("DW_FORM_ref_addr", 0x10):
        return offset + (addr_size if dwarf_version <= 2 else offset_size)
    if form in (
        DW_FORM.get("DW_FORM_addrx", 0x1B),
        DW_FORM.get("DW_FORM_loclistx", 0x22),
        DW_FORM.get("DW_FORM_rnglistx", 0x23),
    ):
        _, offset = read_uleb128(info_data, offset)
        return offset

    raise NotImplementedError(f"Unsupported DW_FORM {form}")


def read_strx_index(form: int, info_data: bytes, offset: int, little_endian: bool) -> tuple[int | None, int]:
    if form == DW_FORM_strx:
        return read_uleb128(info_data, offset)
    if form == DW_FORM.get("DW_FORM_strx1", 0x25):
        return read_uint(info_data, offset, 1, little_endian)
    if form == DW_FORM.get("DW_FORM_strx2", 0x26):
        return read_uint(info_data, offset, 2, little_endian)
    if form == DW_FORM.get("DW_FORM_strx3", 0x27):
        value = int.from_bytes(info_data[offset:offset + 3], "little" if little_endian else "big")
        return value, offset + 3
    if form == DW_FORM.get("DW_FORM_strx4", 0x28):
        return read_uint(info_data, offset, 4, little_endian)
    return None, offset


def read_name_from_form(
    form: int,
    info_data: bytes,
    offset: int,
    little_endian: bool,
    addr_size: int,
    offset_size: int,
    dwarf_version: int,
    debug_str: bytes | None,
    debug_str_offsets: bytes | None,
    str_offsets_base: int | None,
) -> tuple[str | None, int]:
    if form == DW_FORM_indirect:
        actual_form, offset = read_uleb128(info_data, offset)
        return read_name_from_form(
            actual_form,
            info_data,
            offset,
            little_endian,
            addr_size,
            offset_size,
            dwarf_version,
            debug_str,
            debug_str_offsets,
            str_offsets_base,
        )

    if form == DW_FORM.get("DW_FORM_string", 0x08):
        value, offset = read_cstring(info_data, offset)
        return value, offset

    if form == DW_FORM.get("DW_FORM_strp", 0x0E):
        if debug_str is None:
            return None, offset + offset_size
        str_off, offset = read_uint(info_data, offset, offset_size, little_endian)
        value, _ = read_cstring(debug_str, str_off)
        return value, offset

    index, offset = read_strx_index(form, info_data, offset, little_endian)
    if index is not None:
        if debug_str is None or debug_str_offsets is None or str_offsets_base is None:
            return None, offset
        entry_off = str_offsets_base + index * offset_size
        if entry_off + offset_size > len(debug_str_offsets):
            return None, offset
        str_off, _ = read_uint(debug_str_offsets, entry_off, offset_size, little_endian)
        value, _ = read_cstring(debug_str, str_off)
        return value, offset

    return None, skip_form(form, info_data, offset, little_endian, addr_size, offset_size, dwarf_version)


def read_uint_attr_from_form(
    form: int,
    info_data: bytes,
    offset: int,
    little_endian: bool,
    addr_size: int,
    offset_size: int,
    dwarf_version: int,
) -> tuple[int | None, int]:
    if form == DW_FORM_indirect:
        actual_form, offset = read_uleb128(info_data, offset)
        return read_uint_attr_from_form(actual_form, info_data, offset, little_endian, addr_size, offset_size, dwarf_version)

    if form in (
        DW_FORM.get("DW_FORM_sec_offset", 0x17),
        DW_FORM.get("DW_FORM_strp", 0x0E),
        DW_FORM.get("DW_FORM_line_strp", 0x1F),
    ):
        value, offset = read_uint(info_data, offset, offset_size, little_endian)
        return value, offset
    if form == DW_FORM.get("DW_FORM_data4", 0x06):
        value, offset = read_uint(info_data, offset, 4, little_endian)
        return value, offset
    if form == DW_FORM.get("DW_FORM_data8", 0x07):
        value, offset = read_uint(info_data, offset, 8, little_endian)
        return value, offset
    if form == DW_FORM.get("DW_FORM_udata", 0x0F):
        value, offset = read_uleb128(info_data, offset)
        return value, offset

    return None, skip_form(form, info_data, offset, little_endian, addr_size, offset_size, dwarf_version)


def read_sibling_abs_from_form(
    form: int,
    info_data: bytes,
    offset: int,
    little_endian: bool,
    addr_size: int,
    offset_size: int,
    dwarf_version: int,
    unit_start: int,
) -> tuple[int | None, int]:
    if form == DW_FORM_indirect:
        actual_form, offset = read_uleb128(info_data, offset)
        return read_sibling_abs_from_form(
            actual_form, info_data, offset, little_endian, addr_size, offset_size, dwarf_version, unit_start
        )

    ref_forms = {
        DW_FORM.get("DW_FORM_ref1", 0x11): 1,
        DW_FORM.get("DW_FORM_ref2", 0x12): 2,
        DW_FORM.get("DW_FORM_ref4", 0x13): 4,
        DW_FORM.get("DW_FORM_ref8", 0x14): 8,
    }
    if form in ref_forms:
        rel, offset = read_uint(info_data, offset, ref_forms[form], little_endian)
        return unit_start + rel, offset
    if form == DW_FORM.get("DW_FORM_ref_udata", 0x15):
        rel, offset = read_uleb128(info_data, offset)
        return unit_start + rel, offset
    if form == DW_FORM.get("DW_FORM_ref_addr", 0x10):
        abs_off, offset = read_uint(info_data, offset, addr_size if dwarf_version <= 2 else offset_size, little_endian)
        return abs_off, offset

    return None, skip_form(form, info_data, offset, little_endian, addr_size, offset_size, dwarf_version)


def types_cache_key(filename: str, arch: str | None) -> str:
    st = Path(filename).stat()
    raw = f"{filename}\n{st.st_size}\n{st.st_mtime_ns}\n{arch or ''}\n".encode("utf-8", "replace")
    return hashlib.sha256(raw).hexdigest()[:32]


def types_cache_path(filename: str, arch: str | None) -> Path:
    key = types_cache_key(filename, arch)
    cache_dir = Path.home() / ".cache" / "kstructs"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir / f"types-{key}.ksty"


def write_uleb128(value: int) -> bytes:
    if value < 0:
        raise ValueError("uleb128 value must be >= 0")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def parse_types_cache(data: bytes):
    # Binary format (little-endian):
    # - 4  magic "KSTY"
    # - 2  version (u16)
    # - 2  flags (u16) bit0 = little-endian
    # - 8  source file size (u64)
    # - 8  source mtime ns (u64)
    # - 2  arch length (u16)
    # - N  arch bytes (utf-8)
    # - 8  entry count (u64) (named types)
    # - 8*len(TYPE_TAG_NAMES) counts per tag (u64)
    # - records:
    #   - 1 tag index (u8)
    #   - uleb128 name byte length
    #   - name bytes (utf-8)
    if len(data) < 4 + 2 + 2 + 8 + 8 + 2:
        return None
    magic = data[0:4]
    if magic != CACHE_MAGIC:
        return None
    version = int.from_bytes(data[4:6], "little")
    if version != CACHE_VERSION:
        return None
    flags = int.from_bytes(data[6:8], "little")
    little_endian = bool(flags & CACHE_FLAG_LITTLE_ENDIAN)
    if not little_endian:
        return None
    source_size = int.from_bytes(data[8:16], "little")
    source_mtime_ns = int.from_bytes(data[16:24], "little")
    arch_len = int.from_bytes(data[24:26], "little")
    arch_start = 26
    arch_end = arch_start + arch_len
    if arch_end > len(data):
        return None
    arch = data[arch_start:arch_end].decode("utf-8", "replace")

    fixed_header = arch_end
    needed = fixed_header + 8 + (len(TYPE_TAG_NAMES) * 8)
    if needed > len(data):
        return None

    entry_count = int.from_bytes(data[fixed_header:fixed_header + 8], "little")
    counts_start = fixed_header + 8
    counts = []
    off = counts_start
    for _ in range(len(TYPE_TAG_NAMES)):
        counts.append(int.from_bytes(data[off:off + 8], "little"))
        off += 8

    records_offset = off
    return {
        "source_size": source_size,
        "source_mtime_ns": source_mtime_ns,
        "arch": arch,
        "entry_count": entry_count,
        "counts": counts,
        "records_offset": records_offset,
    }


def load_types_cache_bytes(filename: str, arch: str | None) -> bytes | None:
    path = types_cache_path(filename, arch)
    try:
        return path.read_bytes()
    except FileNotFoundError:
        return None
    except Exception:
        return None


def load_types_cache_header(filename: str, arch: str | None):
    cache_bytes = load_types_cache_bytes(filename, arch)
    if cache_bytes is None:
        return None
    header = parse_types_cache(cache_bytes)
    if header is None:
        return None
    st = Path(filename).stat()
    if header["source_size"] != st.st_size or header["source_mtime_ns"] != st.st_mtime_ns:
        return None
    if header["arch"] != (arch or ""):
        return None
    header["cache_bytes"] = cache_bytes
    return header


def iter_cache_records(cache_bytes: bytes, offset: int):
    end = len(cache_bytes)
    while offset < end:
        tag_index = cache_bytes[offset]
        offset += 1
        name_len, offset = read_uleb128(cache_bytes, offset)
        name_end = offset + name_len
        if name_end > end:
            return
        name = cache_bytes[offset:name_end].decode("utf-8", "replace")
        offset = name_end
        yield tag_index, name


def sample_from_cache(cache_bytes: bytes, records_offset: int, limit: int) -> list[tuple[str, str]]:
    if limit <= 0:
        return []
    sample: list[tuple[str, str]] = []
    seen: set[tuple[int, str]] = set()
    for tag_index, name in iter_cache_records(cache_bytes, records_offset):
        if tag_index >= len(TYPE_TAG_NAMES):
            continue
        key = (tag_index, name)
        if key in seen:
            continue
        seen.add(key)
        sample.append((TYPE_TAG_NAMES[tag_index], name))
        if len(sample) >= limit:
            return sample
    return sample


def filter_from_cache(cache_bytes: bytes, records_offset: int, name_filter: str, limit: int) -> tuple[int, dict[str, int], list[tuple[str, str]]]:
    filter_lower = name_filter.lower()
    counts = [0] * len(TYPE_TAG_NAMES)
    sample: list[tuple[str, str]] = []
    seen: set[tuple[int, str]] = set()
    total = 0
    for tag_index, name in iter_cache_records(cache_bytes, records_offset):
        if tag_index >= len(TYPE_TAG_NAMES):
            continue
        if filter_lower not in name.lower():
            continue
        total += 1
        counts[tag_index] += 1
        if limit > 0 and len(sample) < limit:
            key = (tag_index, name)
            if key not in seen:
                seen.add(key)
                sample.append((TYPE_TAG_NAMES[tag_index], name))
    counts_dict = {TYPE_TAG_NAMES[i]: counts[i] for i in range(len(TYPE_TAG_NAMES)) if counts[i]}
    return total, counts_dict, sample


def iter_named_types(dwarfinfo):
    debug_info = read_section_bytes(dwarfinfo.debug_info_sec)
    debug_abbrev = read_section_bytes(dwarfinfo.debug_abbrev_sec)
    debug_str = read_section_bytes(dwarfinfo.debug_str_sec)
    debug_str_offsets = read_section_bytes(getattr(dwarfinfo, "debug_str_offsets_sec", None))
    if debug_info is None or debug_abbrev is None:
        raise ValueError("Missing required DWARF sections: .debug_info/.debug_abbrev")

    little_endian = dwarfinfo.config.little_endian
    abbrev_cache: dict[int, dict[int, tuple[int, bool, list[tuple[int, int, int | None]]]]] = {}

    u16 = struct.Struct("<H" if little_endian else ">H")
    u32 = struct.Struct("<I" if little_endian else ">I")
    u64 = struct.Struct("<Q" if little_endian else ">Q")

    offset = 0
    while offset + 4 <= len(debug_info):
        unit_start = offset
        initial_length = u32.unpack_from(debug_info, offset)[0]
        offset += 4

        if initial_length == 0xFFFFFFFF:
            unit_length = u64.unpack_from(debug_info, offset)[0]
            offset += 8
            offset_size = 8
            header_size = 12
        else:
            unit_length = initial_length
            offset_size = 4
            header_size = 4

        unit_end = unit_start + header_size + unit_length
        if unit_end > len(debug_info):
            break

        dwarf_version = u16.unpack_from(debug_info, offset)[0]
        offset += 2

        if dwarf_version >= 5:
            unit_type = debug_info[offset]
            offset += 1
            addr_size = debug_info[offset]
            offset += 1
            abbrev_offset, offset = read_uint(debug_info, offset, offset_size, little_endian)
            if unit_type in (0x04, 0x05):  # DW_UT_skeleton, DW_UT_split_compile
                offset += 8
        else:
            abbrev_offset, offset = read_uint(debug_info, offset, offset_size, little_endian)
            addr_size = debug_info[offset]
            offset += 1

        die_offset = offset
        offset = unit_end

        abbrev_table = abbrev_cache.get(abbrev_offset)
        if abbrev_table is None:
            abbrev_table = parse_abbrev_table(debug_abbrev, abbrev_offset)
            abbrev_cache[abbrev_offset] = abbrev_table

        str_offsets_base = None
        if DW_AT_str_offsets_base is not None:
            code, cursor = read_uleb128(debug_info, die_offset)
            abbrev = abbrev_table.get(code)
            if abbrev is not None:
                _, _, specs = abbrev
                for attr, form, implicit_const in specs:
                    if form == DW_FORM_implicit_const:
                        continue
                    if attr == DW_AT_str_offsets_base:
                        str_offsets_base, cursor = read_uint_attr_from_form(
                            form, debug_info, cursor, little_endian, addr_size, offset_size, dwarf_version
                        )
                    else:
                        cursor = skip_form(form, debug_info, cursor, little_endian, addr_size, offset_size, dwarf_version)

        cursor = die_offset
        depth = 0
        while cursor < unit_end:
            code, cursor = read_uleb128(debug_info, cursor)
            if code == 0:
                depth -= 1
                if depth < 0:
                    break
                continue

            abbrev = abbrev_table.get(code)
            if abbrev is None:
                break
            tag_value, has_children, specs = abbrev

            is_type_tag = tag_value in TYPE_TAG_VALUES
            found_name = None
            sibling_abs = None

            for attr, form, implicit_const in specs:
                if form == DW_FORM_implicit_const:
                    continue
                if DW_AT_sibling is not None and has_children and attr == DW_AT_sibling:
                    sibling_abs, cursor = read_sibling_abs_from_form(
                        form, debug_info, cursor, little_endian, addr_size, offset_size, dwarf_version, unit_start
                    )
                    continue
                if is_type_tag and attr == DW_AT_name:
                    found_name, cursor = read_name_from_form(
                        form,
                        debug_info,
                        cursor,
                        little_endian,
                        addr_size,
                        offset_size,
                        dwarf_version,
                        debug_str,
                        debug_str_offsets,
                        str_offsets_base,
                    )
                else:
                    cursor = skip_form(form, debug_info, cursor, little_endian, addr_size, offset_size, dwarf_version)

            if is_type_tag and found_name:
                yield tag_value, found_name

            if has_children:
                if sibling_abs is not None and sibling_abs >= cursor and sibling_abs <= unit_end and (
                    tag_value in SKIP_CHILDREN_TAG_VALUES or tag_value in TYPE_TAG_VALUES
                ):
                    cursor = sibling_abs
                else:
                    depth += 1


def build_types_cache(filename: str, arch: str | None, dwarfinfo) -> None:
    path = types_cache_path(filename, arch)
    tmp = path.with_suffix(".tmp")

    st = Path(filename).stat()
    arch_bytes = (arch or "").encode("utf-8", "replace")
    header_prefix = struct.pack(
        "<4sHHQQH",
        CACHE_MAGIC,
        CACHE_VERSION,
        CACHE_FLAG_LITTLE_ENDIAN,
        st.st_size,
        st.st_mtime_ns,
        len(arch_bytes),
    )

    counts = [0] * len(TYPE_TAG_NAMES)
    entry_count = 0
    tag_index_by_value = {DW_TAG[name]: i for i, name in enumerate(TYPE_TAG_NAMES)}

    with tmp.open("wb") as f:
        f.write(header_prefix)
        f.write(arch_bytes)

        entry_count_offset = f.tell()
        f.write(struct.pack("<Q", 0))
        counts_offset = f.tell()
        for _ in range(len(TYPE_TAG_NAMES)):
            f.write(struct.pack("<Q", 0))

        for tag_value, name in iter_named_types(dwarfinfo):
            tag_index = tag_index_by_value.get(tag_value)
            if tag_index is None:
                continue
            name_bytes = name.encode("utf-8", "replace")
            f.write(bytes([tag_index]))
            f.write(write_uleb128(len(name_bytes)))
            f.write(name_bytes)
            counts[tag_index] += 1
            entry_count += 1

        f.seek(entry_count_offset)
        f.write(struct.pack("<Q", entry_count))
        f.seek(counts_offset)
        for count in counts:
            f.write(struct.pack("<Q", count))

    tmp.replace(path)


def build_types_summary(
    filename: str,
    arch: str | None,
    dwarfinfo,
    name_filter: str | None,
    limit: int,
) -> tuple[int, dict[str, int], list[tuple[str, str]]]:
    build_types_cache(filename, arch, dwarfinfo)
    header = load_types_cache_header(filename, arch)
    if header is None:
        raise ValueError("Failed to build types cache.")

    cache_bytes = header["cache_bytes"]
    if name_filter is None:
        total = int(header["entry_count"])
        counts_list = header["counts"]
        counts = {TYPE_TAG_NAMES[i]: counts_list[i] for i in range(len(TYPE_TAG_NAMES)) if counts_list[i]}
        sample = sample_from_cache(cache_bytes, header["records_offset"], limit)
        return total, counts, sample

    return filter_from_cache(cache_bytes, header["records_offset"], name_filter, limit)


def load_types_summary(filename: str, arch: str | None, name_filter: str | None, limit: int):
    header = load_types_cache_header(filename, arch)
    if header is None:
        return None
    cache_bytes = header["cache_bytes"]
    if name_filter is None:
        total = int(header["entry_count"])
        counts_list = header["counts"]
        counts = {TYPE_TAG_NAMES[i]: counts_list[i] for i in range(len(TYPE_TAG_NAMES)) if counts_list[i]}
        sample = sample_from_cache(cache_bytes, header["records_offset"], limit)
        return total, counts, sample
    return filter_from_cache(cache_bytes, header["records_offset"], name_filter, limit)
