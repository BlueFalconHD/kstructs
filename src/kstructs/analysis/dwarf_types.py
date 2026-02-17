import hashlib
import json
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
TYPE_TAG_NAME_BY_VALUE = {DW_TAG[name]: name for name in TYPE_TAG_NAMES}

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


def scan_named_types(dwarfinfo, name_filter: str | None, sample_limit: int) -> tuple[int, dict[str, int], list[tuple[str, str]]]:
    debug_info = read_section_bytes(dwarfinfo.debug_info_sec)
    debug_abbrev = read_section_bytes(dwarfinfo.debug_abbrev_sec)
    debug_str = read_section_bytes(dwarfinfo.debug_str_sec)
    debug_str_offsets = read_section_bytes(getattr(dwarfinfo, "debug_str_offsets_sec", None))
    if debug_info is None or debug_abbrev is None:
        raise ValueError("Missing required DWARF sections: .debug_info/.debug_abbrev")

    little_endian = dwarfinfo.config.little_endian
    filter_lower = name_filter.lower() if name_filter else None

    abbrev_cache: dict[int, dict[int, tuple[int, bool, list[tuple[int, int, int | None]]]]] = {}
    counts_by_tag_value: dict[int, int] = {tag_value: 0 for tag_value in TYPE_TAG_VALUES}
    sample: list[tuple[str, str]] = []
    sample_seen: set[tuple[int, str]] = set()

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
            has_name_attr = False
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
                    has_name_attr = True
                    should_decode = filter_lower is not None or (sample_limit > 0 and len(sample) < sample_limit)
                    if should_decode:
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
                else:
                    cursor = skip_form(form, debug_info, cursor, little_endian, addr_size, offset_size, dwarf_version)

            if is_type_tag and has_name_attr:
                if filter_lower is None:
                    counts_by_tag_value[tag_value] += 1
                    if found_name and sample_limit > 0 and len(sample) < sample_limit:
                        key = (tag_value, found_name)
                        if key not in sample_seen:
                            sample_seen.add(key)
                            sample.append((TYPE_TAG_NAME_BY_VALUE.get(tag_value, f"DW_TAG_{tag_value}"), found_name))
                elif found_name and filter_lower in found_name.lower():
                    counts_by_tag_value[tag_value] += 1
                    if sample_limit > 0 and len(sample) < sample_limit:
                        key = (tag_value, found_name)
                        if key not in sample_seen:
                            sample_seen.add(key)
                            sample.append((TYPE_TAG_NAME_BY_VALUE.get(tag_value, f"DW_TAG_{tag_value}"), found_name))

            if has_children:
                if sibling_abs is not None and sibling_abs >= cursor and sibling_abs <= unit_end and (
                    tag_value in SKIP_CHILDREN_TAG_VALUES or tag_value in TYPE_TAG_VALUES
                ):
                    cursor = sibling_abs
                else:
                    depth += 1

    total = sum(counts_by_tag_value.values())
    counts = {
        TYPE_TAG_NAME_BY_VALUE[tag_value]: counts_by_tag_value[tag_value]
        for tag_value in TYPE_TAG_VALUES
        if counts_by_tag_value[tag_value]
    }
    return total, counts, sample


def types_cache_key(filename: str, arch: str | None) -> str:
    st = Path(filename).stat()
    raw = f"{filename}\n{st.st_size}\n{st.st_mtime_ns}\n{arch or ''}\n".encode("utf-8", "replace")
    return hashlib.sha256(raw).hexdigest()[:32]


def types_cache_path(filename: str, arch: str | None) -> Path:
    key = types_cache_key(filename, arch)
    cache_dir = Path.home() / ".cache" / "kstructs"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir / f"types-{key}.json"


def load_types_cache(filename: str, arch: str | None) -> dict | None:
    path = types_cache_path(filename, arch)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except Exception:
        return None

    if not isinstance(payload, dict) or payload.get("version") != 1:
        return None
    if payload.get("filename") != filename or payload.get("arch") != (arch or ""):
        return None

    st = Path(filename).stat()
    if payload.get("size") != st.st_size or payload.get("mtime_ns") != st.st_mtime_ns:
        return None

    return payload


def save_types_cache(filename: str, arch: str | None, total: int, counts: dict[str, int], sample: list[tuple[str, str]]) -> None:
    path = types_cache_path(filename, arch)
    st = Path(filename).stat()
    payload = {
        "version": 1,
        "filename": filename,
        "arch": arch or "",
        "size": st.st_size,
        "mtime_ns": st.st_mtime_ns,
        "total": total,
        "counts": counts,
        "sample": sample,
    }
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=True), encoding="utf-8")
    tmp.replace(path)


def load_types_summary(filename: str, arch: str | None, limit: int) -> tuple[int, dict[str, int], list[tuple[str, str]]] | None:
    cached = load_types_cache(filename, arch)
    if cached is None or not isinstance(cached.get("sample"), list) or len(cached["sample"]) < limit:
        return None
    total = int(cached["total"])
    counts = {str(k): int(v) for k, v in dict(cached["counts"]).items()}
    sample = [(str(tag), str(name)) for tag, name in cached["sample"][:limit]]
    return total, counts, sample


def build_types_summary(
    filename: str,
    arch: str | None,
    dwarfinfo,
    name_filter: str | None,
    limit: int,
) -> tuple[int, dict[str, int], list[tuple[str, str]]]:
    if name_filter is None:
        cache_limit = max(limit, 500)
        total, counts, sample = scan_named_types(dwarfinfo, name_filter=None, sample_limit=cache_limit)
        save_types_cache(filename, arch, total, counts, sample)
        return total, counts, sample[:limit]
    return scan_named_types(dwarfinfo, name_filter=name_filter, sample_limit=limit)
