from __future__ import annotations

import sys
from typing import Optional

from .dwarf_emit_signatures import _normalized_type_signature
from .dwarf_emit_types import CType, EnumDecl, StructDecl, TypedefDecl, TypeRegistry
from .dwarf_emit_utils import _clone_type_ref, _is_synthetic_member_name, _resolve_typedef, _sig_digest


def _collect_used_types(registry: TypeRegistry) -> set[tuple[str, str]]:
    used: set[tuple[str, str]] = set()

    def visit(type_ref: CType) -> None:
        resolved = _resolve_typedef(registry, type_ref, set())
        if resolved.kind == "named" and resolved.ref_kind in {"struct", "union", "enum"} and resolved.name:
            used.add((resolved.ref_kind, resolved.name))
            return
        if resolved.kind in {"pointer", "array"} and resolved.target is not None:
            visit(resolved.target)

    for decl in registry.structs.values():
        for member in decl.members:
            visit(member.type_ref)

    for typedef in registry.typedefs.values():
        visit(typedef.target)

    return used


def _prune_unused_synthetic(registry: TypeRegistry, log=None) -> None:
    removed = 0
    while True:
        used = _collect_used_types(registry)
        keep: set[tuple[str, str]] = set()
        for key, decl in registry.structs.items():
            if decl.name_origin not in {"member", "anon"}:
                keep.add(key)
        to_remove = [
            key
            for key, decl in registry.structs.items()
            if key not in used and key not in keep and decl.name_origin in {"member", "anon"}
        ]
        if not to_remove:
            break
        for key in to_remove:
            registry.structs.pop(key, None)
            removed += 1
    if log is not None:
        log(f"pruned {removed} synthetic structs/unions")


def _apply_xnu_struct_group_name(registry: TypeRegistry, log=None) -> None:
    collapse: dict[tuple[str, str], tuple[CType, str]] = {}
    cache: dict[tuple, tuple] = {}

    def log_msg(message: str) -> None:
        if log is not None:
            log(message)

    for key, union_decl in registry.structs.items():
        kind, name = key
        if kind != "union" or union_decl.opaque:
            continue
        if not union_decl.members:
            continue
        if any(member.bit_size is not None for member in union_decl.members):
            log_msg(f"skip union {name}: bitfields present")
            continue

        sigs: list[tuple] = []
        for member in union_decl.members:
            sigs.append(_normalized_type_signature(registry, member.type_ref, cache, set(), True, False))
        if len(set(sigs)) != 1:
            if log is not None:
                details = ", ".join(f"{m.name}:{_sig_digest(s)}" for m, s in zip(union_decl.members, sigs))
                log_msg(f"skip union {name}: member types differ ({details})")
            else:
                log_msg(f"skip union {name}: member types differ")
            continue

        canonical = None
        for member in union_decl.members:
            if not _is_synthetic_member_name(member.name):
                canonical = member
                break
        if canonical is None:
            canonical = union_decl.members[0]
        collapse[key] = (_clone_type_ref(canonical.type_ref), canonical.name)
        log_msg(f"collapse union {name} -> {canonical.name}")

    if not collapse:
        log_msg("no unions collapsed")
        return

    for decl in registry.structs.values():
        for member in decl.members:
            if member.type_ref.kind == "named" and member.type_ref.ref_kind == "union":
                ukey = ("union", member.type_ref.name or "")
                replacement = collapse.get(ukey)
                if replacement is not None:
                    replacement_type, replacement_name = replacement
                    member.type_ref = _clone_type_ref(replacement_type)
                    if _is_synthetic_member_name(member.name) and not _is_synthetic_member_name(replacement_name):
                        member.name = replacement_name

    def rewrite_type_ref(type_ref: CType) -> None:
        if type_ref.kind == "named" and type_ref.ref_kind == "union":
            ukey = ("union", type_ref.name or "")
            replacement = collapse.get(ukey)
            if replacement is not None:
                replacement_type, _ = replacement
                new_ref = _clone_type_ref(replacement_type)
                type_ref.kind = new_ref.kind
                type_ref.name = new_ref.name
                type_ref.ref_kind = new_ref.ref_kind
                type_ref.target = new_ref.target
                type_ref.count = new_ref.count
                type_ref.qualifiers = new_ref.qualifiers
            return
        if type_ref.kind in {"pointer", "array"} and type_ref.target is not None:
            rewrite_type_ref(type_ref.target)

    for decl in registry.structs.values():
        for member in decl.members:
            rewrite_type_ref(member.type_ref)

    for typedef in registry.typedefs.values():
        rewrite_type_ref(typedef.target)

    for key in list(collapse):
        registry.structs.pop(key, None)

    _prune_unused_synthetic(registry, log)


def _pointer_to_named_struct(registry: TypeRegistry, type_ref: CType, depth: int) -> Optional[str]:
    current = _resolve_typedef(registry, type_ref, set())
    for _ in range(depth):
        if current.kind != "pointer" or current.target is None:
            return None
        current = _resolve_typedef(registry, current.target, set())
    if current.kind == "named" and current.ref_kind == "struct" and current.name:
        return current.name
    return None


def _is_list_entry_struct(registry: TypeRegistry, decl: StructDecl) -> Optional[str]:
    if decl.kind != "struct" or decl.opaque:
        return None
    if len(decl.members) != 2:
        return None
    by_name = {member.name: member for member in decl.members}
    if "le_next" not in by_name or "le_prev" not in by_name:
        return None
    target_next = _pointer_to_named_struct(registry, by_name["le_next"].type_ref, 1)
    target_prev = _pointer_to_named_struct(registry, by_name["le_prev"].type_ref, 2)
    if target_next is None or target_prev is None:
        return None
    if target_next != target_prev:
        return None
    return target_next


def _apply_xnu_list_entry_inline(registry: TypeRegistry, log=None) -> None:
    list_structs: dict[str, StructDecl] = {}
    for (kind, name), decl in registry.structs.items():
        if kind != "struct":
            continue
        if _is_list_entry_struct(registry, decl) is None:
            continue
        list_structs[name] = decl
    if not list_structs:
        if log is not None:
            log("no LIST_ENTRY structs found")
        return

    inlined = 0
    for (kind, name), decl in registry.structs.items():
        if decl.opaque:
            continue
        for member in decl.members:
            resolved = _resolve_typedef(registry, member.type_ref, set())
            if resolved.kind != "named" or resolved.ref_kind != "struct" or not resolved.name:
                continue
            inline_decl = list_structs.get(resolved.name)
            if inline_decl is None:
                continue
            registry.inline_members[(kind, name, member.name)] = inline_decl
            inlined += 1
            if log is not None:
                log(f"inline LIST_ENTRY {resolved.name} in {name}.{member.name}")

    if log is not None and inlined == 0:
        log("no LIST_ENTRY usages inlined")


def _count_named_union_refs(registry: TypeRegistry) -> dict[tuple[str, str], int]:
    counts: dict[tuple[str, str], int] = {}

    def visit(type_ref: CType) -> None:
        resolved = _resolve_typedef(registry, type_ref, set())
        if resolved.kind == "named" and resolved.ref_kind == "union" and resolved.name:
            key = ("union", resolved.name)
            counts[key] = counts.get(key, 0) + 1
            return
        if resolved.kind in {"pointer", "array"} and resolved.target is not None:
            visit(resolved.target)

    for decl in registry.structs.values():
        for member in decl.members:
            visit(member.type_ref)

    for typedef in registry.typedefs.values():
        visit(typedef.target)

    return counts


def _count_named_struct_refs(registry: TypeRegistry) -> dict[tuple[str, str], int]:
    counts: dict[tuple[str, str], int] = {}

    def visit(type_ref: CType) -> None:
        resolved = _resolve_typedef(registry, type_ref, set())
        if resolved.kind == "named" and resolved.ref_kind == "struct" and resolved.name:
            key = ("struct", resolved.name)
            counts[key] = counts.get(key, 0) + 1
            return
        if resolved.kind in {"pointer", "array"} and resolved.target is not None:
            visit(resolved.target)

    for decl in registry.structs.values():
        for member in decl.members:
            visit(member.type_ref)

    for typedef in registry.typedefs.values():
        visit(typedef.target)

    return counts


def _apply_xnu_anonymous_union_inline(registry: TypeRegistry, log=None) -> None:
    usage = _count_named_union_refs(registry)
    inlined = 0

    for (kind, name), decl in registry.structs.items():
        if decl.opaque:
            continue
        for member in decl.members:
            if not _is_synthetic_member_name(member.name):
                continue
            resolved = _resolve_typedef(registry, member.type_ref, set())
            if resolved.kind != "named" or resolved.ref_kind != "union" or not resolved.name:
                continue
            ukey = ("union", resolved.name)
            union_decl = registry.structs.get(ukey)
            if union_decl is None or union_decl.opaque:
                if log is not None:
                    log(f"skip union {resolved.name} in {name}.{member.name}: missing decl")
                continue
            if union_decl.name_origin not in {"member", "anon"}:
                if log is not None:
                    log(f"skip union {resolved.name} in {name}.{member.name}: named union")
                continue
            if usage.get(ukey, 0) != 1:
                if log is not None:
                    log(f"skip union {resolved.name} in {name}.{member.name}: used {usage.get(ukey, 0)}x")
                continue

            registry.inline_unions[(kind, name, member.name)] = union_decl
            inlined += 1
            if log is not None:
                log(f"inline anonymous union {resolved.name} into {name}.{member.name}")

    if log is not None and inlined == 0:
        log("no anonymous unions inlined")


def _apply_inline_anonymous_structs(registry: TypeRegistry, log=None) -> None:
    usage = _count_named_struct_refs(registry)
    inlined = 0
    for (kind, name), decl in registry.structs.items():
        if decl.opaque:
            continue
        for member in decl.members:
            if (kind, name, member.name) in registry.inline_members:
                continue
            if (kind, name, member.name) in registry.inline_unions:
                continue
            resolved = _resolve_typedef(registry, member.type_ref, set())
            if resolved.kind != "named" or resolved.ref_kind != "struct" or not resolved.name:
                continue
            skey = ("struct", resolved.name)
            struct_decl = registry.structs.get(skey)
            if struct_decl is None or struct_decl.opaque:
                if log is not None:
                    log(f"skip struct {resolved.name} in {name}.{member.name}: missing decl")
                continue
            if struct_decl.name_origin not in {"anon", "member"}:
                if log is not None:
                    log(f"skip struct {resolved.name} in {name}.{member.name}: named struct")
                continue
            if usage.get(skey, 0) != 1:
                if log is not None:
                    log(f"skip struct {resolved.name} in {name}.{member.name}: used {usage.get(skey, 0)}x")
                continue
            registry.inline_members[(kind, name, member.name)] = struct_decl
            inlined += 1
            if log is not None:
                log(f"inline anonymous struct {resolved.name} into {name}.{member.name}")

    if log is not None and inlined == 0:
        log("no anonymous structs inlined")


def _enum_fixed_width_type(enum_decl: EnumDecl) -> Optional[CType]:
    if enum_decl.size is None:
        return None
    size = enum_decl.size
    if size <= 0:
        return None
    signed = any(value < 0 for _, value in enum_decl.enumerators)
    if size == 1:
        name = "int8_t" if signed else "uint8_t"
    elif size == 2:
        name = "int16_t" if signed else "uint16_t"
    elif size == 4:
        name = "int32_t" if signed else "uint32_t"
    elif size == 8:
        name = "int64_t" if signed else "uint64_t"
    else:
        return None
    return CType(kind="named", name=name, ref_kind="base")


def _apply_xnu_enum_fixed_width(registry: TypeRegistry, log=None) -> None:
    adjusted = 0
    for enum_decl in registry.enums.values():
        if enum_decl.opaque:
            continue
        if enum_decl.underlying is not None:
            base_ref = CType(kind="named", name=enum_decl.underlying, ref_kind="base")
        else:
            base_ref = _enum_fixed_width_type(enum_decl)
        if base_ref is None:
            continue
        if enum_decl.underlying is None:
            if enum_decl.size is None or enum_decl.size >= 4:
                continue
        enum_decl.typedef_as = base_ref.name
        # Rewrite typedefs that target this enum to use the fixed-width type.
        for typedef in registry.typedefs.values():
            resolved = _resolve_typedef(registry, typedef.target, set())
            if resolved.kind == "named" and resolved.ref_kind == "enum" and resolved.name == enum_decl.name:
                typedef.target = CType(kind="named", name=base_ref.name, ref_kind="base")
        if enum_decl.name not in registry.typedefs:
            registry.typedefs[enum_decl.name] = TypedefDecl(
                name=enum_decl.name,
                target=CType(kind="named", name=base_ref.name, ref_kind="base"),
            )
        adjusted += 1
        if log is not None:
            log(f"enum {enum_decl.name} size {enum_decl.size} -> typedef {base_ref.name}")

    if log is not None and adjusted == 0:
        log("no enums adjusted")


_BASE_SIZE_HINTS: dict[str, int] = {
    "_Bool": 1,
    "bool": 1,
    "char": 1,
    "signed char": 1,
    "unsigned char": 1,
    "int8_t": 1,
    "uint8_t": 1,
    "short": 2,
    "short int": 2,
    "signed short": 2,
    "signed short int": 2,
    "unsigned short": 2,
    "unsigned short int": 2,
    "int16_t": 2,
    "uint16_t": 2,
    "int": 4,
    "signed": 4,
    "signed int": 4,
    "unsigned": 4,
    "unsigned int": 4,
    "int32_t": 4,
    "uint32_t": 4,
    "long long": 8,
    "long long int": 8,
    "signed long long": 8,
    "signed long long int": 8,
    "unsigned long long": 8,
    "unsigned long long int": 8,
    "int64_t": 8,
    "uint64_t": 8,
    "float": 4,
    "double": 8,
    "long double": 16,
    "__int128": 16,
    "unsigned __int128": 16,
}


def _base_size(registry: TypeRegistry, name: str) -> Optional[int]:
    if name in registry.base_sizes:
        return registry.base_sizes[name]
    if name in {
        "long",
        "long int",
        "signed long",
        "signed long int",
        "unsigned long",
        "unsigned long int",
        "size_t",
        "uintptr_t",
        "intptr_t",
        "ptrdiff_t",
    }:
        if registry.pointer_size:
            return registry.pointer_size
    return _BASE_SIZE_HINTS.get(name)


def _type_size(registry: TypeRegistry, type_ref: CType) -> Optional[int]:
    resolved = _resolve_typedef(registry, type_ref, set())
    if resolved.kind == "named":
        name = resolved.name or ""
        if resolved.ref_kind == "base":
            return _base_size(registry, name)
        if resolved.ref_kind == "enum":
            enum_decl = registry.enums.get(name)
            if enum_decl is None:
                return None
            if enum_decl.underlying is not None:
                return _base_size(registry, enum_decl.underlying)
            return enum_decl.size
        if resolved.ref_kind in {"struct", "union"}:
            decl = registry.structs.get((resolved.ref_kind, name))
            if decl is None:
                return None
            return decl.size
        return None
    if resolved.kind == "pointer":
        return registry.pointer_size or 8
    if resolved.kind == "array":
        if resolved.target is None:
            return None
        elem_size = _type_size(registry, resolved.target)
        if elem_size is None:
            return None
        if resolved.count is None:
            return None
        return elem_size * resolved.count
    return None


def _type_alignment(registry: TypeRegistry, type_ref: CType, seen: Optional[set[tuple[str, str]]] = None) -> Optional[int]:
    resolved = _resolve_typedef(registry, type_ref, set())
    if resolved.kind == "named":
        name = resolved.name or ""
        if resolved.ref_kind == "base":
            return _base_size(registry, name)
        if resolved.ref_kind == "enum":
            enum_decl = registry.enums.get(name)
            if enum_decl is None:
                return None
            if enum_decl.underlying is not None:
                return _base_size(registry, enum_decl.underlying)
            return enum_decl.size
        if resolved.ref_kind in {"struct", "union"}:
            decl = registry.structs.get((resolved.ref_kind, name))
            if decl is None:
                return None
            if decl.packed:
                return 1
            if seen is None:
                seen = set()
            key = (resolved.ref_kind, name)
            if key in seen:
                return None
            seen.add(key)
            max_align = 1
            for member in decl.members:
                if member.bit_size is not None:
                    continue
                align = _type_alignment(registry, member.type_ref, seen)
                if align is None:
                    continue
                max_align = max(max_align, align)
            seen.remove(key)
            return max_align
        return None
    if resolved.kind == "pointer":
        return registry.pointer_size or 8
    if resolved.kind == "array":
        if resolved.target is None:
            return None
        return _type_alignment(registry, resolved.target, seen)
    return None


def _align_up(value: int, align: int) -> int:
    if align <= 1:
        return value
    return (value + align - 1) // align * align


def _max_member_alignment(registry: TypeRegistry, decl: StructDecl) -> tuple[Optional[int], list[str]]:
    max_align: Optional[int] = None
    unknown: list[str] = []
    for member in decl.members:
        if member.bit_size is not None:
            continue
        align = _type_alignment(registry, member.type_ref)
        if member.alignment is not None:
            if align is None:
                align = member.alignment
            else:
                align = max(align, member.alignment)
        if align is None:
            unknown.append(member.name)
            continue
        if max_align is None or align > max_align:
            max_align = align
    return max_align, unknown


def _struct_layout_matches(registry: TypeRegistry, decl: StructDecl, *, packed: bool) -> tuple[bool, Optional[int]]:
    offset = 0
    max_align = 1
    for member in decl.members:
        if member.bit_size is not None:
            return False, None
        size = _type_size(registry, member.type_ref)
        align = _type_alignment(registry, member.type_ref)
        if size is None or align is None:
            return False, None
        if packed:
            align = 1
        max_align = max(max_align, align)
        offset = _align_up(offset, align)
        if member.offset is not None and offset != member.offset:
            return False, None
        offset += size
    struct_align = 1 if packed else max_align
    size = _align_up(offset, struct_align)
    return True, size


def _apply_infer_packed_structs(registry: TypeRegistry, log=None) -> None:
    changed = False
    for decl in registry.structs.values():
        if decl.opaque or decl.packed:
            continue
        if decl.kind != "struct":
            continue
        if decl.size is None:
            continue
        if any(member.bit_size is not None for member in decl.members):
            continue
        ok, size = _struct_layout_matches(registry, decl, packed=False)
        if log is not None:
            if ok and size is not None:
                log(f"struct {decl.name}: natural size 0x{size:x} (dwarf 0x{decl.size:x})")
            else:
                log(f"struct {decl.name}: natural layout unresolved (dwarf 0x{decl.size:x})")
        if ok and size == decl.size:
            continue
        ok_packed, size_packed = _struct_layout_matches(registry, decl, packed=True)
        if log is not None:
            if ok_packed and size_packed is not None:
                log(f"struct {decl.name}: packed size 0x{size_packed:x} (dwarf 0x{decl.size:x})")
            else:
                log(f"struct {decl.name}: packed layout unresolved (dwarf 0x{decl.size:x})")
        if ok_packed and size_packed == decl.size:
            decl.packed = True
            changed = True
            if log is not None:
                log(f"pack struct {decl.name}")
            continue
        max_align, unknown = _max_member_alignment(registry, decl)
        if log is not None:
            if max_align is not None:
                log(f"struct {decl.name}: max member alignment {max_align}")
            if unknown:
                log(f"struct {decl.name}: missing alignment for {', '.join(unknown)}")
        if max_align is not None and max_align > 1 and decl.size % max_align != 0:
            decl.packed = True
            changed = True
            if log is not None:
                log(f"pack struct {decl.name}: size 0x{decl.size:x} not multiple of align {max_align}")
    if log is not None and not changed:
        log("no packed structs inferred")


CORRECTIONS = {
    "xnu-enum-fixed-width": _apply_xnu_enum_fixed_width,
    "xnu-struct-group-name": _apply_xnu_struct_group_name,
    "xnu-list-entry-inline": _apply_xnu_list_entry_inline,
    "xnu-anon-union-inline": _apply_xnu_anonymous_union_inline,
    "inline-anon-structs": _apply_inline_anonymous_structs,
    "infer-packed-structs": _apply_infer_packed_structs,
}


def apply_corrections(
    registry: TypeRegistry,
    disabled: set[str],
    verbose: Optional[set[str]] = None,
) -> None:
    for name, func in CORRECTIONS.items():
        if name in disabled:
            continue
        log = None
        if verbose and (name in verbose or "all" in verbose):
            def _log(msg: str, *, _name: str = name) -> None:
                print(f"[kstructs:{_name}] {msg}", file=sys.stderr)
            log = _log
        func(registry, log)
