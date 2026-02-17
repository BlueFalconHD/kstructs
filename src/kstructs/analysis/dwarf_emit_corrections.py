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


def _apply_xnu_anonymous_union_inline(registry: TypeRegistry, log=None) -> None:
    usage = _count_named_union_refs(registry)
    inlined = 0
    to_remove: set[tuple[str, str]] = set()

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
            to_remove.add(ukey)
            inlined += 1
            if log is not None:
                log(f"inline anonymous union {resolved.name} into {name}.{member.name}")

    for key in to_remove:
        registry.structs.pop(key, None)

    if log is not None and inlined == 0:
        log("no anonymous unions inlined")


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


CORRECTIONS = {
    "xnu-enum-fixed-width": _apply_xnu_enum_fixed_width,
    "xnu-struct-group-name": _apply_xnu_struct_group_name,
    "xnu-list-entry-inline": _apply_xnu_list_entry_inline,
    "xnu-anon-union-inline": _apply_xnu_anonymous_union_inline,
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
