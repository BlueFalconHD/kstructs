from __future__ import annotations

from .dwarf_emit_types import CType, StructDecl, TypeRegistry
from .dwarf_emit_utils import _resolve_typedef


def _struct_signature_with(
    registry: TypeRegistry,
    decl: StructDecl,
    type_sig_fn,
    include_member_names: bool,
) -> tuple:
    members = tuple(
        (
            member.name if include_member_names else None,
            type_sig_fn(member.type_ref),
            member.offset,
            member.bit_size,
            member.bit_offset,
        )
        for member in decl.members
    )
    return (decl.kind, decl.size, members)


def _normalized_type_signature(
    registry: TypeRegistry,
    type_ref: CType,
    cache: dict[tuple, tuple],
    stack: set[tuple[str, str]],
    layout_for_named: bool,
    include_member_names: bool,
) -> tuple:
    resolved = _resolve_typedef(registry, type_ref, set())
    if resolved.kind == "named":
        qualifiers = tuple(resolved.qualifiers)
        if resolved.ref_kind in {"struct", "union"} and resolved.name:
            key = (resolved.ref_kind, resolved.name)
            decl = registry.structs.get(key)
            if decl is not None and not decl.opaque and (layout_for_named or decl.name_origin in {"member", "anon"}):
                cache_key = ("layout",) + key + (layout_for_named, include_member_names)
                cached = cache.get(cache_key)
                if cached is not None:
                    return cached
                if key in stack:
                    return ("rec",) + key + (qualifiers,)
                stack.add(key)
                sig = _struct_signature_with(
                    registry,
                    decl,
                    lambda tref: _normalized_type_signature(
                        registry,
                        tref,
                        cache,
                        stack,
                        layout_for_named,
                        include_member_names,
                    ),
                    include_member_names,
                )
                stack.remove(key)
                out = ("layout", resolved.ref_kind, sig, qualifiers)
                cache[cache_key] = out
                return out
        return ("named", resolved.ref_kind, resolved.name, qualifiers)
    if resolved.kind == "pointer":
        target = resolved.target or CType(kind="named", name="void", ref_kind="base")
        return ("ptr", _normalized_type_signature(registry, target, cache, stack, layout_for_named, include_member_names))
    if resolved.kind == "array":
        target = resolved.target or CType(kind="named", name="void", ref_kind="base")
        return (
            "arr",
            resolved.count,
            _normalized_type_signature(registry, target, cache, stack, layout_for_named, include_member_names),
        )
    return ("unknown",)
