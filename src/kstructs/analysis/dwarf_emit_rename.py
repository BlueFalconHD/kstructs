from __future__ import annotations

from .dwarf_emit_types import CType, TypeRegistry
from .dwarf_emit_utils import _sanitize_identifier


def apply_type_prefix(registry: TypeRegistry, prefix: str) -> None:
    """Prefix all emitted struct/union/enum tags and typedef names.

    This avoids collisions when generated definitions are included alongside
    existing headers that define the same identifiers.
    """

    prefix = _sanitize_identifier(prefix.strip())
    if not prefix:
        return

    renames: dict[tuple[str, str], str] = {}

    # Most types come from the main registries, but some anonymous unions may be
    # removed from `registry.structs` when inlined while still being referenced
    # by `inline_members` / `inline_unions` lookups during rendering.
    for kind, name in registry.structs:
        renames[(kind, name)] = f"{prefix}{name}"
    for name in registry.enums:
        renames[("enum", name)] = f"{prefix}{name}"
    for name in registry.typedefs:
        renames[("typedef", name)] = f"{prefix}{name}"

    for kind, name, _ in registry.inline_members:
        renames.setdefault((kind, name), f"{prefix}{name}")
    for kind, name, _ in registry.inline_unions:
        renames.setdefault((kind, name), f"{prefix}{name}")
    for decl in registry.inline_members.values():
        renames.setdefault((decl.kind, decl.name), f"{prefix}{decl.name}")
    for decl in registry.inline_unions.values():
        renames.setdefault((decl.kind, decl.name), f"{prefix}{decl.name}")

    def rewrite_type_ref(type_ref: CType) -> None:
        if type_ref.kind == "named":
            if type_ref.ref_kind in {"struct", "union", "enum", "typedef"} and type_ref.name:
                type_ref.name = renames.get((type_ref.ref_kind, type_ref.name), type_ref.name)
            return
        if type_ref.kind in {"pointer", "array"} and type_ref.target is not None:
            rewrite_type_ref(type_ref.target)

    for decl in registry.structs.values():
        for member in decl.members:
            rewrite_type_ref(member.type_ref)
    for decl in registry.inline_members.values():
        for member in decl.members:
            rewrite_type_ref(member.type_ref)
    for decl in registry.inline_unions.values():
        for member in decl.members:
            rewrite_type_ref(member.type_ref)
    for typedef in registry.typedefs.values():
        rewrite_type_ref(typedef.target)

    registry.structs = {
        (kind, renames[(kind, name)]): decl
        for (kind, name), decl in registry.structs.items()
    }
    for (kind, name), decl in registry.structs.items():
        decl.name = name

    for decl in registry.inline_members.values():
        decl.name = renames.get((decl.kind, decl.name), decl.name)
    for decl in registry.inline_unions.values():
        decl.name = renames.get((decl.kind, decl.name), decl.name)

    registry.enums = {
        renames[("enum", name)]: enum_decl
        for name, enum_decl in registry.enums.items()
    }
    for name, enum_decl in registry.enums.items():
        enum_decl.name = name

    registry.typedefs = {
        renames[("typedef", name)]: typedef
        for name, typedef in registry.typedefs.items()
    }
    for name, typedef in registry.typedefs.items():
        typedef.name = name

    registry.inline_members = {
        (kind, renames.get((kind, name), f"{prefix}{name}"), member): decl
        for (kind, name, member), decl in registry.inline_members.items()
    }
    registry.inline_unions = {
        (kind, renames.get((kind, name), f"{prefix}{name}"), member): decl
        for (kind, name, member), decl in registry.inline_unions.items()
    }
