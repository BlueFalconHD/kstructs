from __future__ import annotations

from typing import Optional

from .dwarf_emit_builder import TypeBuilder
from .dwarf_emit_corrections import CORRECTIONS, apply_corrections
from .dwarf_emit_rename import apply_type_prefix
from .dwarf_emit_render import render_c, render_type
from .dwarf_emit_types import CType, EnumDecl, MemberInfo, StructDecl, TypedefDecl, TypeRegistry
from .dwarf_emit_utils import _resolve_typedef


__all__ = [
    "CType",
    "EnumDecl",
    "MemberInfo",
    "StructDecl",
    "TypedefDecl",
    "TypeRegistry",
    "TypeBuilder",
    "CORRECTIONS",
    "apply_corrections",
    "render_type",
    "render_c",
    "generate_c_for_type",
    "_resolve_typedef",
]


def generate_c_for_type(
    dwarfinfo,
    type_name: str,
    max_depth: int,
    correction_disable: Optional[set[str]] = None,
    correction_verbose: Optional[set[str]] = None,
    dwarf_verbose: Optional[set[str]] = None,
    type_prefix: Optional[str] = None,
) -> str:
    builder = TypeBuilder(dwarfinfo, max_depth=max_depth, verbose=dwarf_verbose)
    root_die = builder.find_root_die(type_name)
    builder.build_from_root(root_die)
    disabled = correction_disable or set()
    apply_corrections(builder.registry, disabled, verbose=correction_verbose)
    if type_prefix:
        apply_type_prefix(builder.registry, type_prefix)
    return render_c(builder.registry)
