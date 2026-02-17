from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CType:
    kind: str
    name: Optional[str] = None
    ref_kind: Optional[str] = None
    target: Optional["CType"] = None
    count: Optional[int] = None
    qualifiers: list[str] = field(default_factory=list)

    def needs_parens(self) -> bool:
        return self.kind == "array"


@dataclass
class MemberInfo:
    name: str
    type_ref: CType
    offset: Optional[int]
    bit_size: Optional[int]
    bit_offset: Optional[int]
    alignment: Optional[int] = None


@dataclass
class StructDecl:
    kind: str
    name: str
    size: Optional[int]
    members: list[MemberInfo]
    opaque: bool = False
    name_origin: str = "dwarf"


@dataclass
class EnumDecl:
    name: str
    size: Optional[int]
    enumerators: list[tuple[str, int]]
    opaque: bool = False
    typedef_as: Optional[str] = None
    underlying: Optional[str] = None


@dataclass
class TypedefDecl:
    name: str
    target: CType


@dataclass
class TypeRegistry:
    structs: dict[tuple[str, str], StructDecl] = field(default_factory=dict)
    enums: dict[str, EnumDecl] = field(default_factory=dict)
    typedefs: dict[str, TypedefDecl] = field(default_factory=dict)
    inline_members: dict[tuple[str, str, str], StructDecl] = field(default_factory=dict)
    inline_unions: dict[tuple[str, str, str], StructDecl] = field(default_factory=dict)
