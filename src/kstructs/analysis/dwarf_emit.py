from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from typing import Optional
import sys

from elftools.dwarf.dwarf_expr import DWARFExprParser
try:
    from elftools.dwarf.descriptions import describe_DW_TAG as _describe_DW_TAG
except ImportError:
    try:
        from elftools.dwarf.descriptions import describe_DWARF_tag as _describe_DW_TAG
    except ImportError:  # pragma: no cover - older pyelftools
        _describe_DW_TAG = None


STRUCT_TAGS = {
    "DW_TAG_structure_type",
    "DW_TAG_union_type",
    "DW_TAG_class_type",
}
ENUM_TAG = "DW_TAG_enumeration_type"
TYPEDEF_TAG = "DW_TAG_typedef"
BASE_TAG = "DW_TAG_base_type"
POINTER_TAG = "DW_TAG_pointer_type"
REFERENCE_TAG = "DW_TAG_reference_type"
RV_REFERENCE_TAG = "DW_TAG_rvalue_reference_type"
ARRAY_TAG = "DW_TAG_array_type"
CONST_TAG = "DW_TAG_const_type"
VOLATILE_TAG = "DW_TAG_volatile_type"
RESTRICT_TAG = "DW_TAG_restrict_type"
ATOMIC_TAG = "DW_TAG_atomic_type"
UNSPEC_TAG = "DW_TAG_unspecified_type"
SUBROUTINE_TAG = "DW_TAG_subroutine_type"

INDEX_TAGS = STRUCT_TAGS | {ENUM_TAG, TYPEDEF_TAG, BASE_TAG}


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


def _decode_attr(value) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    if isinstance(value, str):
        return value
    return str(value)


def _attr_int(attr) -> Optional[int]:
    if attr is None:
        return None
    value = attr.value
    if isinstance(value, int):
        return value
    return None


def _sanitize_identifier(name: str) -> str:
    if not name:
        return name
    cleaned = []
    for ch in name:
        if ch.isalnum() or ch == "_":
            cleaned.append(ch)
        else:
            cleaned.append("_")
    out = "".join(cleaned)
    if out[0].isdigit():
        out = "_" + out
    return out


class TypeBuilder:
    def __init__(self, dwarfinfo, max_depth: int, verbose: Optional[set[str]] = None) -> None:
        self.dwarfinfo = dwarfinfo
        self.max_depth = max_depth
        self._verbose = verbose or set()
        self.registry = TypeRegistry()
        self.expr_parser = DWARFExprParser(dwarfinfo.structs)
        self._best_by_name_tag, self._name_index = self._build_type_index()
        self._anon_type_counter = 0
        self._expanding: set[tuple[str, str]] = set()
        self._anon_name_overrides: dict[int, tuple[str, str]] = {}
        self._name_owner: dict[tuple[str, str], int] = {}

    def _log_null_member(self, struct_name: str, member_name: str, message: str) -> None:
        if "null-members" in self._verbose or "all" in self._verbose:
            print(f"[kstructs:dwarf-null-members] {struct_name}.{member_name}: {message}", file=sys.stderr)

    def _tag_name(self, tag) -> str:
        if isinstance(tag, str):
            return tag
        if isinstance(tag, int):
            try:
                if _describe_DW_TAG is not None:
                    return _describe_DW_TAG(tag)
            except Exception:
                return f"0x{tag:x}"
            return f"0x{tag:x}"
        return str(tag)

    def _die_debug_detail(self, die) -> str:
        parts: list[str] = []
        try:
            parts.append(f"tag={self._tag_name(die.tag)}")
        except Exception:
            parts.append("tag=?")
        offset = getattr(die, "offset", None)
        if isinstance(offset, int):
            parts.append(f"offset=0x{offset:x}")
        name_attr = die.attributes.get("DW_AT_name")
        if name_attr is not None:
            parts.append(f"name={_decode_attr(name_attr.value)}")
        type_attr = die.attributes.get("DW_AT_type")
        if type_attr is not None:
            value = type_attr.value
            if isinstance(value, int):
                parts.append(f"type.form={type_attr.form} value=0x{value:x}")
            else:
                parts.append(f"type.form={type_attr.form} value={value}")
        size_attr = die.attributes.get("DW_AT_byte_size")
        if size_attr is not None:
            parts.append(f"byte_size={size_attr.value}")
        return ", ".join(parts)

    def _null_member_reason(self, die) -> str:
        tag = die.tag
        tag_name = self._tag_name(tag)
        if tag in {UNSPEC_TAG, SUBROUTINE_TAG}:
            return tag_name
        if tag in {POINTER_TAG, REFERENCE_TAG, RV_REFERENCE_TAG} and "DW_AT_type" not in die.attributes:
            return f"{tag_name} missing DW_AT_type"
        if tag in {CONST_TAG, VOLATILE_TAG, RESTRICT_TAG, ATOMIC_TAG} and "DW_AT_type" not in die.attributes:
            return f"{tag_name} missing DW_AT_type"
        if tag == BASE_TAG and (self._die_name(die) in {None, "", "void"}):
            return "base type void"
        if tag == TYPEDEF_TAG and self._die_name(die) is None and "DW_AT_type" not in die.attributes:
            return "typedef missing name and DW_AT_type"
        return f"{tag_name} resolved to void"

    def _build_type_index(self):
        best_by_name_tag: dict[tuple[str, str], object] = {}
        name_index: dict[str, list[object]] = {}

        def score(die) -> int:
            score_value = 0
            decl = die.attributes.get("DW_AT_declaration")
            if decl is not None and decl.value:
                score_value -= 5
            else:
                score_value += 5
            if "DW_AT_byte_size" in die.attributes:
                score_value += 2
            if die.has_children:
                score_value += 1
            return score_value

        for cu in self.dwarfinfo.iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag not in INDEX_TAGS:
                    continue
                name_attr = die.attributes.get("DW_AT_name")
                if name_attr is None:
                    continue
                name = _decode_attr(name_attr.value)
                if not name:
                    continue
                name_index.setdefault(name, []).append(die)
                key = (name, die.tag)
                current = best_by_name_tag.get(key)
                if current is None or score(die) > score(current):
                    best_by_name_tag[key] = die

        return best_by_name_tag, name_index

    def _canonical_die(self, die):
        name = self._die_name(die)
        if not name:
            return die
        if die.tag in STRUCT_TAGS | {ENUM_TAG}:
            key = (name, die.tag)
            return self._best_by_name_tag.get(key, die)
        return die

    def _die_name(self, die) -> Optional[str]:
        attr = die.attributes.get("DW_AT_name")
        if attr is None:
            return None
        name = _decode_attr(attr.value)
        if not name:
            return None
        return name

    def _anon_type_name(self, kind: str) -> str:
        self._anon_type_counter += 1
        return f"__anon_{kind}_{self._anon_type_counter}"

    def _assign_name(self, kind: str, base: str, die) -> str:
        base = _sanitize_identifier(base)
        if not base:
            base = self._anon_type_name(kind)
        key = (kind, base)
        owner = self._name_owner.get(key)
        if owner is None or owner == die.offset:
            self._name_owner[key] = die.offset
            return base
        idx = 2
        while True:
            candidate = f"{base}_{idx}"
            key = (kind, candidate)
            owner = self._name_owner.get(key)
            if owner is None or owner == die.offset:
                self._name_owner[key] = die.offset
                return candidate
            idx += 1

    def find_root_die(self, type_name: str):
        name = type_name.strip()
        for prefix in ("struct ", "union ", "enum ", "class "):
            if name.startswith(prefix):
                name = name[len(prefix):].strip()
                break
        candidates = self._name_index.get(name)
        if not candidates:
            raise ValueError(f"Type '{type_name}' not found in DWARF.")

        if name.endswith("_t"):
            typedefs = [die for die in candidates if die.tag == TYPEDEF_TAG]
            if typedefs:
                return self._best_by_name_tag.get((name, TYPEDEF_TAG), typedefs[0])

        for preferred in ("DW_TAG_structure_type", "DW_TAG_class_type", "DW_TAG_union_type", ENUM_TAG, TYPEDEF_TAG, BASE_TAG):
            for die in candidates:
                if die.tag == preferred:
                    key = (name, preferred)
                    return self._best_by_name_tag.get(key, die)

        return candidates[0]

    def build_from_root(self, root_die) -> CType:
        return self.build_type_ref(root_die, depth=0)

    def build_type_ref(self, die, depth: int, suggested_name: Optional[str] = None) -> CType:
        if die is None:
            return CType(kind="named", name="void", ref_kind="base")

        die = self._canonical_die(die)
        tag = die.tag

        if tag == TYPEDEF_TAG:
            name = self._die_name(die)
            if not name:
                target_die = die.get_DIE_from_attribute("DW_AT_type") if "DW_AT_type" in die.attributes else None
                return self.build_type_ref(target_die, depth, suggested_name=None)
            if name not in self.registry.typedefs:
                target_die = die.get_DIE_from_attribute("DW_AT_type") if "DW_AT_type" in die.attributes else None
                if target_die is not None and target_die.tag in STRUCT_TAGS | {ENUM_TAG}:
                    if self._die_name(target_die) is None:
                        self._anon_name_overrides[target_die.offset] = (name, "typedef")
                if target_die is None:
                    target_ref = CType(kind="named", name="void", ref_kind="base")
                else:
                    target_ref = self.build_type_ref(target_die, depth, suggested_name=None)
                self.registry.typedefs[name] = TypedefDecl(name=name, target=target_ref)
            return CType(kind="named", name=name, ref_kind="typedef")

        if tag in STRUCT_TAGS:
            return self._build_struct_union(die, depth, suggested_name=suggested_name)

        if tag == ENUM_TAG:
            return self._build_enum(die, depth, suggested_name=suggested_name)

        if tag == BASE_TAG:
            name = self._die_name(die) or "uint8_t"
            return CType(kind="named", name=name, ref_kind="base")

        if tag in {POINTER_TAG, REFERENCE_TAG, RV_REFERENCE_TAG}:
            if "DW_AT_type" in die.attributes:
                target = die.get_DIE_from_attribute("DW_AT_type")
                target_ref = self.build_type_ref(target, depth + 1, suggested_name=None)
            else:
                target_ref = CType(kind="named", name="void", ref_kind="base")
            return CType(kind="pointer", target=target_ref)

        if tag == ARRAY_TAG:
            return self._build_array(die, depth, suggested_name=suggested_name)

        if tag in {CONST_TAG, VOLATILE_TAG, RESTRICT_TAG, ATOMIC_TAG}:
            if "DW_AT_type" in die.attributes:
                target = die.get_DIE_from_attribute("DW_AT_type")
                target_ref = self.build_type_ref(target, depth, suggested_name=suggested_name)
            else:
                target_ref = CType(kind="named", name="void", ref_kind="base")
            qualifier = {
                CONST_TAG: "const",
                VOLATILE_TAG: "volatile",
                RESTRICT_TAG: "restrict",
                ATOMIC_TAG: "_Atomic",
            }[tag]
            return self._apply_qualifier(target_ref, qualifier)

        if "DW_AT_type" in die.attributes:
            # Vendor-specific wrapper types (e.g. ptrauth) should behave like transparent
            # typedefs/qualifiers. Follow the DW_AT_type chain rather than falling back to void.
            target = die.get_DIE_from_attribute("DW_AT_type")
            if target is not None and target is not die:
                return self.build_type_ref(target, depth, suggested_name=None)

        if tag in {UNSPEC_TAG, SUBROUTINE_TAG}:
            return CType(kind="named", name="void", ref_kind="base")

        name = self._die_name(die)
        if name:
            if name not in self.registry.typedefs:
                size = _attr_int(die.attributes.get("DW_AT_byte_size")) or 1
                opaque = self._opaque_type_for_size(size)
                self.registry.typedefs[name] = TypedefDecl(name=name, target=opaque)
            return CType(kind="named", name=name, ref_kind="typedef")

        return CType(kind="named", name="void", ref_kind="base")

    def _apply_qualifier(self, type_ref: CType, qualifier: str) -> CType:
        if type_ref.kind == "named":
            if qualifier not in type_ref.qualifiers:
                type_ref.qualifiers.insert(0, qualifier)
            return type_ref
        if qualifier == "_Atomic" and type_ref.kind == "pointer":
            if qualifier not in type_ref.qualifiers:
                type_ref.qualifiers.insert(0, qualifier)
            return type_ref
        if type_ref.kind in {"pointer", "array"} and type_ref.target is not None:
            type_ref.target = self._apply_qualifier(type_ref.target, qualifier)
        return type_ref

    def _build_array(self, die, depth: int, suggested_name: Optional[str]) -> CType:
        element_die = die.get_DIE_from_attribute("DW_AT_type") if "DW_AT_type" in die.attributes else None
        if element_die is None:
            element_ref = CType(kind="named", name="uint8_t", ref_kind="base")
        else:
            element_ref = self.build_type_ref(element_die, depth, suggested_name=suggested_name)
        counts: list[Optional[int]] = []
        for child in die.iter_children():
            if child.tag != "DW_TAG_subrange_type":
                continue
            count = _attr_int(child.attributes.get("DW_AT_count"))
            if count is None:
                upper = _attr_int(child.attributes.get("DW_AT_upper_bound"))
                if upper is not None:
                    if upper < 0:
                        count = None
                    else:
                        count = upper + 1
            counts.append(count)
        if not counts:
            return CType(kind="array", target=element_ref, count=None)
        current = element_ref
        for count in reversed(counts):
            current = CType(kind="array", target=current, count=count)
        return current

    def _build_struct_union(self, die, depth: int, suggested_name: Optional[str]) -> CType:
        kind = "struct"
        if die.tag == "DW_TAG_union_type":
            kind = "union"
        name_origin = "dwarf"
        name = self._die_name(die)
        if not name:
            override = self._anon_name_overrides.get(die.offset)
            if override:
                name, name_origin = override
            elif suggested_name:
                name = suggested_name
                name_origin = "member"
            else:
                name = self._anon_type_name(kind)
                name_origin = "anon"
        name = self._assign_name(kind, name, die)
        key = (kind, name)

        if key in self._expanding:
            return CType(kind="named", name=name, ref_kind=kind)

        existing = self.registry.structs.get(key)
        if existing is not None and (not existing.opaque or depth > self.max_depth):
            return CType(kind="named", name=name, ref_kind=kind)

        size = _attr_int(die.attributes.get("DW_AT_byte_size"))
        if depth > self.max_depth:
            self.registry.structs[key] = StructDecl(
                kind=kind,
                name=name,
                size=size,
                members=[],
                opaque=True,
                name_origin=name_origin,
            )
            return CType(kind="named", name=name, ref_kind=kind)

        self._expanding.add(key)
        decl = StructDecl(
            kind=kind,
            name=name,
            size=size,
            members=[],
            opaque=False,
            name_origin=name_origin,
        )
        self.registry.structs[key] = decl

        member_names: dict[str, int] = {}
        for child in die.iter_children():
            if child.tag != "DW_TAG_member":
                continue
            if _attr_int(child.attributes.get("DW_AT_artificial")):
                continue
            raw_name = self._die_name(child)
            if not raw_name:
                raw_name = self._anon_type_name("member")
            raw_name = _sanitize_identifier(raw_name)
            count = member_names.get(raw_name, 0)
            member_names[raw_name] = count + 1
            if count:
                raw_name = f"{raw_name}_{count}"

            member_type_die = child.get_DIE_from_attribute("DW_AT_type") if "DW_AT_type" in child.attributes else None
            if member_type_die is None:
                member_size = _attr_int(child.attributes.get("DW_AT_byte_size")) or 1
                self._log_null_member(
                    name,
                    raw_name,
                    f"missing DW_AT_type, using opaque size {member_size} bytes",
                )
                member_type_ref = self._opaque_type_for_size(member_size)
            else:
                suggested = None
                if member_type_die.tag in STRUCT_TAGS | {ENUM_TAG}:
                    if self._die_name(member_type_die) is None:
                        suggested = f"{name}_{raw_name}"
                member_type_ref = self.build_type_ref(member_type_die, depth, suggested_name=suggested)
                member_size = _attr_int(child.attributes.get("DW_AT_byte_size"))
                if member_size is not None and self._is_void_type(member_type_ref):
                    self._log_null_member(
                        name,
                        raw_name,
                        f"type resolved to void ({self._null_member_reason(member_type_die)}); "
                        f"using opaque size {member_size} bytes; {self._die_debug_detail(member_type_die)}",
                    )
                    member_type_ref = self._opaque_type_for_size(member_size)
                elif self._is_void_type(member_type_ref):
                    reason = self._null_member_reason(member_type_die)
                    size_hint = _attr_int(child.attributes.get("DW_AT_byte_size"))
                    if size_hint is None:
                        self._log_null_member(
                            name,
                            raw_name,
                            f"type resolved to void ({reason}); no DW_AT_byte_size available, "
                            f"leaving as void; {self._die_debug_detail(member_type_die)}",
                        )
                    else:
                        self._log_null_member(
                            name,
                            raw_name,
                            f"type resolved to void ({reason}); DW_AT_byte_size={size_hint} but not applied; "
                            f"{self._die_debug_detail(member_type_die)}",
                        )
            offset = self._member_offset(child, kind)
            bit_size = _attr_int(child.attributes.get("DW_AT_bit_size"))
            bit_offset = _attr_int(child.attributes.get("DW_AT_data_bit_offset"))
            if bit_offset is None:
                bit_offset = _attr_int(child.attributes.get("DW_AT_bit_offset"))

            decl.members.append(
                MemberInfo(
                    name=raw_name,
                    type_ref=member_type_ref,
                    offset=offset,
                    bit_size=bit_size,
                    bit_offset=bit_offset,
                )
            )

        self._expanding.remove(key)
        return CType(kind="named", name=name, ref_kind=kind)

    def _build_enum(self, die, depth: int, suggested_name: Optional[str]) -> CType:
        name = self._die_name(die)
        if not name:
            override = self._anon_name_overrides.get(die.offset)
            if override:
                name, _ = override
            elif suggested_name:
                name = suggested_name
            else:
                name = self._anon_type_name("enum")
        name = self._assign_name("enum", name, die)

        existing = self.registry.enums.get(name)
        if existing is not None and (not existing.opaque or depth > self.max_depth):
            return CType(kind="named", name=name, ref_kind="enum")

        size = _attr_int(die.attributes.get("DW_AT_byte_size"))
        underlying: Optional[str] = None
        if "DW_AT_type" in die.attributes:
            target = die.get_DIE_from_attribute("DW_AT_type")
            if target is not None:
                target_ref = self.build_type_ref(target, depth, suggested_name=None)
                resolved = _resolve_typedef(self.registry, target_ref, set())
                if resolved.kind == "named" and resolved.ref_kind == "base" and resolved.name:
                    underlying = resolved.name
        if depth > self.max_depth:
            self.registry.enums[name] = EnumDecl(
                name=name,
                size=size,
                enumerators=[],
                opaque=True,
                underlying=underlying,
            )
            return CType(kind="named", name=name, ref_kind="enum")

        enumerators: list[tuple[str, int]] = []
        for child in die.iter_children():
            if child.tag != "DW_TAG_enumerator":
                continue
            enum_name = self._die_name(child) or self._anon_type_name("enum_value")
            enum_name = _sanitize_identifier(enum_name)
            value_attr = child.attributes.get("DW_AT_const_value")
            if value_attr is None:
                value = 0
            else:
                value = value_attr.value
                if isinstance(value, bytes):
                    value = int.from_bytes(value, "little", signed=False)
            if not isinstance(value, int):
                value = int(value)
            enumerators.append((enum_name, value))

        self.registry.enums[name] = EnumDecl(
            name=name,
            size=size,
            enumerators=enumerators,
            opaque=False,
            underlying=underlying,
        )
        return CType(kind="named", name=name, ref_kind="enum")

    def _is_void_type(self, type_ref: CType) -> bool:
        resolved = _resolve_typedef(self.registry, type_ref, set())
        return resolved.kind == "named" and (resolved.name or "") == "void"

    def _opaque_type_for_size(self, size: int) -> CType:
        if size == 1:
            return CType(kind="named", name="uint8_t", ref_kind="base")
        if size == 2:
            return CType(kind="named", name="uint16_t", ref_kind="base")
        if size == 4:
            return CType(kind="named", name="uint32_t", ref_kind="base")
        if size == 8:
            return CType(kind="named", name="uint64_t", ref_kind="base")
        if size == 16:
            return CType(kind="named", name="unsigned __int128", ref_kind="base")
        return CType(kind="array", target=CType(kind="named", name="uint8_t", ref_kind="base"), count=size)

    def _member_offset(self, member_die, parent_kind: str) -> Optional[int]:
        attr = member_die.attributes.get("DW_AT_data_member_location")
        if attr is None:
            if parent_kind == "union":
                return 0
            return None
        value = attr.value
        if isinstance(value, int):
            return value
        if isinstance(value, bytes):
            ops = self.expr_parser.parse_expr(value)
            if len(ops) == 1 and ops[0].op_name in {"DW_OP_plus_uconst", "DW_OP_constu", "DW_OP_consts"}:
                return int(ops[0].args[0])
        return None


def _resolve_typedef(registry: TypeRegistry, type_ref: CType, seen: set[str]) -> CType:
    if type_ref.kind != "named" or type_ref.ref_kind != "typedef":
        return type_ref
    if type_ref.name in seen:
        return type_ref
    seen.add(type_ref.name or "")
    target = registry.typedefs.get(type_ref.name or "")
    if target is None:
        return type_ref
    return _resolve_typedef(registry, target.target, seen)


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
        return ("arr", resolved.count, _normalized_type_signature(registry, target, cache, stack, layout_for_named, include_member_names))
    return ("unknown",)


def _sig_digest(sig: tuple) -> str:
    data = repr(sig).encode("utf-8", "replace")
    return hashlib.sha1(data).hexdigest()[:8]


def _is_synthetic_member_name(name: str) -> bool:
    return name.startswith("__anon_member")


def _clone_type_ref(type_ref: CType) -> CType:
    clone = CType(
        kind=type_ref.kind,
        name=type_ref.name,
        ref_kind=type_ref.ref_kind,
        count=type_ref.count,
        qualifiers=list(type_ref.qualifiers),
    )
    if type_ref.target is not None:
        clone.target = _clone_type_ref(type_ref.target)
    return clone


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
            key for key, decl in registry.structs.items()
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
                details = ", ".join(
                    f"{m.name}:{_sig_digest(s)}" for m, s in zip(union_decl.members, sigs)
                )
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
            if (
                resolved.kind == "named"
                and resolved.ref_kind == "enum"
                and resolved.name == enum_decl.name
            ):
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


def render_type(
    registry: TypeRegistry,
    type_ref: CType,
    name: str,
    expand_typedefs: bool,
) -> str:
    if expand_typedefs:
        type_ref = _resolve_typedef(registry, type_ref, set())

    if type_ref.kind == "named":
        base = type_ref.name or "void"
        if type_ref.ref_kind in {"struct", "union", "enum"}:
            if type_ref.ref_kind == "enum" and type_ref.name in registry.enums:
                enum_decl = registry.enums[type_ref.name]
                if enum_decl.typedef_as is not None:
                    base = type_ref.name
                else:
                    base = f"{type_ref.ref_kind} {base}"
            else:
                base = f"{type_ref.ref_kind} {base}"
        if type_ref.qualifiers:
            base = " ".join(type_ref.qualifiers) + " " + base
        if name:
            return f"{base} {name}"
        return base

    if type_ref.kind == "pointer":
        quals = " ".join(type_ref.qualifiers)
        if name:
            inner = f"*{name}" if not quals else f"* {quals} {name}"
        else:
            inner = "*" if not quals else f"* {quals}"
        if type_ref.target and type_ref.target.needs_parens():
            inner = f"({inner})"
        return render_type(registry, type_ref.target or CType(kind="named", name="void", ref_kind="base"), inner, expand_typedefs)

    if type_ref.kind == "array":
        count = "" if type_ref.count is None else str(type_ref.count)
        inner = f"{name}[{count}]" if name else f"[{count}]"
        return render_type(registry, type_ref.target or CType(kind="named", name="void", ref_kind="base"), inner, expand_typedefs)

    return "void"


def _collect_value_deps(registry: TypeRegistry, type_ref: CType) -> set[tuple[str, str]]:
    resolved = _resolve_typedef(registry, type_ref, set())
    if resolved.kind == "named":
        if resolved.ref_kind in {"struct", "union", "enum"}:
            if resolved.name:
                return {(resolved.ref_kind, resolved.name)}
        return set()
    if resolved.kind == "pointer":
        return set()
    if resolved.kind == "array":
        if resolved.target is None:
            return set()
        return _collect_value_deps(registry, resolved.target)
    return set()


def _sorted_decl_keys(registry: TypeRegistry) -> list[tuple[str, str]]:
    decls: dict[tuple[str, str], object] = {}
    for key, value in registry.structs.items():
        decls[key] = value
    for name in registry.enums:
        decls[("enum", name)] = registry.enums[name]

    deps: dict[tuple[str, str], set[tuple[str, str]]] = {}
    for key, decl in decls.items():
        if isinstance(decl, StructDecl):
            if decl.opaque:
                deps[key] = set()
                continue
            refs: set[tuple[str, str]] = set()
            for member in decl.members:
                inline_union = registry.inline_unions.get((decl.kind, decl.name, member.name))
                if inline_union is not None:
                    for submember in inline_union.members:
                        refs |= _collect_value_deps(registry, submember.type_ref)
                    continue
                refs |= _collect_value_deps(registry, member.type_ref)
            deps[key] = {ref for ref in refs if ref in decls}
        else:
            deps[key] = set()

    order: list[tuple[str, str]] = []
    visited: set[tuple[str, str]] = set()
    visiting: set[tuple[str, str]] = set()

    def visit(node: tuple[str, str]) -> None:
        if node in visited:
            return
        if node in visiting:
            return
        visiting.add(node)
        for dep in sorted(deps.get(node, [])):
            visit(dep)
        visiting.remove(node)
        visited.add(node)
        order.append(node)

    for key in sorted(decls):
        visit(key)
    return order


def render_c(registry: TypeRegistry) -> str:
    lines: list[str] = []
    lines.append("/* Generated by kstructs */")
    lines.append("#include <stddef.h>")
    lines.append("#include <stdint.h>")
    lines.append("")

    opaque_typedefs: set[str] = set()
    opaque_lines: list[str] = []
    for (kind, name), decl in sorted(registry.structs.items()):
        if not decl.opaque:
            continue
        opaque_lines.append(f"{kind} {name};")
        opaque_lines.append(f"typedef {kind} {name} {name};")
        opaque_typedefs.add(name)

    for name, enum_decl in sorted(registry.enums.items()):
        if not enum_decl.opaque:
            continue
        opaque_lines.append(f"enum {name};")
        opaque_lines.append(f"typedef enum {name} {name};")
        opaque_typedefs.add(name)

    if opaque_lines:
        lines.extend(opaque_lines)
        lines.append("")

    for key in _sorted_decl_keys(registry):
        kind, name = key
        if kind == "enum":
            enum_decl = registry.enums[name]
            if enum_decl.opaque:
                continue
            lines.append(f"enum {enum_decl.name} {{")
            for enum_name, value in enum_decl.enumerators:
                lines.append(f"    {enum_name} = {value},")
            lines.append("};")
            lines.append("")
            continue

        decl = registry.structs[key]
        if decl.opaque:
            continue
        lines.append(f"{decl.kind} {decl.name} {{")
        extra_asserts: list[tuple[str, int]] = []
        skip_members: set[str] = set()
        for member in decl.members:
            inline_union = registry.inline_unions.get((decl.kind, decl.name, member.name))
            if inline_union is not None:
                skip_members.add(member.name)
                if member.offset is not None:
                    for submember in inline_union.members:
                        if submember.offset is None or submember.bit_size is not None:
                            continue
                        extra_asserts.append((submember.name, member.offset + submember.offset))
                lines.append("    union {")
                for submember in inline_union.members:
                    inline_decl = registry.inline_members.get((inline_union.kind, inline_union.name, submember.name))
                    if inline_decl is not None:
                        lines.append("        struct {")
                        for inline_member in inline_decl.members:
                            if inline_member.bit_size is not None:
                                decl_text = render_type(
                                    registry, inline_member.type_ref, inline_member.name, expand_typedefs=True
                                )
                                if inline_member.bit_offset is not None:
                                    lines.append(
                                        f"            {decl_text} : {inline_member.bit_size}; /* bit offset {inline_member.bit_offset} */"
                                    )
                                else:
                                    lines.append(f"            {decl_text} : {inline_member.bit_size};")
                            else:
                                decl_text = render_type(
                                    registry, inline_member.type_ref, inline_member.name, expand_typedefs=True
                                )
                                lines.append(f"            {decl_text};")
                        lines.append(f"        }} {submember.name};")
                        continue
                    if submember.bit_size is not None:
                        decl_text = render_type(registry, submember.type_ref, submember.name, expand_typedefs=True)
                        if submember.bit_offset is not None:
                            lines.append(
                                f"        {decl_text} : {submember.bit_size}; /* bit offset {submember.bit_offset} */"
                            )
                        else:
                            lines.append(f"        {decl_text} : {submember.bit_size};")
                    else:
                        decl_text = render_type(registry, submember.type_ref, submember.name, expand_typedefs=True)
                        lines.append(f"        {decl_text};")
                lines.append("    };")
                continue
            inline_decl = registry.inline_members.get((decl.kind, decl.name, member.name))
            if inline_decl is not None:
                lines.append("    struct {")
                for submember in inline_decl.members:
                    if submember.bit_size is not None:
                        decl_text = render_type(registry, submember.type_ref, submember.name, expand_typedefs=True)
                        if submember.bit_offset is not None:
                            lines.append(f"        {decl_text} : {submember.bit_size}; /* bit offset {submember.bit_offset} */")
                        else:
                            lines.append(f"        {decl_text} : {submember.bit_size};")
                    else:
                        decl_text = render_type(registry, submember.type_ref, submember.name, expand_typedefs=True)
                        lines.append(f"        {decl_text};")
                lines.append(f"    }} {member.name};")
                continue
            if member.bit_size is not None:
                decl_text = render_type(registry, member.type_ref, member.name, expand_typedefs=True)
                if member.bit_offset is not None:
                    lines.append(f"    {decl_text} : {member.bit_size}; /* bit offset {member.bit_offset} */")
                else:
                    lines.append(f"    {decl_text} : {member.bit_size};")
            else:
                decl_text = render_type(registry, member.type_ref, member.name, expand_typedefs=True)
                lines.append(f"    {decl_text};")
        lines.append("};")

        if not decl.opaque:
            type_name = f"{decl.kind} {decl.name}"
            for member in decl.members:
                if member.name in skip_members:
                    continue
                if member.offset is None or member.bit_size is not None:
                    continue
                lines.append(
                    f"_Static_assert(offsetof({type_name}, {member.name}) == 0x{member.offset:x}, "
                    f"\"{decl.name}.{member.name} offset\");"
                )
            for member_name, offset in extra_asserts:
                lines.append(
                    f"_Static_assert(offsetof({type_name}, {member_name}) == 0x{offset:x}, "
                    f"\"{decl.name}.{member_name} offset\");"
                )
        lines.append("")

    if registry.typedefs:
        for typedef_name in sorted(registry.typedefs):
            if typedef_name in opaque_typedefs:
                continue
            typedef = registry.typedefs[typedef_name]
            decl_text = render_type(registry, typedef.target, typedef.name, expand_typedefs=True)
            lines.append(f"typedef {decl_text};")

    return "\n".join(lines).rstrip() + "\n"


def generate_c_for_type(
    dwarfinfo,
    type_name: str,
    max_depth: int,
    correction_disable: Optional[set[str]] = None,
    correction_verbose: Optional[set[str]] = None,
    dwarf_verbose: Optional[set[str]] = None,
) -> str:
    builder = TypeBuilder(dwarfinfo, max_depth=max_depth, verbose=dwarf_verbose)
    root_die = builder.find_root_die(type_name)
    builder.build_from_root(root_die)
    disabled = correction_disable or set()
    apply_corrections(builder.registry, disabled, verbose=correction_verbose)
    return render_c(builder.registry)
