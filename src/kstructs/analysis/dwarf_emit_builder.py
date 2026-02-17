from __future__ import annotations

import sys
from typing import Optional

from elftools.dwarf.dwarf_expr import DWARFExprParser

from .dwarf_emit_types import CType, EnumDecl, MemberInfo, StructDecl, TypedefDecl, TypeRegistry
from .dwarf_emit_utils import _attr_int, _decode_attr, _resolve_typedef, _sanitize_identifier

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

        for preferred in (
            "DW_TAG_structure_type",
            "DW_TAG_class_type",
            "DW_TAG_union_type",
            ENUM_TAG,
            TYPEDEF_TAG,
            BASE_TAG,
        ):
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
            alignment = _attr_int(child.attributes.get("DW_AT_alignment"))
            if alignment is not None and alignment <= 1:
                alignment = None

            decl.members.append(
                MemberInfo(
                    name=raw_name,
                    type_ref=member_type_ref,
                    offset=offset,
                    bit_size=bit_size,
                    bit_offset=bit_offset,
                    alignment=alignment,
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
