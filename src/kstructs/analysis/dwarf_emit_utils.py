from __future__ import annotations

import hashlib
from typing import Optional

from .dwarf_emit_types import CType, TypeRegistry


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
