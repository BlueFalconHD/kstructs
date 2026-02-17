import os
import sys
import unittest


REPO_ROOT = os.path.dirname(os.path.dirname(__file__))
SRC_ROOT = os.path.join(REPO_ROOT, "src")
sys.path.insert(0, SRC_ROOT)


from kstructs.analysis.dwarf_emit_rename import apply_type_prefix  # noqa: E402
from kstructs.analysis.dwarf_emit_types import (  # noqa: E402
    CType,
    EnumDecl,
    MemberInfo,
    StructDecl,
    TypedefDecl,
    TypeRegistry,
)


class TypePrefixTests(unittest.TestCase):
    def test_prefixes_and_rewrites_references(self) -> None:
        reg = TypeRegistry()

        reg.enums["foo_e"] = EnumDecl(name="foo_e", size=4, enumerators=[("FOO_A", 0)])

        reg.structs[("struct", "proc")] = StructDecl(
            kind="struct",
            name="proc",
            size=8,
            members=[
                MemberInfo(
                    name="p_pid",
                    type_ref=CType(kind="named", name="pid_t", ref_kind="typedef"),
                    offset=0,
                    bit_size=None,
                    bit_offset=None,
                ),
                MemberInfo(
                    name="p_self",
                    type_ref=CType(
                        kind="pointer",
                        target=CType(kind="named", name="proc", ref_kind="struct"),
                    ),
                    offset=4,
                    bit_size=None,
                    bit_offset=None,
                ),
                MemberInfo(
                    name="p_enum",
                    type_ref=CType(kind="named", name="foo_e", ref_kind="enum"),
                    offset=6,
                    bit_size=None,
                    bit_offset=None,
                ),
            ],
        )

        reg.typedefs["pid_t"] = TypedefDecl(
            name="pid_t", target=CType(kind="named", name="int", ref_kind="base")
        )
        reg.typedefs["proc_t"] = TypedefDecl(
            name="proc_t",
            target=CType(
                kind="pointer",
                target=CType(kind="named", name="proc", ref_kind="struct"),
            ),
        )

        # Inline mappings use (kind, container_name, member_name) keys.
        inline_decl = StructDecl(
            kind="struct",
            name="le",
            size=16,
            members=[
                MemberInfo(
                    name="le_next",
                    type_ref=CType(kind="pointer", target=CType(kind="named", name="proc", ref_kind="struct")),
                    offset=0,
                    bit_size=None,
                    bit_offset=None,
                )
            ],
        )
        reg.structs[("struct", "le")] = inline_decl
        reg.inline_members[("struct", "proc", "p_inline")] = inline_decl

        # Anonymous unions can be removed from `structs` but still referenced by
        # `inline_unions` / `inline_members` lookups during rendering.
        anon_union = StructDecl(
            kind="union",
            name="proc___anon_member_1",
            size=8,
            members=[
                MemberInfo(
                    name="le",
                    type_ref=CType(kind="named", name="le", ref_kind="struct"),
                    offset=0,
                    bit_size=None,
                    bit_offset=None,
                )
            ],
        )
        reg.inline_unions[("struct", "proc", "p_union")] = anon_union
        reg.inline_members[("union", "proc___anon_member_1", "le")] = inline_decl

        apply_type_prefix(reg, "ks_")

        self.assertIn(("struct", "ks_proc"), reg.structs)
        self.assertIn(("struct", "ks_le"), reg.structs)
        self.assertIn("ks_foo_e", reg.enums)
        self.assertIn("ks_proc_t", reg.typedefs)
        self.assertIn("ks_pid_t", reg.typedefs)

        proc_decl = reg.structs[("struct", "ks_proc")]
        self.assertEqual(proc_decl.name, "ks_proc")

        # member typedef -> prefixed typedef
        self.assertEqual(proc_decl.members[0].type_ref.name, "ks_pid_t")
        # member pointer target struct -> prefixed struct tag
        self.assertEqual(proc_decl.members[1].type_ref.target.name, "ks_proc")
        # member enum -> prefixed enum tag
        self.assertEqual(proc_decl.members[2].type_ref.name, "ks_foo_e")

        # typedef pointer target struct -> prefixed struct tag
        self.assertEqual(reg.typedefs["ks_proc_t"].target.target.name, "ks_proc")

        # inline mappings updated
        self.assertIn(("struct", "ks_proc", "p_inline"), reg.inline_members)
        self.assertIn(("struct", "ks_proc", "p_union"), reg.inline_unions)
        self.assertIn(("union", "ks_proc___anon_member_1", "le"), reg.inline_members)
        self.assertEqual(reg.inline_unions[("struct", "ks_proc", "p_union")].name, "ks_proc___anon_member_1")


if __name__ == "__main__":
    unittest.main()
