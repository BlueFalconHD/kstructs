import argparse
from pathlib import Path

from .analysis.dwarf import emit_c_types

def main() -> None:
    parser = argparse.ArgumentParser(description="Parse DWARF data from ELF or Mach-O files.")
    parser.add_argument("path", help="Path to the ELF/Mach-O file containing DWARF sections.")
    parser.add_argument(
        "--arch",
        help="Select a specific Mach-O slice (e.g. x86_64, arm64, arm64e).",
        default=None,
    )
    parser.add_argument(
        "--type",
        dest="type_name",
        default=None,
        help="Generate C definitions for the given DWARF type name (e.g. proc, proc_t).",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=1,
        help="Maximum pointer recursion depth for expanding struct/union/enum types (default: 1).",
    )
    parser.add_argument(
        "--correction-disable",
        default="",
        help="Comma-separated list of correction passes to disable (e.g. xnu-struct-group-name).",
    )
    parser.add_argument(
        "--correction-verbose",
        default="",
        help="Comma-separated list of correction passes to log (or 'all').",
    )
    parser.add_argument(
        "--dwarf-verbose",
        default="",
        help="Comma-separated list of DWARF debug logs to enable (null-members, or 'all').",
    )
    parser.add_argument(
        "--type-prefix",
        default=None,
        help="Prefix all generated struct/union/enum tags and typedefs to avoid name collisions (e.g. ks_).",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Write generated C to this path instead of stdout.",
    )
    args = parser.parse_args()

    if not args.type_name:
        raise ValueError("--type is required")

    if args.max_depth < 0:
        raise ValueError("--max-depth must be >= 0")
    output = emit_c_types(
        args.path,
        type_name=args.type_name,
        arch=args.arch,
        max_depth=args.max_depth,
        correction_disable={
            item.strip()
            for item in args.correction_disable.split(",")
            if item.strip()
        },
        correction_verbose={
            item.strip()
            for item in args.correction_verbose.split(",")
            if item.strip()
        },
        dwarf_verbose={
            item.strip()
            for item in args.dwarf_verbose.split(",")
            if item.strip()
        },
        type_prefix=args.type_prefix,
    )
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
    else:
        print(output, end="")
