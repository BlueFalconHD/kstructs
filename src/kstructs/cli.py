import argparse
from pathlib import Path

from .analysis.dwarf import emit_c_types, print_types

def main() -> None:
    parser = argparse.ArgumentParser(description="Parse DWARF data from ELF or Mach-O files.")
    parser.add_argument("path", help="Path to the ELF/Mach-O file containing DWARF sections.")
    parser.add_argument(
        "--arch",
        help="Select a specific Mach-O slice (e.g. x86_64, arm64, arm64e).",
        default=None,
    )
    parser.add_argument(
        "--filter",
        help="Only show types whose name contains this substring (case-insensitive).",
        default=None,
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Limit number of type names printed (default: 100, use 0 to suppress).",
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
        "--output",
        default=None,
        help="Write generated C to this path instead of stdout.",
    )
    args = parser.parse_args()

    if args.type_name:
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
        )
        if args.output:
            Path(args.output).write_text(output, encoding="utf-8")
        else:
            print(output, end="")
        return

    print_types(args.path, arch=args.arch, name_filter=args.filter, limit=args.limit)
