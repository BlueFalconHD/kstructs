import argparse

from .analysis.dwarf import print_types

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
    args = parser.parse_args()

    print("Hello from kstructs!")
    print_types(args.path, arch=args.arch, name_filter=args.filter, limit=args.limit)
