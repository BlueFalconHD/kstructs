# kstructs

kstructs is a command line program capable of creating a C header file with structures from MacOS dSYMs. It is specifically made to work with KDKs.

## Usage

To generate a header file, run the following command:

```bash
build/kstructs --type proc_t,task_t,vm_map_t --max-depth 10 --type-prefix ks_ /Library/Developer/KDKs/path_to_kdk/System/Library/Kernels/path_to_kernel/Contents/Resources/DWARF/path_to_dwarf > t8112.h
```

This will generate a header file named `t8112.h` with the structures `proc_t`, `task_t`, and `vm_map_t` from the specified dSYM. The `--max-depth` option limits the depth of recursion for type resolution (i.e. new structures referenced by other will be generated up to this depth). The `--type-prefix` option adds a prefix to the generated structure names to avoid naming conflicts.

## Building
To build kstructs, you can use CMake.

```bash
cmake -S . -B build
cmake --build build
```
