cmake_minimum_required(VERSION 3.20)

project(kstructs LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(LLVM_ROOT "/opt/homebrew/opt/llvm" CACHE PATH "LLVM install prefix")

add_executable(kstructs
  src/main.cpp
  src/dwarf_builder.cpp
  src/dwarf_corrections.cpp
  src/dwarf_rename.cpp
  src/dwarf_render.cpp
  src/dwarf_signatures.cpp
  src/dwarf_utils.cpp
)

target_include_directories(kstructs PRIVATE
  ${LLVM_ROOT}/include
  ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(kstructs PRIVATE
  ${LLVM_ROOT}/lib/libLLVM.dylib
  ${LLVM_ROOT}/lib/c++/libc++.1.dylib
  ${LLVM_ROOT}/lib/c++/libc++abi.1.dylib
)

target_compile_definitions(kstructs PRIVATE
  LLVM_ENABLE_ASSERTIONS=1
)

set_target_properties(kstructs PROPERTIES
  BUILD_RPATH "${LLVM_ROOT}/lib"
)
