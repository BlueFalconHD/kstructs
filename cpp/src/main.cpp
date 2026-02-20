#include "dwarf_builder.h"
#include "dwarf_corrections.h"
#include "dwarf_render.h"
#include "dwarf_rename.h"

#include <llvm/ADT/SmallVector.h>
#include <llvm/ADT/StringRef.h>
#include <llvm/Object/Archive.h>
#include <llvm/Object/Binary.h>
#include <llvm/Object/MachO.h>
#include <llvm/Object/MachOUniversal.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/Path.h>
#include <llvm/Support/ToolOutputFile.h>
#include <llvm/Support/WithColor.h>

#include <filesystem>
#include <iomanip>
#include <random>
#include <set>
#include <sstream>

using namespace llvm;
using namespace llvm::object;

namespace kstructs {

struct Options {
  std::string path;
  std::string arch;
  bool has_arch = false;
  std::vector<std::string> type_names;
  int max_depth = 1;
  std::set<std::string> correction_disable;
  std::set<std::string> correction_verbose;
  std::set<std::string> dwarf_verbose;
  std::optional<std::string> type_prefix;
  bool include_guard = false;
  std::string output;
  bool has_output = false;
};

static std::set<std::string> split_set(const std::string &value) {
  std::set<std::string> out;
  size_t start = 0;
  while (start <= value.size()) {
    size_t end = value.find(',', start);
    if (end == std::string::npos) {
      end = value.size();
    }
    std::string token = value.substr(start, end - start);
    size_t left = 0;
    while (left < token.size() && std::isspace(static_cast<unsigned char>(token[left]))) {
      left++;
    }
    size_t right = token.size();
    while (right > left && std::isspace(static_cast<unsigned char>(token[right - 1]))) {
      right--;
    }
    if (right > left) {
      out.insert(token.substr(left, right - left));
    }
    if (end == value.size()) {
      break;
    }
    start = end + 1;
  }
  return out;
}

static std::vector<std::string> split_list(const std::string &value) {
  std::vector<std::string> out;
  size_t start = 0;
  while (start <= value.size()) {
    size_t end = value.find(',', start);
    if (end == std::string::npos) {
      end = value.size();
    }
    std::string token = value.substr(start, end - start);
    size_t left = 0;
    while (left < token.size() && std::isspace(static_cast<unsigned char>(token[left]))) {
      left++;
    }
    size_t right = token.size();
    while (right > left && std::isspace(static_cast<unsigned char>(token[right - 1]))) {
      right--;
    }
    if (right > left) {
      out.push_back(token.substr(left, right - left));
    }
    if (end == value.size()) {
      break;
    }
    start = end + 1;
  }
  return out;
}

static void error_or_exit(Error Err, StringRef Prefix) {
  if (!Err) {
    return;
  }
  WithColor::error() << Prefix << ": " << toString(std::move(Err)) << "\n";
  exit(1);
}

static bool arch_matches(const std::string &requested, const ObjectFile &obj) {
  if (requested.empty()) {
    return true;
  }
  Triple triple = obj.makeTriple();
  std::string arch_name = triple.getArchName().str();
  std::string request = requested;
  auto normalize = [](std::string value) {
    std::string out;
    for (char ch : value) {
      if (ch != '-' && ch != '_') {
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
      }
    }
    return out;
  };
  return normalize(request) == normalize(arch_name);
}

static void expand_dsym_objects(StringRef path, std::vector<std::string> &objects) {
  auto dsym = MachOObjectFile::findDsymObjectMembers(path);
  if (dsym) {
    if (dsym->empty()) {
      objects.emplace_back(path.str());
    } else {
      for (const auto &obj : *dsym) {
        objects.push_back(obj);
      }
    }
    return;
  }
  error_or_exit(dsym.takeError(), path);
}

static void handle_object(ObjectFile &obj,
                          DWARFContext &ctx,
                          const Options &options,
                          raw_ostream &os,
                          std::optional<std::string> *include_guard) {
  TypeBuilder builder(ctx, options.max_depth, options.dwarf_verbose);
  for (const auto &type_name : options.type_names) {
    auto root = builder.find_root_die(type_name);
    builder.build_from_root(root);
  }

  apply_corrections(builder.registry, options.correction_disable, &options.correction_verbose);
  if (options.type_prefix) {
    apply_type_prefix(builder.registry, options.type_prefix.value());
  }

  std::optional<std::string> guard_value;
  if (include_guard && include_guard->has_value()) {
    guard_value = *include_guard;
    include_guard->reset();
  }
  os << render_c(builder.registry, guard_value);
}

static bool handle_buffer(StringRef filename,
                          MemoryBufferRef buffer,
                          const Options &options,
                          raw_ostream &os,
                          std::optional<std::string> *include_guard);

static bool handle_archive(StringRef filename,
                           Archive &archive,
                           const Options &options,
                           raw_ostream &os,
                           std::optional<std::string> *include_guard) {
  bool result = true;
  Error err = Error::success();
  for (const auto &child : archive.children(err)) {
    auto buffer_or = child.getMemoryBufferRef();
    error_or_exit(buffer_or.takeError(), filename);
    auto name_or = child.getName();
    error_or_exit(name_or.takeError(), filename);
    std::string name = (filename + "(" + name_or.get() + ")").str();
    result &= handle_buffer(name, buffer_or.get(), options, os, include_guard);
  }
  error_or_exit(std::move(err), filename);
  return result;
}

static bool handle_buffer(StringRef filename,
                          MemoryBufferRef buffer,
                          const Options &options,
                          raw_ostream &os,
                          std::optional<std::string> *include_guard) {
  Expected<std::unique_ptr<Binary>> bin_or_err = object::createBinary(buffer);
  if (!bin_or_err) {
    error_or_exit(bin_or_err.takeError(), filename);
    return false;
  }

  if (auto *obj = dyn_cast<ObjectFile>(bin_or_err->get())) {
    if (!arch_matches(options.has_arch ? options.arch : "", *obj)) {
      return true;
    }
    auto ctx = DWARFContext::create(*obj, DWARFContext::ProcessDebugRelocations::Process, nullptr, "",
                                    WithColor::defaultErrorHandler, WithColor::defaultWarningHandler, true);
    handle_object(*obj, *ctx, options, os, include_guard);
    return true;
  }

  if (auto *fat = dyn_cast<MachOUniversalBinary>(bin_or_err->get())) {
    bool result = true;
    for (auto &obj_for_arch : fat->objects()) {
      if (auto mach_or_err = obj_for_arch.getAsObjectFile()) {
        auto &obj = **mach_or_err;
        if (!arch_matches(options.has_arch ? options.arch : "", obj)) {
          continue;
        }
        auto ctx = DWARFContext::create(obj, DWARFContext::ProcessDebugRelocations::Process, nullptr, "",
                                        WithColor::defaultErrorHandler, WithColor::defaultWarningHandler, true);
        handle_object(obj, *ctx, options, os, include_guard);
        continue;
      } else {
        consumeError(mach_or_err.takeError());
      }
      if (auto archive_or_err = obj_for_arch.getAsArchive()) {
        error_or_exit(archive_or_err.takeError(), filename);
        result &= handle_archive(filename, *archive_or_err.get(), options, os, include_guard);
      } else {
        consumeError(archive_or_err.takeError());
      }
    }
    return result;
  }

  if (auto *archive = dyn_cast<Archive>(bin_or_err->get())) {
    return handle_archive(filename, *archive, options, os, include_guard);
  }

  return false;
}

static bool handle_file(StringRef filename,
                        const Options &options,
                        raw_ostream &os,
                        std::optional<std::string> *include_guard) {
  auto buffer_or = MemoryBuffer::getFileOrSTDIN(filename);
  if (!buffer_or) {
    error_or_exit(errorCodeToError(buffer_or.getError()), filename);
    return false;
  }
  return handle_buffer(filename, *buffer_or.get(), options, os, include_guard);
}

static std::string make_guard() {
  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<uint64_t> dist;
  uint64_t a = dist(gen);
  uint64_t b = dist(gen);
  std::ostringstream oss;
  oss << "KSTRUCTS_GUARD_" << std::hex << std::uppercase
      << std::setw(16) << std::setfill('0') << a
      << std::setw(16) << std::setfill('0') << b
      << "_H";
  return oss.str();
}

static Options parse_options(int argc, char **argv) {
  cl::OptionCategory category("kstructs options");
  cl::opt<std::string> input_path(cl::Positional, cl::desc("<input object files or .dSYM bundles>"),
                                  cl::Required, cl::cat(category));
  cl::opt<std::string> arch("arch", cl::desc("Select a specific Mach-O slice (e.g. x86_64, arm64, arm64e)"),
                            cl::init(""), cl::cat(category));
  cl::opt<std::string> type_name("type", cl::desc("Generate C definitions for the given DWARF type name(s)"),
                                 cl::Required, cl::cat(category));
  cl::opt<int> max_depth("max-depth", cl::desc("Maximum pointer recursion depth"), cl::init(1),
                         cl::cat(category));
  cl::opt<std::string> correction_disable("correction-disable",
                                          cl::desc("Comma-separated list of correction passes to disable"),
                                          cl::init(""), cl::cat(category));
  cl::opt<std::string> correction_verbose("correction-verbose",
                                          cl::desc("Comma-separated list of correction passes to log (or 'all')"),
                                          cl::init(""), cl::cat(category));
  cl::opt<std::string> dwarf_verbose("dwarf-verbose",
                                     cl::desc("Comma-separated list of DWARF debug logs to enable (null-members, or 'all')"),
                                     cl::init(""), cl::cat(category));
  cl::opt<std::string> type_prefix("type-prefix",
                                   cl::desc("Prefix all generated struct/union/enum tags and typedefs"),
                                   cl::init(""), cl::cat(category));
  cl::opt<bool> include_guard("include-guard",
                              cl::desc("Emit an include guard in the generated output"),
                              cl::init(false), cl::cat(category));
  cl::opt<std::string> output("output", cl::desc("Write generated C to this path instead of stdout"),
                              cl::init(""), cl::cat(category));

  cl::HideUnrelatedOptions({&category});
  cl::ParseCommandLineOptions(argc, argv);

  Options options;
  options.path = input_path;
  if (!arch.empty()) {
    options.arch = arch;
    options.has_arch = true;
  }
  options.type_names = split_list(type_name);
  if (options.type_names.empty()) {
    WithColor::error() << "--type must include at least one type name\n";
    exit(1);
  }
  options.max_depth = max_depth;
  options.correction_disable = split_set(correction_disable);
  options.correction_verbose = split_set(correction_verbose);
  options.dwarf_verbose = split_set(dwarf_verbose);
  if (!type_prefix.empty()) {
    options.type_prefix = type_prefix;
  }
  options.include_guard = include_guard;
  if (!output.empty()) {
    options.output = output;
    options.has_output = true;
  }
  return options;
}

} // namespace kstructs

int main(int argc, char **argv) {
  InitLLVM init(argc, argv);
  auto options = kstructs::parse_options(argc, argv);

  if (options.max_depth < 0) {
    WithColor::error() << "--max-depth must be >= 0\n";
    return 1;
  }

  std::vector<std::string> objects;
  kstructs::expand_dsym_objects(options.path, objects);
  if (objects.empty()) {
    objects.push_back(options.path);
  }

  std::error_code ec;
  std::unique_ptr<ToolOutputFile> output_file;
  raw_ostream *os = &outs();
  if (options.has_output) {
    output_file = std::make_unique<ToolOutputFile>(options.output, ec, sys::fs::OF_TextWithCRLF);
    if (ec) {
      WithColor::error() << "unable to open output file " << options.output << ": " << ec.message() << "\n";
      return 1;
    }
    output_file->keep();
    os = &output_file->os();
  }

  bool success = true;
  std::optional<std::string> include_guard;
  if (options.include_guard) {
    include_guard = kstructs::make_guard();
  }
  for (const auto &obj : objects) {
    success &= kstructs::handle_file(obj, options, *os, &include_guard);
  }

  return success ? 0 : 1;
}
