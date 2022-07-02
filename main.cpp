#include <LIEF/LIEF.hpp>
#include <cstring>
#include <fmt/core.h>
#include <iostream>
#include <tuple>

// later
// bool do_we_swap_endianness(const LIEF::Binary *binary){};

int get_pointer_size_for_bin(const LIEF::Binary *binary) {
  if (binary->header().is_32()) {
    return 4;
  } else if (binary->header().is_64()) {
    return 8;
  }
  return -1;
};

auto get_pointer_data_at_offset(const LIEF::Binary *binary,
                                uint64_t virtual_addr,
                                int pointer_size_for_binary) {
  auto bytes_at_mem = binary->get_content_from_virtual_address(
      virtual_addr, pointer_size_for_binary);
  std::uint64_t unswapped_data = {};
  std::memcpy(&unswapped_data, bytes_at_mem.data(), pointer_size_for_binary);
  return unswapped_data;
};

auto fixup_symbol_name(LIEF::EXE_FORMATS format, LIEF::Symbol symbol) {
  auto name = symbol.name();
  if (not(name.empty() || (symbol.value() == 0))) {
    if (format == LIEF::EXE_FORMATS::FORMAT_MACHO && name.front() == '_') {
      // Remove the leading underscore, as per
      // https://developer.apple.com/library/archive/documentation/DeveloperTools/Conceptual/MachOTopics/1-Articles/executing_files.html
      name.erase(0, 1);
    }
  };
  return name;
};

auto generate_symbol_map(const LIEF::Binary *binary) {
  std::map<uint64_t, LIEF::Symbol> symbol_map{};
  for (auto &symbol : binary->symbols()) {
    auto phys_addr = symbol.value();
    auto virtual_addr = binary->offset_to_virtual_address(phys_addr);
    symbol_map[virtual_addr] = symbol;
  };
  return symbol_map;
};

struct vtable_data_t {
  int pointer_size;
  int vtable_num_of_methods;
  std::map<uint64_t, LIEF::Symbol> vtable_members;
};

vtable_data_t get_vtable(LIEF::Binary *binary, auto symbol_map, uint64_t addr) {
  auto pointer_size_for_binary = get_pointer_size_for_bin(binary);
  std::map<uint64_t, LIEF::Symbol> vtable_members{};

  // Skip non vtable stuff
  const auto vtable_addr = addr + (2 * pointer_size_for_binary);

  auto vtable_num_of_methods = 0;
  auto current_loop_addr = vtable_addr;
  while (true) {
    auto data_at_offset = get_pointer_data_at_offset(binary, current_loop_addr,
                                                     pointer_size_for_binary);
    auto current_offset = current_loop_addr - vtable_addr;

    if (symbol_map.contains(current_loop_addr)) {
      // fmt::print("Skipping because of symbol {}",
      // symbol_map[vtable_addr].name());
      break;
    };
    // if (data_at_offset == 0)
    //   break;

    vtable_members[current_offset] = symbol_map[data_at_offset];
    vtable_num_of_methods++;
    current_loop_addr += pointer_size_for_binary;
  };
  return {.pointer_size = pointer_size_for_binary,
          .vtable_num_of_methods = vtable_num_of_methods,
          .vtable_members = vtable_members};
};

int main(int argc, const char **argv) {
  if (argc < 2)
    return 1;
  auto binary = LIEF::Parser::parse(argv[1]);
  auto symbol_map = generate_symbol_map(binary.get());
  for (const auto &[addr, symbol] : symbol_map) {
    auto name = fixup_symbol_name(binary->format(), symbol);
    if (name.starts_with("_ZTV")) {
      auto vtable_data = get_vtable(binary.get(), symbol_map, addr);

      fmt::print("{} = {:#08x}\n", name, addr);
      fmt::print("\tnumber of vtable methods: {}\n",
                 vtable_data.vtable_num_of_methods);
      for (const auto &[offset, member_symbol] : vtable_data.vtable_members) {
        std::string formatted_name = "";
        if (member_symbol.name().empty()) {
          formatted_name = fmt::format("{:#08X}", member_symbol.value());
        } else {
          formatted_name = fixup_symbol_name(binary->format(), member_symbol);
        };
        fmt::print("\t{} is at offset {} (member# {})\n", formatted_name,
                   offset, offset / vtable_data.pointer_size);
      };
    };
  };
};
