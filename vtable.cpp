#include "vtable.hpp"
#include <fmt/core.h>

// later
// bool do_we_swap_endianness(const LIEF::Binary *binary){};

int VtableExtractor::get_pointer_size_for_bin() {
  if (binary.header().is_32()) {
    return 4;
  } else if (binary.header().is_64()) {
    return 8;
  }
  return -1;
};

uint64_t VtableExtractor::get_pointer_data_at_offset(uint64_t virtual_addr) {
  auto bytes_at_mem = binary.get_content_from_virtual_address(
      virtual_addr, pointer_size_for_binary);
  uint64_t unswapped_data = {};
  std::memcpy(&unswapped_data, bytes_at_mem.data(), pointer_size_for_binary);
  return unswapped_data;
};

std::string VtableExtractor::fixup_symbol_name(LIEF::Symbol symbol) {
  auto name = symbol.name();
  if (not(name.empty() || (symbol.value() == 0))) {
    if (binary.format() == LIEF::EXE_FORMATS::FORMAT_MACHO &&
        name.front() == '_') {
      // Remove the leading underscore, as per
      // https://developer.apple.com/library/archive/documentation/DeveloperTools/Conceptual/MachOTopics/1-Articles/executing_files.html
      name.erase(0, 1);
    }
  };
  return name;
};

void VtableExtractor::generate_symbol_map() {
  for (auto &symbol : binary.symbols()) {
    auto phys_addr = symbol.value();
    auto virtual_addr = binary.offset_to_virtual_address(phys_addr);
    symbol_map[virtual_addr] = symbol;
  };
};

VtableExtractor::vtable_data_t VtableExtractor::get_vtable(uint64_t addr) {
  std::map<uint64_t, vtable_member_t> vtable_members{};

  // Skip non vtable stuff
  const auto vtable_addr = addr + (2 * pointer_size_for_binary);

  auto vtable_num_of_methods = 0;
  auto current_loop_addr = vtable_addr;
  while (true) {
    auto data_at_offset = get_pointer_data_at_offset(current_loop_addr);
    auto current_offset = current_loop_addr - vtable_addr;

    // Another vtable has most likely started
    if (symbol_map.contains(current_loop_addr)) {
      // fmt::print("Skipping because of symbol {}",
      // symbol_map[vtable_addr].name());
      break;
    };
    if (!symbol_map.contains(data_at_offset)) {
      // Could be a relocated weird magic thingy
      break;
    };
    if (data_at_offset == 0)
      break;

    auto symbol = symbol_map[data_at_offset];
    vtable_members[current_offset] = {
        .symbol = symbol,
        .fixed_name = fixup_symbol_name(symbol),
    };
    vtable_num_of_methods++;
    current_loop_addr += pointer_size_for_binary;
  };
  return {
      // name is set in get_vtables
      .addr = addr,
      .pointer_size = pointer_size_for_binary,
      .vtable_num_of_methods = vtable_num_of_methods,
      .vtable_members = vtable_members,
  };
};

std::vector<VtableExtractor::vtable_data_t> VtableExtractor::get_vtables() {
  std::vector<VtableExtractor::vtable_data_t> vtables{};
  for (const auto &[addr, symbol] : symbol_map) {
    auto name = fixup_symbol_name(symbol);
    if (name.starts_with("_ZTV")) {
      auto vtable_data = get_vtable(addr);
      vtable_data.name = name;
      vtables.emplace_back(vtable_data);
    };
  };
  return vtables;
};

VtableExtractor::VtableExtractor(LIEF::Binary &binary) : binary(binary) {
  pointer_size_for_binary = get_pointer_size_for_bin();
  generate_symbol_map();
};
