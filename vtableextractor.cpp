#include "vtableextractor.hpp"
#include <fmt/core.h>

// later
// bool do_we_swap_endianness(const LIEF::Binary *binary){};

int VtableExtractor::get_pointer_size_for_bin() {
  if (binary.header().is_32()) {
    return 4;
  } else if (binary.header().is_64()) {
    return 8;
  } else {
    throw StringError("Cant figure out valid pointer size");
  };
};

template <typename T>
T VtableExtractor::get_data_at_offset(uint64_t virtual_addr) {
  auto bytes_at_mem =
      binary.get_content_from_virtual_address(virtual_addr, sizeof(T));
  T unswapped_data = {};
  std::memcpy(&unswapped_data, bytes_at_mem.data(), sizeof(T));
  return unswapped_data;
};

std::string VtableExtractor::fixup_symbol_name(std::string name) {
  if (not name.empty()) {
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

std::string VtableExtractor::get_typeinfo_name(uint64_t addr) {
  switch (binary.format()) {
    case LIEF::FORMAT_MACHO: {
      const auto binary_macho = dynamic_cast<LIEF::MachO::Binary *>(&binary);
      auto section = binary_macho->section_from_virtual_address(addr);
      const auto section_content = section->content().data();
      auto string_content_unconverted =
          &(section_content[addr - section->virtual_address()]);
      return std::string(
          reinterpret_cast<const char *>(string_content_unconverted));
      break;
    }
    default: {
      throw StringError("Unknown binary format");
      break;
    }
  };
};
VtableExtractor::typeinfo_t VtableExtractor::parse_typeinfo(uint64_t addr) {
  typeinfo_t typeinfo{};
  switch (binary.format()) {
    case LIEF::FORMAT_MACHO: {
      const auto binary_macho = dynamic_cast<LIEF::MachO::Binary *>(&binary);
      const auto dyld_info = binary_macho->dyld_info();
      // TODO: It's fast enough but we should cache this
      std::string typeinfo_type{""};
      for (const auto &binding_info : dyld_info->bindings()) {
        if (addr == binding_info.address()) {
          typeinfo_type = binding_info.symbol()->name();
          break;
        };
      };
      if (typeinfo_type == "")
        throw StringError(fmt::format(
            "There should be a typeinfo class symbol here. Address is {:08X}",
            addr));
      auto class_name =
          get_typeinfo_name(get_ptr_at_offset(addr + pointer_size_for_binary));
      auto typeinfo_classinfo_name = fixup_symbol_name(typeinfo_type);
      typeinfo.typeinfo_type = typeinfo_t::CLASS_TYPE_INFO;
      if (typeinfo_classinfo_name.find("__si_class_type_info") !=
          std::string::npos) {
        typeinfo.typeinfo_type = typeinfo_t::SI_CLASS_TYPE_INFO;
      } else if (typeinfo_classinfo_name.find("__vmi_class_type_info") !=
                 std::string::npos) {
        typeinfo.typeinfo_type = typeinfo_t::VMI_CLASS_TYPE_INFO;
      }
      typeinfo.name = class_name;
      break;
    }
    default: {
      throw StringError("Unknown binary format");
      break;
    }
  };

  switch (typeinfo.typeinfo_type) {
    case typeinfo_t::SI_CLASS_TYPE_INFO: {
      auto typeinfo_addr =
          get_ptr_at_offset(addr + (2 * pointer_size_for_binary));
      if (typeinfo_addr != 0) {
        auto base_typeinfo = parse_typeinfo(typeinfo_addr);
        typeinfo.si_base_class = std::make_shared<typeinfo_t>(base_typeinfo);
      };
      break;
    };
    case typeinfo_t::VMI_CLASS_TYPE_INFO: {
      auto flags =
          get_data_at_offset<uint32_t>(addr + (2 * pointer_size_for_binary));
      auto base_count =
          get_data_at_offset<uint32_t>(addr + (3 * pointer_size_for_binary));
      for (uint32_t i = 0; i < base_count; i++) {
        typeinfo_t::vmi_base_class_t base_class_info{};
        try {
          // It could be located in a different lib, we will throw.
          auto base_class = parse_typeinfo(get_ptr_at_offset(
              addr + ((4 + (i * 2)) * pointer_size_for_binary)));
          base_class_info.base_class = std::make_shared<typeinfo_t>(base_class);
        } catch (std::exception &e) {
          base_class_info.base_class = nullptr;
        };
        // TODO: This isn't compatible with X86-64 because this assumes that
        // long is 32bits wide
        auto offset_flags = get_data_at_offset<uint32_t>(
            addr + ((5 + (i * 2)) * pointer_size_for_binary));
        base_class_info.offset_flags = offset_flags;
        typeinfo.vmi_base_class_info.emplace_back(base_class_info);
      }
      typeinfo.vmi_flags = flags;
      typeinfo.vmi_base_count = base_count;
      break /* a leg */;
    };
    default: {
      break;
    };
  };
  return typeinfo;
};

VtableExtractor::vtable_data_t VtableExtractor::get_vtable(uint64_t addr) {
  std::map<uint64_t, vtable_member_t> vtable_members{};

  // Skip vptr offset
  auto typeinfo_addr = get_ptr_at_offset(addr + pointer_size_for_binary);

  // This is a fix for certain classes where the symbol is put three pointers
  // before the vtable, which puts the typeinfo one pointer down. (since it's
  // at entry "-1" of the vtable). This is purely a heuristic since the
  // offset-to-top pointers could be non-null, but it seems to work at every
  // case i've thrown at it so far. TODO: Can we make this more stable? Yeah we
  // can just loop until the pointer points to a typeinfo symbol
  //
  // This var is used to fixup the vtable offset.
  int vtable_offset_from_symbol = 2 * pointer_size_for_binary;
  if (typeinfo_addr == 0) {
    vtable_offset_from_symbol += pointer_size_for_binary;
    typeinfo_addr = get_ptr_at_offset(addr + (2 * pointer_size_for_binary));
  }
  auto typeinfo = parse_typeinfo(typeinfo_addr);

  const auto vtable_addr = addr + vtable_offset_from_symbol;

  auto vtable_num_of_methods = 0;
  auto current_loop_addr = vtable_addr;
  while (true) {
    auto data_at_offset = get_ptr_at_offset(current_loop_addr);
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
        .fixed_name = fixup_symbol_name(symbol.name()),
    };
    vtable_num_of_methods++;
    current_loop_addr += pointer_size_for_binary;
  };
  return {
      // name is set in get_vtables
      .typeinfo = typeinfo,
      .addr = addr,
      .pointer_size = pointer_size_for_binary,
      .vtable_num_of_methods = vtable_num_of_methods,
      .vtable_members = vtable_members,
  };
};

std::vector<VtableExtractor::vtable_data_t> VtableExtractor::get_vtables() {
  std::vector<VtableExtractor::vtable_data_t> vtables{};
  for (const auto &[addr, symbol] : symbol_map) {
    auto name = fixup_symbol_name(symbol.name());
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
