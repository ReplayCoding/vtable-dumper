#include "vtableextractor.hpp"
#include "error.hpp"
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
  if (binary.format() == LIEF::EXE_FORMATS::FORMAT_MACHO &&
      (!name.empty() && name.front() == '_')) {
    // Remove the leading underscore, as per
    // https://developer.apple.com/library/archive/documentation/DeveloperTools/Conceptual/MachOTopics/1-Articles/executing_files.html
    name.erase(0, 1);
  }

  return name;
};

void VtableExtractor::generate_symbol_map() {
  for (const auto &symbol : binary.symbols()) {
    const auto virtual_addr = binary.offset_to_virtual_address(symbol.value());

    symbol_map[virtual_addr] = symbol;
  };
};

void VtableExtractor::generate_binding_map() {
  switch (binary.format()) {
    case LIEF::FORMAT_MACHO: {
      const auto binary_macho = dynamic_cast<LIEF::MachO::Binary *>(&binary);
      const auto dyld_info = binary_macho->dyld_info();

      for (const auto &binding_info : dyld_info->bindings()) {
        binding_map[binding_info.address()] = *binding_info.symbol();
      };
      break;
    };

    default: {
      throw StringError("Unknown binary format: {}", binary.format());
      break;
    };
  };
};

std::string VtableExtractor::get_typeinfo_name(uint64_t addr) {
  switch (binary.format()) {
    case LIEF::FORMAT_MACHO: {
      const auto binary_macho = dynamic_cast<LIEF::MachO::Binary *>(&binary);
      const auto section = binary_macho->section_from_virtual_address(addr);
      const auto section_content = section->content().data();
      const auto string_content_unconverted =
          &(section_content[addr - section->virtual_address()]);

      return std::string(
          reinterpret_cast<const char *>(string_content_unconverted));
      break;
    }

    default: {
      throw StringError("Unknown binary format: {}", binary.format());
      break;
    }
  };
};
VtableExtractor::typeinfo_t VtableExtractor::parse_typeinfo(uint64_t addr) {
  typeinfo_t typeinfo{};

  auto typeinfo_type = binding_map[addr].name();
  if (typeinfo_type == "") {
    throw StringError(fmt::format(
        "There should be a typeinfo class symbol here. Address is {:08X}",
        addr));
  }

  auto class_name =
      get_typeinfo_name(get_ptr_at_offset(addr + pointer_size_for_binary));
  auto typeinfo_classinfo_name = fixup_symbol_name(typeinfo_type);

  typeinfo.name = class_name;

  if (typeinfo_classinfo_name.find("__si_class_type_info") !=
      std::string::npos) {
    typeinfo.typeinfo_type = typeinfo_t::SI_CLASS_TYPE_INFO;
  } else if (typeinfo_classinfo_name.find("__vmi_class_type_info") !=
             std::string::npos) {
    typeinfo.typeinfo_type = typeinfo_t::VMI_CLASS_TYPE_INFO;
  } else {
    typeinfo.typeinfo_type = typeinfo_t::CLASS_TYPE_INFO;
  }

  switch (typeinfo.typeinfo_type) {
    case typeinfo_t::SI_CLASS_TYPE_INFO: {
      auto typeinfo_addr =
          get_ptr_at_offset(addr + (2 * pointer_size_for_binary));

      if (typeinfo_addr != 0) {
        auto base_typeinfo = parse_typeinfo(typeinfo_addr);
        typeinfo.si_class_ti.base_class =
            std::make_shared<typeinfo_t>(base_typeinfo);
      };
      break;
    };

    case typeinfo_t::VMI_CLASS_TYPE_INFO: {
      auto flags =
          get_data_at_offset<uint32_t>(addr + (2 * pointer_size_for_binary));
      auto base_count =
          get_data_at_offset<uint32_t>(addr + (3 * pointer_size_for_binary));

      for (uint32_t i = 0; i < base_count; i++) {
        typeinfo_t::vmi_class_type_info::vmi_base_class_t base_class_info{};
        try {
          // It could be located in a different lib, we will catch the error in
          // this case.
          auto base_class = parse_typeinfo(get_ptr_at_offset(
              addr + ((4 + (i * 2)) * pointer_size_for_binary)));

          base_class_info.base_class = std::make_shared<typeinfo_t>(base_class);
        } catch (std::exception &e) {
          base_class_info.base_class = nullptr;
        };

        // FIXME: This isn't compatible with X86-64 because this assumes that
        // long is 32bits wide, but im lazy
        auto offset_flags = get_data_at_offset<uint32_t>(
            addr + ((5 + (i * 2)) * pointer_size_for_binary));
        auto offset_offset = get_data_at_offset<int32_t>(
            addr + ((5 + (i * 2)) * pointer_size_for_binary));

        // Lower octet is flags
        base_class_info.offset_flags.flags = offset_flags & 0xff;
        // Rest is offset
        base_class_info.offset_flags.offset = offset_offset >> 8;

        typeinfo.vmi_class_ti.base_classes_info.emplace_back(base_class_info);
      }

      typeinfo.vmi_class_ti.flags = flags;
      typeinfo.vmi_class_ti.base_count = base_count;
      break /* a leg */;
    };

    default: {
      break;
    };
  };

  return typeinfo;
};

std::pair<std::vector<VtableExtractor::vtable_member_t>, bool>
VtableExtractor::get_methods_of_vftable(uint64_t vftable_addr) {
  // fmt::print(" ... {:08X}\n", vftable_addr);

  std::vector<VtableExtractor::vtable_member_t> members{};
  bool should_we_continue = false;

  auto current_loop_addr = vftable_addr;
  while (true) {
    auto data_at_offset = get_ptr_at_offset(current_loop_addr);

    // Another vtable has most likely started
    if (symbol_map.contains(current_loop_addr)) {
      // fmt::print("Skipping because of symbol {}",
      // symbol_map[vtable_addr].name());
      should_we_continue = false;
      break;
    };

    auto symbol = symbol_map[data_at_offset].name();

    // Could be a __cxa_pure_virtual binding, or just padding.
    if (data_at_offset == 0) {
      if (binding_map.contains(current_loop_addr)) {
        symbol = binding_map[current_loop_addr].name();
      } else {
        should_we_continue = true;
        break;
      };
    };

    // Could be a relocated weird magic thingy so there hopefully wont be symbol
    // FIXME!
    if (symbol.empty()) {
      should_we_continue = true;
      break;
    };

    current_loop_addr += pointer_size_for_binary;

    vtable_member_t member{.name = fixup_symbol_name(symbol)};
    members.emplace_back(member);
  };

  return std::pair(members, should_we_continue);
};

std::pair<uint64_t, uint64_t> VtableExtractor::find_typeinfo(uint64_t addr) {
  // Handle offset-to-X ptrs in classes with X-in-Y vtables;
  // This var is used to fixup the vtable offset.
  int vtable_location = addr + pointer_size_for_binary;
  auto typeinfo_addr = 0;
  while (true) {
    // TODO: fix a terrible edge case
    // Basically avoid a case where we misread typeinfo as a part of the
    // vftables because of padding fucking with the checks
    if (symbol_map.contains(vtable_location)) {
      throw StringError(fmt::format("Stupid fucking edge case happened at {}",
                                    vtable_location));
    };

    typeinfo_addr = get_ptr_at_offset(vtable_location);
    vtable_location += pointer_size_for_binary;

    if (symbol_map.contains(typeinfo_addr) &&
        !symbol_map[typeinfo_addr].name().empty() &&
        fixup_symbol_name(symbol_map[typeinfo_addr].name())
            .starts_with("_ZTI")) {
      break;
    }
  }

  return std::pair(typeinfo_addr, vtable_location);
};

bool VtableExtractor::is_there_a_vmi_in_typeinfo_graph(
    VtableExtractor::typeinfo_t *typeinfo) {
  if (typeinfo == nullptr) {
    return false;
  };

  if (typeinfo->typeinfo_type ==
      VtableExtractor::typeinfo_t::VMI_CLASS_TYPE_INFO) {
    return true;
  } else if (typeinfo->typeinfo_type ==
             VtableExtractor::typeinfo_t::SI_CLASS_TYPE_INFO) {
    return is_there_a_vmi_in_typeinfo_graph(
        typeinfo->si_class_ti.base_class.get());
  };

  return false;
};
VtableExtractor::vtable_data_t VtableExtractor::get_vtable(uint64_t addr) {
  std::map<uint64_t, vtable_member_t> vtable_members{};

  auto typeinfo_location = find_typeinfo(addr);
  auto typeinfo_addr = typeinfo_location.first;
  auto vftable_location = typeinfo_location.second;
  auto typeinfo = parse_typeinfo(typeinfo_addr);
  // fmt::print("typeinfo is at: {:08X}", typeinfo_addr);
  std::vector<std::vector<vtable_member_t>> vftables{};

  const auto vftable_primary_methods = get_methods_of_vftable(vftable_location);
  vftables.emplace_back(vftable_primary_methods.first);

  uint64_t current_loop_addr =
      vftable_location +
      (vftable_primary_methods.first.size() * pointer_size_for_binary);
  bool should_we_continue{vftable_primary_methods.second &&
                          is_there_a_vmi_in_typeinfo_graph(&typeinfo)};

  while (should_we_continue) {
    // fmt::print("DBG: {:08X} {:08X} {}\n", addr, current_loop_addr,
    //            should_we_continue);
    try {
      auto typeinfo_location = find_typeinfo(current_loop_addr);
      auto vftable_location = typeinfo_location.second;
      const auto vftable_methods = get_methods_of_vftable(vftable_location);

      vftables.emplace_back(vftable_methods.first);
      current_loop_addr = vftable_location + (vftable_methods.first.size() *
                                              pointer_size_for_binary);
      should_we_continue = vftable_methods.second;
    } catch (std::exception &_) {
      should_we_continue = false;
    };
  };

  return {
      .typeinfo = typeinfo,
      .addr = addr,
      .pointer_size = pointer_size_for_binary,
      .vftables = vftables,
  };
};

std::vector<VtableExtractor::vtable_data_t> VtableExtractor::get_vtables() {
  std::vector<VtableExtractor::vtable_data_t> vtables{};

  for (const auto &[addr, symbol] : symbol_map) {
    const auto name = fixup_symbol_name(symbol.name());

    if (name.starts_with("_ZTV")) {
      auto vtable_data = get_vtable(addr);
      vtables.emplace_back(vtable_data);
    };
  };
  return vtables;
};

VtableExtractor::VtableExtractor(LIEF::Binary &binary) : binary(binary) {
  pointer_size_for_binary = get_pointer_size_for_bin();

  generate_symbol_map();
  generate_binding_map();
};
