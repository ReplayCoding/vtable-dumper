#include "vtableextractor.hpp"
#include "error.hpp"
#include <bit>
#include <cstdint>
#include <fmt/core.h>
#include <optional>
#include <variant>

uint8_t get_pointer_size_for_bin(const LIEF::Binary *binary) {
  if (binary->header().is_32()) {
    return 4;
  } else if (binary->header().is_64()) {
    return 8;
  } else {
    throw StringError("Cant figure out valid pointer size");
  };
};

template <typename T>
T get_data_at_offset(const LIEF::Binary *binary, uint64_t virtual_addr) {
  auto bytes_at_mem =
      binary->get_content_from_virtual_address(virtual_addr, sizeof(T));
  T unswapped_data = {};

  std::memcpy(&unswapped_data, bytes_at_mem.data(), sizeof(T));
  return unswapped_data;
};

inline uint64_t get_ptr_at_offset(const LIEF::Binary *binary,
                                  uint64_t virtual_addr) {
  auto pointer_size_for_binary = get_pointer_size_for_bin(binary);
  if (pointer_size_for_binary == 4) {
    return get_data_at_offset<uint32_t>(binary, virtual_addr);
  } else if (pointer_size_for_binary == 8) {
    return get_data_at_offset<uint64_t>(binary, virtual_addr);
  } else {
    throw StringError("No valid pointer size for binary");
  };
};

std::string fixup_symbol_name(const LIEF::Binary *binary, std::string name) {
  if (binary->format() == LIEF::EXE_FORMATS::FORMAT_MACHO &&
      (!name.empty() && name.front() == '_')) {
    // Remove the leading underscore, as per
    // https://developer.apple.com/library/archive/documentation/DeveloperTools/Conceptual/MachOTopics/1-Articles/executing_files.html
    name.erase(0, 1);
  }

  return name;
};

std::string VtableExtractor::get_typeinfo_name(uint64_t addr) {
  switch (binary->format()) {
    case LIEF::FORMAT_MACHO: {
      const auto binary_macho =
          dynamic_cast<LIEF::MachO::Binary *>(binary.get());
      const auto section = binary_macho->section_from_virtual_address(addr);
      const auto section_content = section->content().data();
      return std::string(reinterpret_cast<const char *>(
          &(section_content[addr - section->virtual_address()])));
      break;
    }

    default: {
      throw StringError("Unknown binary format: {}", binary->format());
      break;
    }
  };
};

Typeinfo VtableExtractor::parse_typeinfo(uint64_t addr) {
  Typeinfo typeinfo{};

  auto typeinfo_type = binding_map.at(addr).name();
  if (typeinfo_type == "") {
    throw StringError(
        "There should be a typeinfo class symbol here. Address is {:08X}",
        addr);
  }

  typeinfo.name =
      get_typeinfo_name(get_ptr_at_offset(binary.get(), addr + pointer_size));
  auto typeinfo_classinfo_name = fixup_symbol_name(binary.get(), typeinfo_type);

  if (typeinfo_classinfo_name.ends_with("__si_class_type_infoE")) {
    auto typeinfo_addr =
        get_ptr_at_offset(binary.get(), addr + (2 * pointer_size));

    if (typeinfo_addr != 0) {
      auto base_typeinfo = parse_typeinfo(typeinfo_addr);
      typeinfo.ti = Typeinfo::si_class_type_info{
          .base_class = std::make_shared<Typeinfo>(base_typeinfo)};
    };
  } else if (typeinfo_classinfo_name.ends_with("__vmi_class_type_infoE")) {
    auto flags =
        get_data_at_offset<uint32_t>(binary.get(), addr + (2 * pointer_size));
    auto base_count =
        get_data_at_offset<uint32_t>(binary.get(), addr + (3 * pointer_size));

    std::vector<Typeinfo::vmi_class_type_info::vmi_base_class_t>
        base_classes_info{};
    for (uint32_t i = 0; i < base_count; i++) {
      Typeinfo::vmi_class_type_info::vmi_base_class_t base_class_info{};
      try {
        // It could be located in a different lib, we will catch the error in
        // this case.
        auto base_class = parse_typeinfo(get_ptr_at_offset(
            binary.get(), addr + ((4 + (i * 2)) * pointer_size)));

        base_class_info.base_class = std::make_shared<Typeinfo>(base_class);
      } catch (std::exception &e) {
        base_class_info.base_class = nullptr;
      };

      // FIXME: This isn't compatible with X86-64 because this assumes that
      // long is 32bits wide, but im lazy
      auto offset = get_data_at_offset<int32_t>(
          binary.get(), addr + ((5 + (i * 2)) * pointer_size));

      // Lower octet is flags
      base_class_info.offset_flags.flags = offset & 0xff;
      // Rest is offset
      base_class_info.offset_flags.offset = offset >> 8;

      base_classes_info.emplace_back(base_class_info);
    }

    typeinfo.ti =
        Typeinfo::vmi_class_type_info{.flags = flags,
                                      .base_count = base_count,
                                      .base_classes_info = base_classes_info};
  } else if (typeinfo_classinfo_name.ends_with("__class_type_infoE")) {
    // class_type_info
    typeinfo.ti = Typeinfo::class_type_info{};
  } else {
    throw StringError("Unknown RTTI type: {}", typeinfo_classinfo_name);
  }

  return typeinfo;
};

std::pair<std::vector<VtableMember>, bool>
VtableExtractor::get_methods_of_vftable(uint64_t vftable_addr) {
  // fmt::print(" ... {:08X}\n", vftable_addr);

  std::vector<VtableMember> members{};
  bool should_we_continue = false;

  auto current_loop_addr = vftable_addr;
  while (true) {
    auto data_at_offset = get_ptr_at_offset(binary.get(), current_loop_addr);

    // Another vtable has most likely started
    if (symbol_map.contains(current_loop_addr)) {
      // fmt::print("Skipping because of symbol {}",
      // symbol_map.at(vtable_addr).name());
      should_we_continue = false;
      break;
    };

    std::optional<std::string> symbol = std::nullopt;
    if (symbol_map.contains(data_at_offset)) {
      auto symbol_temp = symbol_map.at(data_at_offset).name();
      // HACK HACK HACK!
      if (symbol_temp != "dyld_stub_binder")
        symbol = symbol_temp;
    }

    if (!symbol) {
      // Could be a __cxa_pure_virtual binding, or just padding.
      if (binding_map.contains(current_loop_addr)) {
        symbol = binding_map.at(current_loop_addr).name();
      } else {
        should_we_continue = true;
        break;
      };
    };

    if (symbol) {
      current_loop_addr += pointer_size;

      VtableMember member{.name =
                              fixup_symbol_name(binary.get(), symbol.value())};
      members.emplace_back(member);
    } else {
      should_we_continue = true;
      break;
    };
  };

  return std::pair(members, should_we_continue);
};

std::pair<uint64_t, uint64_t> VtableExtractor::find_typeinfo(uint64_t addr) {
  // Handle offset-to-X ptrs in classes with X-in-Y vtables;
  // This var is used to fixup the vtable offset.
  int vtable_location = addr + pointer_size;
  auto typeinfo_addr = 0;
  while (true) {
    // TODO: fix a terrible edge case
    // Basically avoid a case where we misread typeinfo as a part of the
    // vftables because of padding fucking with the checks
    if (symbol_map.contains(vtable_location)) {
      throw StringError("Stupid fucking edge case happened at {}",
                        vtable_location);
    };

    typeinfo_addr = get_ptr_at_offset(binary.get(), vtable_location);
    vtable_location += pointer_size;

    if (symbol_map.contains(typeinfo_addr) &&
        !symbol_map.at(typeinfo_addr).name().empty() &&
        fixup_symbol_name(binary.get(), symbol_map.at(typeinfo_addr).name())
            .starts_with("_ZTI")) {
      break;
    }
  }

  return std::pair(typeinfo_addr, vtable_location);
};

bool VtableExtractor::is_there_a_vmi_in_typeinfo_graph(Typeinfo *typeinfo) {
  if (typeinfo == nullptr) {
    return false;
  };

  if (std::holds_alternative<Typeinfo::vmi_class_type_info>(typeinfo->ti)) {
    return true;
  } else if (auto ti =
                 std::get_if<Typeinfo::si_class_type_info>(&typeinfo->ti)) {
    return is_there_a_vmi_in_typeinfo_graph(ti->base_class.get());
  };

  return false;
};

VtableData VtableExtractor::get_vtable(uint64_t addr) {
  std::map<uint64_t, VtableMember> vtable_members{};

  auto [typeinfo_addr, vftable_location] = find_typeinfo(addr);
  auto typeinfo = parse_typeinfo(typeinfo_addr);
  // fmt::print("typeinfo is at: {:08X}", typeinfo_addr);
  std::vector<std::vector<VtableMember>> vftables{};

  const auto [vftable_primary_methods, do_continue] =
      get_methods_of_vftable(vftable_location);
  vftables.emplace_back(vftable_primary_methods);

  uint64_t current_loop_addr =
      vftable_location + (vftable_primary_methods.size() * pointer_size);
  bool should_we_continue{do_continue &&
                          is_there_a_vmi_in_typeinfo_graph(&typeinfo)};

  while (should_we_continue) {
    // fmt::print("DBG: {:08X} {:08X} {}\n", addr, current_loop_addr,
    //            should_we_continue);
    try {
      const auto [_, vftable_location] = find_typeinfo(current_loop_addr);
      const auto [vftable_methods, do_continue] =
          get_methods_of_vftable(vftable_location);

      vftables.emplace_back(vftable_methods);
      current_loop_addr =
          vftable_location + (vftable_methods.size() * pointer_size);
      should_we_continue = do_continue;
    } catch (std::exception &_) {
      should_we_continue = false;
    };
  };

  return {
      .typeinfo = typeinfo,
      .addr = addr,
      .vftables = vftables,
  };
};

std::vector<VtableData> VtableExtractor::get_vtables() {
  std::vector<VtableData> vtables{};

  for (const auto &[addr, symbol] : symbol_map) {
    const auto name = fixup_symbol_name(binary.get(), symbol.name());

    if (name.starts_with("_ZTV")) {
      auto vtable_data = get_vtable(addr);
      vtables.emplace_back(vtable_data);
    };
  };
  return vtables;
};

void VtableExtractor::generate_symbol_map() {
  for (const auto &symbol : binary->symbols()) {
    const auto virtual_addr = binary->offset_to_virtual_address(symbol.value());

    symbol_map[virtual_addr] = symbol;
  };
};

void VtableExtractor::generate_binding_map() {
  switch (binary->format()) {
    case LIEF::FORMAT_MACHO: {
      const auto binary_macho =
          dynamic_cast<LIEF::MachO::Binary *>(binary.get());
      const auto dyld_info = binary_macho->dyld_info();

      if (dyld_info == nullptr)
        throw StringError("No dyld info, can't get bindings");

      for (const auto &binding_info : dyld_info->bindings()) {
        binding_map[binding_info.address()] = *binding_info.symbol();
      };
      break;
    };

    default: {
      throw StringError("Unknown binary format: {}", binary->format());
      break;
    };
  };
};

VtableExtractor::VtableExtractor(std::unique_ptr<LIEF::Binary> binary)
    : binary(std::move(binary)) {
  pointer_size = get_pointer_size_for_bin(this->binary.get());

  generate_symbol_map();
  generate_binding_map();
};
