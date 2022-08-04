#include "vtableextractor.hpp"
#include <LIEF/LIEF.hpp>
#include <fmt/core.h>

void print_typeinfo(VtableExtractor::typeinfo_t typeinfo, std::string prefix) {
  fmt::print(prefix + "type: {}\n",
             typeinfo_type_lookup[typeinfo.typeinfo_type]);
  fmt::print(prefix + "name: {}\n", typeinfo.name);
  switch (typeinfo.typeinfo_type) {
    case VtableExtractor::typeinfo_t::SI_CLASS_TYPE_INFO: {
      if (typeinfo.si_class_ti.base_class) {
        print_typeinfo(*typeinfo.si_class_ti.base_class, prefix + "\t");
      };
      break;
    };
    case VtableExtractor::typeinfo_t::VMI_CLASS_TYPE_INFO: {
      fmt::print(prefix + "flags: {:08X}\n", typeinfo.vmi_class_ti.flags);
      fmt::print(prefix + "base_count: {}\n", typeinfo.vmi_class_ti.base_count);
      for (auto &vmi_base_class : typeinfo.vmi_class_ti.base_class_info) {
        fmt::print(prefix + "\t" + "offset flags: {:08X}\n",
                   vmi_base_class.offset_flags);
        if (vmi_base_class.base_class) {
          print_typeinfo(*vmi_base_class.base_class, prefix + "\t");
        };
        fmt::print(prefix + "\t\n");
      };
      break;
    }
    default:
      break;
  };
};

int main(int argc, const char **argv) {
  if (argc != 2) {
    fmt::print("usage: {} <binary>\n", argv[0]);
    return 1;
  };
  auto binary = LIEF::Parser::parse(argv[1]);
  auto vtables = VtableExtractor(*binary).get_vtables();

  for (auto vtable : vtables) {
    fmt::print("{} = {:#08x}\n", vtable.typeinfo.name, vtable.addr);

    fmt::print("\ttypeinfo:\n");
    print_typeinfo(vtable.typeinfo, "\t\t");

    fmt::print("\tnumber of vtable methods: {}\n",
               vtable.vtable_num_of_methods);
    for (const auto &[offset, member] : vtable.vtable_members) {
      fmt::print("\t{} is at offset {} (member# {})\n", member.name, offset,
                 offset / vtable.pointer_size);
    };
  }
};
