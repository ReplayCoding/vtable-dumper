#include "vtableextractor.hpp"
#include <LIEF/LIEF.hpp>
#include <fmt/core.h>

void print_typeinfo(VtableExtractor::typeinfo_t typeinfo, std::string prefix) {
  fmt::print(prefix + "type: {}\n",
             typeinfo_type_lookup[typeinfo.typeinfo_type]);
  fmt::print(prefix + "name: {}\n", "_Z" + typeinfo.name);
  switch (typeinfo.typeinfo_type) {
    case VtableExtractor::typeinfo_t::SI_CLASS_TYPE_INFO: {
      print_typeinfo(*typeinfo.base_type, prefix + "\t");
      break;
    };
    case VtableExtractor::typeinfo_t::VMI_CLASS_TYPE_INFO: {
      break;
    }
    case VtableExtractor::typeinfo_t::CLASS_TYPE_INFO:
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
    fmt::print("{} = {:#08x}\n", vtable.name, vtable.addr);

    fmt::print("\ttypeinfo:\n");
    print_typeinfo(vtable.typeinfo, "\t\t");

    fmt::print("\tnumber of vtable methods: {}\n",
               vtable.vtable_num_of_methods);
    for (const auto &[offset, member] : vtable.vtable_members) {
      std::string formatted_name = "";
      if (member.symbol.name().empty()) {
        formatted_name = fmt::format("{:#08X}", member.symbol.value());
      } else {
        formatted_name = member.fixed_name;
      };
      fmt::print("\t{} is at offset {} (member# {})\n", formatted_name, offset,
                 offset / vtable.pointer_size);
    };
  }
};
