#include "vtableextractor.hpp"
#include <LIEF/LIEF.hpp>
#include <fmt/core.h>
#include <fmt/color.h>

int main(int argc, const char **argv) {
  if (argc < 2)
    return 1;
  auto binary = LIEF::Parser::parse(argv[1]);
  auto vtables = VtableExtractor(*binary).get_vtables();

  for (auto vtable : vtables) {
    fmt::print("{} = {:#08x}\n", vtable.name, vtable.addr);
    fmt::print("\tnumber of vtable methods: {}\n",
               vtable.vtable_num_of_methods);
    for (const auto &[offset, member] : vtable.vtable_members) {
      std::string formatted_name = "";
      if (member.symbol.name().empty()) {
        formatted_name = fmt::format("{:#08X}", member.symbol.value());
      } else {
        formatted_name = member.fixed_name;
      };
      fmt::print("\t{} is at offset {} (member# {})\n", formatted_name, offset, offset / vtable.pointer_size);
    };
  }
};
