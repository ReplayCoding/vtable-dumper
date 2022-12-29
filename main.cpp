#include "vtableextractor.hpp"
#include <LIEF/LIEF.hpp>
#include <fmt/core.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

json generate_json_from_typeinfo(const VtableExtractor::typeinfo_t typeinfo) {
  json typeinfo_obj;
  typeinfo_obj["name"] = typeinfo.name;
  typeinfo_obj["type"] = typeinfo_type_lookup[typeinfo.typeinfo_type];

  switch (typeinfo.typeinfo_type) {
    case VtableExtractor::typeinfo_t::CLASS_TYPE_INFO:
      break;
    case VtableExtractor::typeinfo_t::SI_CLASS_TYPE_INFO: {
      const auto base_class = typeinfo.si_class_ti.base_class;
      if (base_class != nullptr) {
        typeinfo_obj["base_class"] = generate_json_from_typeinfo(*base_class);
      };
      break;
    };
    case VtableExtractor::typeinfo_t::VMI_CLASS_TYPE_INFO: {
      const auto vmi_class_ti = typeinfo.vmi_class_ti;
      typeinfo_obj["flags"] = vmi_class_ti.flags;
      typeinfo_obj["base_count"] = vmi_class_ti.base_count;

      json base_classes_obj = json::array();
      for (const auto &base_class_info : vmi_class_ti.base_classes_info) {
        json base_class_obj;
        base_class_obj["flags"] = base_class_info.offset_flags.flags;
        base_class_obj["offset"] = base_class_info.offset_flags.offset;

        const auto base_class = base_class_info.base_class;
        if (base_class != nullptr) {
          base_class_obj["base_class"] =
              generate_json_from_typeinfo(*base_class);
        };
        base_classes_obj.emplace_back(base_class_obj);
      };
      typeinfo_obj["base_classes"] = base_classes_obj;
      break;
    };
  };
  return typeinfo_obj;
};

json generate_json_output(
    std::vector<VtableExtractor::vtable_data_t> &vtables) {
  json vtables_array = json::array();
  for (const auto &vtable : vtables) {
    json vtable_obj;
    vtable_obj["address"] = vtable.addr;
    vtable_obj["pointer_size"] = vtable.pointer_size;
    vtable_obj["typeinfo"] = generate_json_from_typeinfo(vtable.typeinfo);

    json vftables_obj = json::array();
    for (const auto &vftable : vtable.vftables) {
      json vftable_obj = json::array();
      for (const auto &member : vftable) {
        vftable_obj.emplace_back(member.name);
      };
      vftables_obj.emplace_back(vftable_obj);
    };
    vtable_obj["vftables"] = vftables_obj;
    vtables_array.emplace_back(vtable_obj);
  }
  return vtables_array;
};

void cli_print_typeinfo(const VtableExtractor::typeinfo_t &typeinfo,
                        std::string prefix) {
  fmt::print(prefix + "type: {}\n",
             typeinfo_type_lookup[typeinfo.typeinfo_type]);
  fmt::print(prefix + "name: {}\n", "_Z" + typeinfo.name);
  switch (typeinfo.typeinfo_type) {
    case VtableExtractor::typeinfo_t::SI_CLASS_TYPE_INFO: {
      if (typeinfo.si_class_ti.base_class) {
        cli_print_typeinfo(*typeinfo.si_class_ti.base_class, prefix + "\t");
      };
      break;
    };
    case VtableExtractor::typeinfo_t::VMI_CLASS_TYPE_INFO: {
      fmt::print(prefix + "flags: {:08X}\n", typeinfo.vmi_class_ti.flags);
      fmt::print(prefix + "base_count: {}\n", typeinfo.vmi_class_ti.base_count);
      for (auto &vmi_base_class : typeinfo.vmi_class_ti.base_classes_info) {
        fmt::print(prefix + "\t" + "offset: {}\n",
                   vmi_base_class.offset_flags.offset);
        fmt::print(prefix + "\t" + "flags: {:X}\n",
                   vmi_base_class.offset_flags.flags);
        if (vmi_base_class.base_class) {
          cli_print_typeinfo(*vmi_base_class.base_class, prefix + "\t");
        };
        fmt::print(prefix + "\t\n");
      };
      break;
    }
    default:
      break;
  };
};

std::string eighty_cols =
    "-----------------------------------------------------------"
    "---------------------";

void generate_cli_output(std::vector<VtableExtractor::vtable_data_t> &vtables) {
  for (const auto &vtable : vtables) {
    fmt::print("{} = {:#08x}\n", "_Z" + vtable.typeinfo.name, vtable.addr);

    fmt::print("\ttypeinfo:\n");
    cli_print_typeinfo(vtable.typeinfo, "\t\t");

    fmt::print("\tnumber of vftables: {}\n", vtable.vftables.size());
    for (const auto &vftable : vtable.vftables) {
      fmt::print(eighty_cols + " VFTABLE \n");
      for (size_t i = 0; i < vftable.size(); i++) {
        auto member = vftable[i];
        fmt::print("\t{} is at offset {:X} (member# {})\n", member.name,
                   i * vtable.pointer_size, i);
      };
    };
    fmt::print("\n\n" + eighty_cols + " NEXT VTABLE \n\n");
  }
};

int main(int argc, const char **argv) {
  if (argc != 2) {
    fmt::print("usage: {} <binary>\n", argv[0]);
    return 1;
  };
  auto binary = LIEF::Parser::parse(argv[1]);
  auto vtables = VtableExtractor(*binary).get_vtables();
  // std::cout << generate_json_output(vtables);
  generate_cli_output(vtables);
};
