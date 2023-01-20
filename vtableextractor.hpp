#include "error.hpp"
#include <LIEF/LIEF.hpp>
#include <fmt/core.h>
#include <memory>
#include <stdint.h>
#include <string_view>
#include <variant>

struct Typeinfo {
  struct class_type_info {};

  struct si_class_type_info {
    std::shared_ptr<Typeinfo> base_class;
  };

  struct vmi_class_type_info {
    struct vmi_base_class_t {
      std::shared_ptr<Typeinfo> base_class;
      // I'm not completely sure if this is signed or not but thats what the
      // docs say sooooo
      struct {
        uint8_t flags;
        int64_t offset;
      } offset_flags;
    };
    uint32_t flags;
    uint32_t base_count;
    std::vector<vmi_base_class_t> base_classes_info{};
  };

  std::string name;
  std::variant<class_type_info, si_class_type_info, vmi_class_type_info> ti;
};

struct VtableMember {
  std::string name{};
};

struct VtableData {
  Typeinfo typeinfo{};
  uint64_t addr;

  int pointer_size;
  // This is oh so dumb looking
  std::vector<std::vector<VtableMember>> vftables;
};

class VtableExtractor {
public:
  VtableExtractor(LIEF::Binary &binary);

  std::vector<VtableData> get_vtables();

private:
  void generate_symbol_map();
  void generate_binding_map();
  std::string get_typeinfo_name(uint64_t name);
  Typeinfo parse_typeinfo(uint64_t addr);
  VtableData get_vtable(uint64_t addr);
  /* number of members, should we continue? */
  std::pair<std::vector<VtableMember>, bool>
  get_methods_of_vftable(uint64_t addr);

  /* typeinfo address, vftable address (right after typeinfo ptr) */
  std::pair<uint64_t, uint64_t> find_typeinfo(uint64_t addr);
  bool is_there_a_vmi_in_typeinfo_graph(Typeinfo *typeinfo);

  std::map<uint64_t, LIEF::Symbol> symbol_map{};
  std::map<uint64_t, LIEF::Symbol> binding_map{};
  LIEF::Binary &binary;
  int pointer_size_for_binary;
};

inline std::string_view get_typeinfo_type_name(const Typeinfo &t) {
  if (std::holds_alternative<Typeinfo::class_type_info>(t.ti)) {
    return "CLASS_TYPE_INFO";
  } else if (std::holds_alternative<Typeinfo::si_class_type_info>(t.ti)) {
    return "SI_CLASS_TYPE_INFO";
  } else if (std::holds_alternative<Typeinfo::vmi_class_type_info>(t.ti)) {
    return "VMI_CLASS_TYPE_INFO";
  }

  return "UNKNOWN";
}
