#include <LIEF/LIEF.hpp>
#include <memory>
#include <stdint.h>

class VtableExtractor {
public:
  VtableExtractor(LIEF::Binary &binary);
  struct typeinfo_t {
    typeinfo_t() = default;
    ~typeinfo_t(){};

    std::string typeinfo_type;
    std::string name;

    std::shared_ptr<typeinfo_t> base_type;
  };
  struct vtable_member_t {
    LIEF::Symbol symbol;
    std::string fixed_name;
  };
  struct vtable_data_t {
    std::string name{};
    typeinfo_t typeinfo{};
    uint64_t addr;

    int pointer_size;
    int vtable_num_of_methods;
    std::map<uint64_t, vtable_member_t> vtable_members;
  };

  std::vector<vtable_data_t> get_vtables();

private:
  int get_pointer_size_for_bin();
  uint64_t get_pointer_data_at_offset(uint64_t virtual_addr);
  std::string fixup_symbol_name(std::string name);
  void generate_symbol_map();
  std::string get_typeinfo_name(uint64_t name);
  typeinfo_t parse_typeinfo(uint64_t addr);
  vtable_data_t get_vtable(uint64_t addr);

  std::map<uint64_t, LIEF::Symbol> symbol_map;
  LIEF::Binary &binary;
  int pointer_size_for_binary;
};
