#include <LIEF/LIEF.hpp>
#include <stdint.h>

class VtableExtractor {
public:
  VtableExtractor(LIEF::Binary &binary);
  struct vtable_member_t {
    LIEF::Symbol symbol;
    std::string fixed_name;
  };
  struct vtable_data_t {
    std::string name{};
    uint64_t addr;

    int pointer_size;
    int vtable_num_of_methods;
    std::map<uint64_t, vtable_member_t> vtable_members;
  };

  std::vector<vtable_data_t> get_vtables();

private:
  int get_pointer_size_for_bin();
  uint64_t get_pointer_data_at_offset(uint64_t virtual_addr);
  std::string fixup_symbol_name(LIEF::Symbol symbol);
  void generate_symbol_map();
  vtable_data_t get_vtable(uint64_t addr);

  std::map<uint64_t, LIEF::Symbol> symbol_map;
  LIEF::Binary &binary;
  int pointer_size_for_binary;
};
