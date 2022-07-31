#include <LIEF/LIEF.hpp>
#include <memory>
#include <stdint.h>

static std::array<std::string, 3> typeinfo_type_lookup = {
    "CLASS_TYPE_INFO", "SI_CLASS_TYPE_INFO", "VMI_CLASS_TYPE_INFO"};
class StringError;
class VtableExtractor {
public:
  VtableExtractor(LIEF::Binary &binary);
  struct typeinfo_t {
    typeinfo_t(){};
    ~typeinfo_t(){};

    enum typeinfo_type_t {
      CLASS_TYPE_INFO = 0,
      SI_CLASS_TYPE_INFO,
      VMI_CLASS_TYPE_INFO,
    } typeinfo_type;
    std::string name;

    // __si_class_type_info
    std::shared_ptr<typeinfo_t> base_type;

    // __vmi_class_type_info
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

class StringError : public std::exception {
public:
  StringError(std::string s) : s(s){};
  virtual const char *what() const noexcept override { return s.c_str(); };

private:
  std::string s;
};
