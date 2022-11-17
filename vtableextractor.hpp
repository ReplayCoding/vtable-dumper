#include <LIEF/LIEF.hpp>
#include <fmt/core.h>
#include <memory>
#include <stdint.h>

static std::array<std::string, 3> typeinfo_type_lookup = {
    "CLASS_TYPE_INFO", "SI_CLASS_TYPE_INFO", "VMI_CLASS_TYPE_INFO"};

class StringError : public std::exception {
public:
  StringError(const std::string &message) : message(message){};

  template <typename... T> StringError(const std::string &format, T... Args) {
    message = fmt::format(format, Args...);
  }

  const char *what() const noexcept override { return message.c_str(); };

private:
  std::string message;
};

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
    struct si_class_type_info {
      std::shared_ptr<typeinfo_t> base_class;
    } si_class_ti{};

    // __vmi_class_type_info
    struct vmi_class_type_info {
      struct vmi_base_class_t {
        std::shared_ptr<typeinfo_t> base_class;
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
    } vmi_class_ti{};
  };
  struct vtable_member_t {
    std::string name{};
  };
  struct vtable_data_t {
    typeinfo_t typeinfo{};
    uint64_t addr;

    int pointer_size;
    // This is oh so dumb looking
    std::vector<std::vector<vtable_member_t>> vftables;
  };

  std::vector<vtable_data_t> get_vtables();

private:
  int get_pointer_size_for_bin();
  std::string fixup_symbol_name(std::string name);
  void generate_symbol_map();
  void generate_binding_map();
  std::string get_typeinfo_name(uint64_t name);
  typeinfo_t parse_typeinfo(uint64_t addr);
  vtable_data_t get_vtable(uint64_t addr);
  /* number of members, should we continue? */
  std::pair<std::vector<VtableExtractor::vtable_member_t>, bool>
  get_methods_of_vftable(uint64_t addr);

  /* typeinfo address, vftable address (right after typeinfo ptr) */
  std::pair<uint64_t, uint64_t> find_typeinfo(uint64_t addr);
  bool is_there_a_vmi_in_typeinfo_graph(typeinfo_t *typeinfo);

  template <typename T> T get_data_at_offset(uint64_t virtual_addr);
  inline uint64_t get_ptr_at_offset(uint64_t virtual_addr) {
    if (pointer_size_for_binary == 4) {
      return get_data_at_offset<uint32_t>(virtual_addr);
    } else if (pointer_size_for_binary == 8) {
      return get_data_at_offset<uint64_t>(virtual_addr);
    } else {
      throw StringError("No valid pointer size for binary");
    };
  };

  std::map<uint64_t, LIEF::Symbol> symbol_map{};
  std::map<uint64_t, LIEF::Symbol> binding_map{};
  LIEF::Binary &binary;
  int pointer_size_for_binary;
};
