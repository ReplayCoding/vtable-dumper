from binaryninja import *
from copy import deepcopy
import json

def build_type_from_vtable(view, vtable, ti_ptr_type):
    mangled_name = "_Z" + vtable["typeinfo"]["name"]
    _, name = demangle_gnu3(view.arch, mangled_name)

    with StructureBuilder.builder(view, name) as sb:
        vt_name = deepcopy(name)
        if isinstance(vt_name, list):
            vt_name[-1] = "vtable_for_" + vt_name[-1]
        else:
            vt_name = "vtable_for_" + vt_name
        with StructureBuilder.builder(view, vt_name) as vb:

            vb.append(ti_ptr_type, "rtti")
            for func in vtable["vftables"][0]:
                # TODO: Add `this` to the function prototype, it's kind of useless without this
                ftype, fname = demangle_gnu3(view.arch, func)
                # Fallback, binja doesn't support getting types from non-virtual thunks
                if ftype == None:
                    ftype = Type.void()

                var_name = fname
                if isinstance(fname, list):
                    var_name = fname[-1]

                vb.append(Type.pointer(view.arch, ftype), var_name)
                # print(ftype, fname)

            # vtable pointers go past typeinfo
            vb.pointer_offset = ti_ptr_type.width

            vb_ref = NamedTypeReferenceType.create_from_type(vt_name, vb)
            sb.append(Type.pointer(view.arch, vb_ref), "vtable")


def import_vtables(view):
    fname = get_open_filename_input("filename:", "*.json")
    if fname == None:
        return
    file = open(fname, "rb")
    vtables = json.load(file)

    state = view.begin_undo_actions()
    try: 
        with StructureBuilder.builder(view, "typeinfo_ptr") as ti_ptr_type:
            ti_ptr_type.append(Type.int(4), "offset_to_top")
            ti_ptr_type.append(Type.pointer(view.arch, Type.void()), "typeinfo")

            ti_ptr_ref = NamedTypeReferenceType.create_from_type("typeinfo_ptr", ti_ptr_type)

            for vtable in vtables["vtables"]:
                build_type_from_vtable(view, vtable, ti_ptr_ref)

        view.commit_undo_actions(state)
    except Exception as e:
        view.revert_undo_actions(state)
        raise e

PluginCommand.register("Import VTables", "", import_vtables)
