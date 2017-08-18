"""
Referee creates struct xrefs for decompiled functions
"""

import idaapi


def is_assn(t):
    return (
        t == idaapi.cot_asg or
        t == idaapi.cot_asgbor or
        t == idaapi.cot_asgxor or
        t == idaapi.cot_asgband or
        t == idaapi.cot_asgsub or
        t == idaapi.cot_asgmul or
        t == idaapi.cot_asgsshr or
        t == idaapi.cot_asgushr or
        t == idaapi.cot_asgsdiv or
        t == idaapi.cot_asgudiv or
        t == idaapi.cot_asgsmod or
        t == idaapi.cot_asgumod)


def add_struct_xrefs(cfunc):
    class xref_adder_t(idaapi.ctree_visitor_t):
        def __init__(self, cfunc):
            idaapi.ctree_visitor_t.__init__(self, idaapi.CV_PARENTS)
            self.cfunc = cfunc

        def visit_expr(self, e):
            dr = idaapi.dr_R | idaapi.XREF_USER

            # We wish to know what context a struct usage occurs in
            # so we can determine what kind of xref to create. Unfortunately,
            # a post-order traversal makes this difficult.

            # For assignments, we visit the left, instead
            # Note that immediate lvalues will be visited twice,
            # and will be eronneously marked with a read dref.
            # However, it is safer to overapproximate than underapproximate
            if is_assn(e.op):
                e = e.x
                dr = idaapi.dr_W | idaapi.XREF_USER

            if e.op == idaapi.cot_ref:
                e = e.x
                dr = idaapi.dr_O | idaapi.XREF_USER

            if e.op == idaapi.cot_memref or e.op == idaapi.cot_memptr:
                moff = e.m

                # The only way I could figure out how
                # to get the structure/member assocaited with its use
                typ = e.x.type

                if e.op == idaapi.cot_memptr:
                    typ.remove_ptr_or_array()

                
                strname = typ.dstr()
                if strname.startswith("struct "):
                    strname = strname[len("struct "):]
                stid  = idaapi.get_struc_id(strname)
                s = idaapi.get_struc(stid)
                mem = idaapi.get_member(s, moff)
                if e.ea != idaapi.BADADDR:
                    ea = e.ea
                else:
                    parent = e
                    while True:
                        parent = self.cfunc.body.find_parent_of(parent)
                        if parent is None:
                            ea = self.cfunc.entry_ea
                            break
                        if parent.ea != idaapi.BADADDR:
                            ea = parent.ea
                            break


                if s:
                    idaapi.add_dref(ea, stid, idaapi.dr_R | idaapi.XREF_USER)
                    idaapi.msg(
                            "Referee add_dref in 0x{:X} on struct {} (id: 0x{:X})\n".format(
                                ea, strname, stid))
                    if mem:
                        idaapi.add_dref(ea, mem.id, dr)
                        idaapi.msg(
                                "Referee add_dref in 0x{:X} on struct member {}.{} (id: 0x{:X})\n".format(
                                    ea, strname, idaapi.get_member_name(mem.id), mem.id))
                else:
                    idaapi.msg(
                            "Referee failure in 0x{:X} on struct {} (id: 0x{:X})\n".format(
                                ea, strname, stid))

                    
            return 0
    adder = xref_adder_t(cfunc)
    adder.apply_to_exprs(cfunc.body, None)


def clear_struct_xrefs(cfunc):
    xb = idaapi.xrefblk_t()
    ok = xb.first_from(cfunc.entry_ea, idaapi.XREF_DATA)
    while ok:
        if xb.user == 1:
            idaapi.del_dref(cfunc.entry_ea, xb.to)
        ok = xb.next_from()

def callback(*args):
    if args[0] == idaapi.hxe_maturity:
        cfunc = args[1]
        mat = args[2]
        if mat == idaapi.CMAT_FINAL:
            idaapi.msg("Referee analyzing function at 0x{:X}\n".format(cfunc.entry_ea))
            clear_struct_xrefs(cfunc)
            add_struct_xrefs(cfunc)
    return 0


class Referee(idaapi.plugin_t):
    flags = idaapi.PLUGIN_HIDE
    comment = "Adds struct xref info from decompilation"
    help = ""
    
    wanted_name = "Referee"
    wanted_hotkey = ""

    def init(self):
        if not idaapi.init_hexrays_plugin():
            return idaapi.PLUGIN_SKIP

        idaapi.install_hexrays_callback(callback)
        idaapi.msg(
                "Hex-Rays version {0} has been detected; {1} is ready to use\n".format(
                    idaapi.get_hexrays_version(), self.wanted_name))
        self.inited = True
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        if self.inited:
            idaapi.remove_hexrays_callback(callback)
            idaapi.term_hexrays_plugin()


def PLUGIN_ENTRY():
    return Referee()
