"""
Referee creates struct xrefs for decompiled functions
"""
import logging

import idaapi

# logging.basicConfig(level=logging.WARN)
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger("referee")


es = []


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

        def find_addr(self, e):
            if e.ea != idaapi.BADADDR:
                ea = e.ea
            else:
                while True:
                    e = self.cfunc.body.find_parent_of(e)
                    if e is None:
                        ea = self.cfunc.entry_ea
                        break
                    if e.ea != idaapi.BADADDR:
                        ea = e.ea
                        break
            return ea

        # def go_up(self, e):
        #     while e.is_expr():
        #         e = e.cexpr
        #         e = self.cfunc.body.find_parent_of(e)
        #         if e.op not in (idaapi.cot_ref, idaapi.cot_memref, idaapi.cot_

        def visit_expr(self, e):
            dr = idaapi.dr_R | idaapi.XREF_USER

            typ = e.type
            typ.remove_ptr_or_array()
            if typ.is_struct():
                strname = typ.dstr()
                if strname.startswith("struct "):
                    strname = strname[len("struct "):]
                stid = idaapi.get_struc_id(strname)
                s = idaapi.get_struc(stid)
                ea = self.find_addr(e)
                # log.warn("STRUCT {:>6}: {:>3} 0x{:010X} {:>10}".format(e.opname, len(es), ea, e.type.dstr()))
                es.append(e)

                if s:

                    # if is_assn(e.op):
                    #     e = e.x
                    #     dr = idaapi.dr_W | idaapi.XREF_USER
                        # log.warn("ASSGN {}:\t{}\t0x{:X}\t{}\t{}".format(e.opname, len(es), e.ea, dr, e.type.dstr()))
                        # s.append(e)

                    parent = self.cfunc.body.find_parent_of(e)
                    grandparent = self.cfunc.body.find_parent_of(parent)
                    if (parent and grandparent and
                       (is_assn(parent.op) and parent.cexpr.x == e) or
                       (parent.op in (idaapi.cot_memref, idaapi.cot_memptr) and
                            is_assn(grandparent.op) and
                            grandparent.cexpr.x == parent.cexpr)):
                        dr = idaapi.dr_W | idaapi.XREF_USER

                    # &x
                    if e.op == idaapi.cot_ref:
                        dr = idaapi.dr_O | idaapi.XREF_USER
                        # idaapi.add_dref(ea, stid, dr)
                        # # idaapi.add_dref(ea, stid, idaapi.dr_R | idaapi.XREF_USER)
                        # log.debug(("xref from 0x{:X} "
                        #            "to struct {} (id: 0x{:X}) "
                        #            "(type: 0x{:X}").format(
                        #            ea, strname, stid, dr))

                    # x.m, x->m
                    elif (e.op == idaapi.cot_memref or
                          e.op == idaapi.cot_memptr):
                        moff = e.m

                        mem = idaapi.get_member(s, moff)

                        # idaapi.add_dref(ea, stid, dr)
                        # log.debug(("xref from 0x{:X} "
                        #            "to struct {} (id: 0x{:X}) "
                        #            "(type: 0x{:X}").format(
                        #            ea, strname, stid, dr))
                        if mem:
                            idaapi.add_dref(ea, mem.id, dr)
                            log.debug(("xref from 0x{:X} "
                                       "to struct member {}.{} "
                                       "(id: 0x{:X}) "
                                       "(type: 0x{:X}").format(
                                       ea, strname,
                                       idaapi.get_member_name(mem.id), mem.id,
                                       dr))
                    else:  # var, etc.
                        pass
                    idaapi.add_dref(ea, stid, dr)
                    log.debug(("xref from 0x{:X} "
                               "to struct {} "
                               "(type: 0x{:X})").format(
                               ea, strname, dr))
                else:
                    log.error(("xref failure from 0x{:X} "
                               "to struct {} (id: 0x{:X})").format(
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
            log.debug("analyzing function at 0x{:X}".format(
                cfunc.entry_ea))
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
        log.info(("Hex-Rays version {} has been detected; "
                  "{} is ready to use").format(
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
