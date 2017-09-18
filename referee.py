"""
Referee creates struct xrefs for decompiled functions
"""
import logging

import idaapi

# logging.basicConfig(level=logging.WARN)
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger("referee")


es = []
xs = []


def clear_output_window():
    idaapi.process_ui_action('msglist:Clear')


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


def flags_to_str(num):
    match = []
    if num & idaapi.dr_R == idaapi.dr_R:
        match.append('dr_R')
        num ^= idaapi.dr_R
    if num & idaapi.dr_O == idaapi.dr_O:
        match.append('dr_O')
        num ^= idaapi.dr_O
    if num & idaapi.dr_W == idaapi.dr_W:
        match.append('dr_W')
        num ^= idaapi.dr_W
    if num & idaapi.dr_I == idaapi.dr_I:
        match.append('dr_I')
        num ^= idaapi.dr_I
    if num & idaapi.dr_T == idaapi.dr_T:
        match.append('dr_T')
        num ^= idaapi.dr_T
    if num & idaapi.XREF_USER == idaapi.XREF_USER:
        match.append('XREF_USER')
        num ^= idaapi.XREF_USER
    if num & idaapi.XREF_DATA == idaapi.XREF_DATA:
        match.append('XREF_DATA')
        num ^= idaapi.XREF_DATA
    res = ' | '.join(match)
    if num:
        res += ' unknown: 0x{:X}'.format(num)
    return res

def add_struct_xrefs(cfunc):
    class xref_adder_t(idaapi.ctree_visitor_t):
        def __init__(self, cfunc):
            idaapi.ctree_visitor_t.__init__(self, idaapi.CV_PARENTS)
            self.cfunc = cfunc
            self.xrefs = {}

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


        def visit_expr(self, e):
            dr = idaapi.dr_R | idaapi.XREF_USER

            ea = self.find_addr(e)
            # if typ.is_struct():
            #     strname = typ.dstr()
            #     if strname.startswith("struct "):
            #         strname = strname[len("struct "):]
            #     stid = idaapi.get_struc_id(strname)
            #     s = idaapi.get_struc(stid)
                # log.warn("STRUCT {:>6}: {:>3} 0x{:010X} {:>10}".format(e.opname, len(es), ea, e.type.dstr()))

                # if s:
                #
                #
                #     parent = self.cfunc.body.find_parent_of(e)
                #     grandparent = self.cfunc.body.find_parent_of(parent)
                #     if ((parent and (is_assn(parent.op) and parent.cexpr.x == e)) or
                #        (parent.op in (idaapi.cot_memref, idaapi.cot_memptr) and
                #             grandparent and is_assn(grandparent.op) and
                #             grandparent.cexpr.x == parent.cexpr)):
                #         dr = idaapi.dr_W | idaapi.XREF_USER
                #         es.append(e)
                #         xs.append((ea, stid, dr))
                #         idaapi.add_dref(ea, stid, dr)
                #         log.debug(("xref from 0x{:X} "
                #                    "to struct {} "
                #                    "({})").format(
                #                    ea, strname, flags_to_str(dr)))

            if is_assn(e.op):
                e = e.x
                dr = idaapi.dr_W | idaapi.XREF_USER

            # &x
            if e.op == idaapi.cot_ref:
                e = e.x
                dr = idaapi.dr_O | idaapi.XREF_USER

            # x.m, x->m
            if (e.op == idaapi.cot_memref or
                  e.op == idaapi.cot_memptr):
                moff = e.m

                typ = e.x.type
                if e.op == idaapi.cot_memptr:
                    typ.remove_ptr_or_array()
                strname = typ.dstr()
                if strname.startswith("struct "):
                    strname = strname[len("struct "):]
                stid = idaapi.get_struc_id(strname)
                s = idaapi.get_struc(stid)

                mem = idaapi.get_member(s, moff)
                if s:
                    if (ea, stid) not in self.xrefs or dr < self.xrefs[(ea, stid)]:
                        es.append(e)
                        xs.append((ea, stid, dr))
                        self.xrefs[(ea, stid)] = dr
                        idaapi.add_dref(ea, stid, dr)
                        log.debug((" 0x{:X} \t"
                                   "struct {} \t"
                                   "{}").format(
                                   ea, strname, flags_to_str(dr)))

                    # idaapi.add_dref(ea, stid, dr)
                    if mem:
                        if (ea, mem.id) not in self.xrefs or dr < self.xrefs[(ea, mem.id)]:
                            es.append(e)
                            xs.append((ea, mem.id, dr))
                            self.xrefs[(ea, mem.id)] = dr
                            idaapi.add_dref(ea, mem.id, dr)
                            log.debug((" 0x{:X} \t"
                                       "member {}.{} \t"
                                       "{}").format(
                                       ea, strname,
                                       idaapi.get_member_name(mem.id),
                                       flags_to_str(dr)))

                else:
                    log.error(("xref failure from 0x{:X} "
                               "to struct {} (id: 0x{:X}) ({})").format(
                               ea, strname, stid, flags_to_str(dr)))

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
