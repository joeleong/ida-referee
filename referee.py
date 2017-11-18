# -*- coding: utf-8 -*-
"""
Referee creates struct xrefs for decompiled functions
"""
import logging
import traceback

import idaapi
import ida_idaapi
import ida_kernwin
import ida_struct

logging.basicConfig(level=logging.WARN)
log = logging.getLogger("referee")


NETNODE_NAME = '$ referee-xrefs'
NETNODE_TAG = 'X'


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


def is_incdec(t):
    return (
        t == idaapi.cot_postinc or  # = 53,  ///< x++
        t == idaapi.cot_postdec or  # = 54,  ///< x--
        t == idaapi.cot_preinc  or  # = 55,  ///< ++x
        t == idaapi.cot_predec)     # = 56,  ///< --x


def add_struct_xrefs(cfunc):
    class xref_adder_t(idaapi.ctree_visitor_t):
        def __init__(self, cfunc):
            idaapi.ctree_visitor_t.__init__(self, idaapi.CV_PARENTS)
            self.cfunc = cfunc
            self.node = idaapi.netnode()
            self.clear_struct_xrefs()
            self.xrefs = {}

        def load(self):
            try:
                data = self.node.getblob_ea(self.cfunc.entry_ea, NETNODE_TAG)
                if data:
                    xrefs = eval(data)
                    log.debug('Loaded {} xrefs'.format(len(xrefs)))
                    return xrefs
            except:
                log.error('Failed to load xrefs from netnode')
                traceback.print_exc()
            return {}

        def save(self):
            try:
                self.node.setblob_ea(repr(self.xrefs),
                                     self.cfunc.entry_ea,
                                     NETNODE_TAG)
            except:
                log.error('Failed to save xrefs to netnode')
                traceback.print_exc()

        def clear_struct_xrefs(self):
            if not self.node.create(NETNODE_NAME):
                xrefs = self.load()
                for (ea, struct_id, member_id) in xrefs.keys():
                    if member_id is None:
                        idaapi.del_dref(ea, struct_id)
                    else:
                        idaapi.del_dref(ea, member_id)
                self.xrefs = {}
                self.save()
                log.debug('Cleared {} xrefs'.format(len(xrefs)))

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

        def add_dref(self, ea, struct_id, flags, member_id=None):
            if ((ea, struct_id, member_id) not in self.xrefs or
                    flags < self.xrefs[(ea, struct_id, member_id)]):
                self.xrefs[(ea, struct_id, member_id)] = flags
                strname = idaapi.get_struc_name(struct_id)
                if member_id is None:
                    idaapi.add_dref(ea, struct_id, flags)
                    log.debug((" 0x{:X} \t"
                               "struct {} \t"
                               "{}").format(
                               ea, strname, flags_to_str(flags)))
                else:
                    idaapi.add_dref(ea, member_id, flags)
                    log.debug((" 0x{:X} \t"
                               "member {}.{} \t"
                               "{}").format(
                               ea, strname,
                               idaapi.get_member_name(member_id),
                               flags_to_str(flags)))
            self.save()

        def visit_expr(self, e):
            dr = idaapi.dr_R | idaapi.XREF_USER
            ea = self.find_addr(e)

            # We wish to know what context a struct usage occurs in
            # so we can determine what kind of xref to create. Unfortunately,
            # a post-order traversal makes this difficult.

            # For assignments, we visit the left, instead
            # Note that immediate lvalues will be visited twice,
            # and will be eronneously marked with a read dref.
            # However, it is safer to overapproximate than underapproximate
            if is_assn(e.op) or is_incdec(e.op):
                e = e.x
                dr = idaapi.dr_W | idaapi.XREF_USER

            # &x
            if e.op == idaapi.cot_ref:
                e = e.x
                dr = idaapi.dr_O | idaapi.XREF_USER

            # x.m, x->m
            if (e.op == idaapi.cot_memref or e.op == idaapi.cot_memptr):
                moff = e.m

                # The only way I could figure out how
                # to get the structure/member associated with its use
                typ = e.x.type

                if e.op == idaapi.cot_memptr:
                    typ.remove_ptr_or_array()

                strname = typ.dstr()
                if strname.startswith("struct "):
                    strname = strname[len("struct "):]

                stid = idaapi.get_struc_id(strname)
                struc = idaapi.get_struc(stid)
                mem = idaapi.get_member(struc, moff)

                if struc is not None:
                    self.add_dref(ea, stid, dr)
                    if mem is not None:
                        self.add_dref(ea, stid, dr, mem.id)

                else:
                    log.error(("failure from 0x{:X} "
                               "on struct {} (id: 0x{:X}) {}").format(
                               ea, strname, stid, flags_to_str(dr)))

            elif idaapi.is_lvalue(e.op) and e.type.is_struct():
                strname = e.type.dstr()
                if strname.startswith("struct "):
                    strname = strname[len("struct "):]

                stid = idaapi.get_struc_id(strname)
                struc = idaapi.get_struc(stid)

                if struc is not None:
                    self.add_dref(ea, stid, dr)

            return 0

    adder = xref_adder_t(cfunc)
    adder.apply_to_exprs(cfunc.body, None)


def callback(*args):
    if args[0] == idaapi.hxe_maturity:
        cfunc = args[1]
        mat = args[2]
        if mat == idaapi.CMAT_FINAL:
            log.debug("analyzing function at 0x{:X}".format(
                cfunc.entry_ea))
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
        # never called
        pass

    def term(self):
        if self.inited:
            idaapi.remove_hexrays_callback(callback)
            idaapi.term_hexrays_plugin()


def PLUGIN_ENTRY():
    return Referee()


class hx_xrefs_action_handler_t(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        # self.get_struct_or_member_name(ctx)
        # self.get_current_struct_name(ctx)
        xref_id = self.get_current_structure_id(ctx)
        if xref_id:
            chooser = XrefChooser(xref_id)
            chooser.Show()
            # chooser.Show(True)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

    def get_current_structure_id(self, ctx):
        view = ida_kernwin.get_current_viewer()
        from_mouse = False
        line = ida_kernwin.get_custom_viewer_curline(view, from_mouse)
        if '\x01(' in line:
            obj_id = int(line.split('\x01(')[1][:16], 16)
            if idaapi.is_member_id(obj_id):
                log.debug("retrieving xrefs for member: {}".format(
                    ida_struct.get_member_name(ctx.cur_strmem.id)))
            else:
                log.debug("retrieving xrefs for structure: {}".format(
                    ida_struct.get_struc_name(ctx.cur_struc.id)))
            return obj_id
        return None

    def get_current_struct_name(self, ctx):
        view = ida_kernwin.get_current_viewer()
        from_mouse = False
        line = ida_kernwin.get_custom_viewer_curline(view, from_mouse)
        # print(line)
        print(repr(line))
        print("Current structure: %s" % hex(ctx.cur_struc.id))
        print("Current member: %s" % hex(ctx.cur_strmem.id))
        if '\x01(' in line:
            obj_id = int(line.split('\x01(')[1][:16], 16)
            if idaapi.is_member_id(obj_id):
                print("Current member: %s" % ida_struct.get_member_name(ctx.cur_strmem.id))
            else:
                print("Current structure: %s" % ida_struct.get_struc_name(ctx.cur_struc.id))
        return ida_lines.tag_remove(line).split()[1]

    def get_struct_or_member_name(self, ctx):
       if ctx.cur_struc and ctx.cur_struc.id != ida_idaapi.BADADDR:
          print("Current structure: %s" % ida_struct.get_struc_name(ctx.cur_struc.id))
          print("Current member: %s" % ida_struct.get_member_name(ctx.cur_strmem.id))
          print("Current highlight: {} {}".format(*ida_kernwin.get_highlight(ctx.widget)))
          chooser = XrefChooser(ctx.cur_strmem.id)
          print(chooser.Show())
          # print(chooser.Show(True))


action_desc = idaapi.action_desc_t(
    'referee:hx_xrefs',                    # The action name. This acts like an ID and must be unique
    'List Xrefs with decompiler output',   # The action text.
    hx_xrefs_action_handler_t(),           # The action handler.
    'Ctrl-Shift-X',                        # Optional: the action shortcut
    'Lists Xrefs with decompiler output',  # Optional: the action tooltip (available in menus/toolbar)
    199)                                   # Optional: the action icon (shows when in menus/toolbars)

class my_hooks_t(ida_kernwin.UI_Hooks):
    def __init__(self):
        ida_kernwin.UI_Hooks.__init__(self)

    def finish_populating_widget_popup(self, widget, popup):
        if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_STRUCTS:
            ida_kernwin.attach_action_to_popup(widget, popup, 'referee:hx_refs')

idaapi.register_action(action_desc)
my_hooks = my_hooks_t()
my_hooks.hook()
# struct_widget = idaapi.create_empty_widget('Structures')
# idaapi.attach_action_to_popup(struct_widget, None, 'referee:hx_xrefs', None)


class XrefChooser(ida_kernwin.Choose):
    def __init__(self, xref_id):
        ida_kernwin.Choose.__init__(
                self,
                'xrefs to {}'.format(idaapi.get_member_fullname(xref_id)),
                [["Direction",   4   | ida_kernwin.Choose.CHCOL_PLAIN],
                 ["Type",        3   | ida_kernwin.Choose.CHCOL_PLAIN],
                 ["Address",     8  | ida_kernwin.Choose.CHCOL_HEX],
                 ["Function",   10  | ida_kernwin.Choose.CHCOL_PLAIN],
                 ["Pseudocode", 20  | ida_kernwin.Choose.CHCOL_PLAIN],
                 ["Disasm",     20  | ida_kernwin.Choose.CHCOL_PLAIN]],
                icon=-1)
                # flags=Choose.CH_NOIDB,
                # embedded=True, width=30, height=20)

        self.items = []
        xb = idaapi.xrefblk_t()
        ok = xb.first_to(xref_id, idaapi.XREF_ALL)
        # ok = xb.first_to(xref_id, idaapi.XREF_DATA)
        while ok:
            self.items.append((xb.frm, xb.type))
            ok = xb.next_to()

        log.warn(self.items)

    def OnGetLine(self, n):
        ea, flags = self.items[n]
        funcname = idaapi.get_func_name(ea)
        func = idaapi.get_func(ea)
        offset = 0
        if func is not None:
            offset = ea - func.start_ea
        if funcname is None:
            funcname = ''
        elif offset:
            funcname = '{}+{:X}'.format(funcname, offset)
        if ea == idaapi.get_screen_ea():
            direction = '↔'
        elif ea > idaapi.get_screen_ea():
            direction = '↓ Down'
        else:
            direction = '↑ Up'
        disasm = idaapi.generate_disasm_line(ea)
        if disasm is not None:
            disasm = idaapi.tag_remove(disasm)
        else:
            disasm = ''
        return [direction,
                flags_to_str(flags).strip('dr_').lower(),
                '0x{:X}'.format(ea),
                funcname,
                self.get_decompiled_line(ea),
                disasm]

    def OnGetSize(self):
        return len(self.items)

    def OnSelectLine(self, n):
        ea, flags = self.items[n]
        if ea != ida_idaapi.BADADDR:
            idaapi.open_pseudocode(ea)
            return True

    def get_decompiled_line(self, ea):
        cfunc = idaapi.decompile(ea)
        if cfunc is None:
            return ''
        if ea not in cfunc.eamap:
            print 'strange, %x is not in %x eamap' % (ea, cfunc.entry_ea)
            return ''
        return '\n'.join(
                idaapi.tag_remove(stmt.print1(cfunc.__deref__()))
                for stmt in cfunc.eamap[ea])


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


def clear_output_window():
    idaapi.process_ui_action('msglist:Clear')
