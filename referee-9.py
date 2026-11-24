# -*- coding: utf-8 -*-
"""
Referee creates struct xrefs for decompiled functions
"""
import ast
import logging
import traceback

import ida_hexrays
import ida_idaapi
import ida_kernwin
import ida_netnode
import ida_typeinf
import ida_xref

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger("referee")


NETNODE_NAME = '$ referee-xrefs'
NETNODE_TAG = 'X'


def is_assn(t):
    return (
        t == ida_hexrays.cot_asg or
        t == ida_hexrays.cot_asgbor or
        t == ida_hexrays.cot_asgxor or
        t == ida_hexrays.cot_asgband or
        t == ida_hexrays.cot_asgsub or
        t == ida_hexrays.cot_asgmul or
        t == ida_hexrays.cot_asgsshr or
        t == ida_hexrays.cot_asgushr or
        t == ida_hexrays.cot_asgsdiv or
        t == ida_hexrays.cot_asgudiv or
        t == ida_hexrays.cot_asgsmod or
        t == ida_hexrays.cot_asgumod)


def is_incdec(t):
    return (
        t == ida_hexrays.cot_postinc or  # = 53,  ///< x++
        t == ida_hexrays.cot_postdec or  # = 54,  ///< x--
        t == ida_hexrays.cot_preinc  or  # = 55,  ///< ++x
        t == ida_hexrays.cot_predec)     # = 56,  ///< --x


def decode_blob(blob):
    if isinstance(blob, bytes):
        return blob.decode("utf-8")
    return blob


def format_ea(ea):
    if ea is None or ea == ida_idaapi.BADADDR:
        return "BADADDR"
    return "0x{:X}".format(ea)


def ida_msg(message):
    try:
        ida_kernwin.msg("[referee] {}\n".format(message))
    except Exception:
        pass


def format_context(**kwargs):
    parts = []
    for key, value in kwargs.items():
        if value is None:
            continue
        parts.append("{}={}".format(key, value))
    return ", ".join(parts)


def log_message(level, message, **kwargs):
    context = format_context(**kwargs)
    if context:
        message = "{} ({})".format(message, context)
    getattr(log, level)(message)
    ida_msg("{}: {}".format(level.upper(), message))


def log_exception(message, **kwargs):
    context = format_context(**kwargs)
    if context:
        message = "{} ({})".format(message, context)
    log.exception(message)
    ida_msg("ERROR: {}".format(message))
    ida_msg(traceback.format_exc().rstrip())


def clean_type_name(name):
    prefixes = ("const ", "volatile ", "struct ", "union ")
    while True:
        for prefix in prefixes:
            if name.startswith(prefix):
                name = name[len(prefix):]
                break
        else:
            return name


def get_type_name(tif):
    try:
        return tif.dstr()
    except Exception:
        return "<unknown>"


def get_udt_name(tif):
    return clean_type_name(get_type_name(tif))


def get_tid_name(tid):
    if tid is None or tid == ida_idaapi.BADADDR:
        return "<unnamed>"
    try:
        name = ida_typeinf.get_tid_name(tid)
        if name:
            return name
    except Exception:
        pass
    return "<unnamed>"


def get_expr_type_name(e):
    try:
        return get_type_name(ida_typeinf.tinfo_t(e.type))
    except Exception:
        return "<unknown>"


def describe_expr(e):
    return format_context(
        ea=format_ea(getattr(e, "ea", None)),
        op=getattr(e, "op", None),
        type=get_expr_type_name(e))


def types_match(left, right):
    if left is None or right is None:
        return False
    try:
        if left.empty() or right.empty():
            return False
    except Exception:
        pass
    try:
        if left.equals_to(right):
            return True
    except Exception:
        pass
    return get_type_name(left) == get_type_name(right)


def get_udt_tid(tif):
    if not tif.is_udt():
        return ida_idaapi.BADADDR
    try:
        tid = tif.force_tid()
        if tid != ida_idaapi.BADADDR:
            return tid
    except Exception:
        pass
    return ida_typeinf.get_named_type_tid(get_udt_name(tif))


def add_struct_xrefs(cfunc):
    class xref_adder_t(ida_hexrays.ctree_visitor_t):
        def __init__(self, cfunc):
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_PARENTS)
            self.cfunc = cfunc
            self.node = ida_netnode.netnode()
            self.clear_struct_xrefs()
            self.xrefs = {}

        def load(self):
            try:
                data = self.node.getblob_ea(self.cfunc.entry_ea, NETNODE_TAG)
                if data:
                    xrefs = ast.literal_eval(decode_blob(data))
                    log.debug('Loaded {} xrefs'.format(len(xrefs)))
                    return xrefs
            except Exception:
                log_exception(
                    'Failed to load xrefs from netnode',
                    function_ea=format_ea(self.cfunc.entry_ea),
                    tag=NETNODE_TAG)
            return {}

        def save(self):
            try:
                self.node.setblob_ea(repr(self.xrefs).encode("utf-8"),
                                     self.cfunc.entry_ea,
                                     NETNODE_TAG)
            except Exception:
                log_exception(
                    'Failed to save xrefs to netnode',
                    function_ea=format_ea(self.cfunc.entry_ea),
                    xref_count=len(self.xrefs),
                    tag=NETNODE_TAG)

        def clear_struct_xrefs(self):
            if not self.node.create(NETNODE_NAME):
                xrefs = self.load()
                for (ea, struct_id, member_id) in xrefs.keys():
                    if member_id is None:
                        ida_xref.del_dref(ea, struct_id)
                    else:
                        ida_xref.del_dref(ea, member_id)
                self.xrefs = {}
                self.save()
                log_message(
                    "info",
                    'Cleared cached struct xrefs',
                    function_ea=format_ea(self.cfunc.entry_ea),
                    count=len(xrefs))

        def find_addr(self, e):
            if e.ea != ida_idaapi.BADADDR:
                ea = e.ea
            else:
                while True:
                    e = self.cfunc.body.find_parent_of(e)
                    if e is None:
                        ea = self.cfunc.entry_ea
                        break
                    if e.ea != ida_idaapi.BADADDR:
                        ea = e.ea
                        break
            return ea

        def add_dref(self, ea, struct_id, flags, member_id=None, member_name=None, struct_name=None):
            if ((ea, struct_id, member_id) not in self.xrefs or
                    flags < self.xrefs[(ea, struct_id, member_id)]):
                self.xrefs[(ea, struct_id, member_id)] = flags
                strname = struct_name or get_tid_name(struct_id)
                if member_id is None:
                    if not ida_xref.add_dref(ea, struct_id, flags):
                        log_message(
                            "warning",
                            "Failed to add struct dref",
                            ea=format_ea(ea),
                            struct_name=strname,
                            struct_id=struct_id,
                            flags=flags_to_str(flags))
                    log.debug((" 0x{:X} \t"
                               "struct {} \t"
                               "{}").format(
                               ea, strname, flags_to_str(flags)))
                else:
                    if not ida_xref.add_dref(ea, member_id, flags):
                        log_message(
                            "warning",
                            "Failed to add member dref",
                            ea=format_ea(ea),
                            struct_name=strname,
                            member_name=member_name or get_tid_name(member_id),
                            member_id=member_id,
                            flags=flags_to_str(flags))
                    log.debug((" 0x{:X} \t"
                               "member {}.{} \t"
                               "{}").format(
                               ea, strname,
                               member_name or get_tid_name(member_id),
                               flags_to_str(flags)))
            self.save()

        def get_member_name(self, member):
            name = getattr(member, "name", None)
            if name:
                return name
            return "<anonymous>"

        def get_member_type(self, member):
            return ida_typeinf.tinfo_t(member.type)

        def format_member_path(self, path):
            if not path:
                return "<unresolved>"
            return " -> ".join(
                "{}.{}".format(item["owner_name"], item["member_name"])
                for item in path)

        def resolve_struct_member(self, udt_type, bit_offset):
            idx = udt_type.find_udm(bit_offset)
            if idx == -1:
                return None

            idx, member = udt_type.get_udm(idx)
            if idx == -1 or member is None:
                return None

            residual_bits = bit_offset - member.offset
            if residual_bits < 0:
                return None

            member_type = self.get_member_type(member)
            owner_tid = get_udt_tid(udt_type)
            member_tid = udt_type.get_udm_tid(idx)

            return {
                "owner_tid": owner_tid,
                "owner_name": get_udt_name(udt_type),
                "member_tid": member_tid,
                "member_name": self.get_member_name(member),
                "member_type": member_type,
                "residual_bits": residual_bits,
            }

        def resolve_union_member(self, union_type, member_index):
            idx, member = union_type.get_udm(member_index)
            if idx == -1 or member is None:
                return None

            owner_tid = get_udt_tid(union_type)
            member_tid = union_type.get_udm_tid(idx)

            return {
                "owner_tid": owner_tid,
                "owner_name": get_udt_name(union_type),
                "member_tid": member_tid,
                "member_name": self.get_member_name(member),
                "member_type": self.get_member_type(member),
                "residual_bits": 0,
            }

        def resolve_member_path(self, base_type, member_ref, target_type):
            path = []
            current_type = ida_typeinf.tinfo_t(base_type)

            if not current_type.is_udt():
                return path, "base type is not a UDT"

            bit_offset = member_ref * 8
            used_union_selector = False

            for _depth in range(16):
                if current_type.is_union():
                    if used_union_selector:
                        return path, "nested union requires a separate member expression"
                    item = self.resolve_union_member(current_type, member_ref)
                    used_union_selector = True
                else:
                    item = self.resolve_struct_member(current_type, bit_offset)

                if item is None:
                    if current_type.is_union():
                        return path, "member index {} was not found in {}".format(
                            member_ref, get_udt_name(current_type))
                    return path, "bit offset {} was not found in {}".format(
                        bit_offset, get_udt_name(current_type))

                path.append(item)

                if target_type is not None and types_match(item["member_type"], target_type):
                    return path, None

                residual_bits = item["residual_bits"]
                next_type = item["member_type"]

                if residual_bits == 0:
                    if not next_type.is_udt():
                        return path, None
                    return path, "stopped at nested UDT {}".format(get_udt_name(next_type))

                if next_type.is_union():
                    return path, "residual bit offset {} landed inside nested union {}".format(
                        residual_bits, get_udt_name(next_type))

                if not next_type.is_udt():
                    return path, "residual bit offset {} landed inside non-UDT {}".format(
                        residual_bits, get_type_name(next_type))

                current_type = next_type
                bit_offset = residual_bits

            return path, "maximum member recursion depth exceeded"

        def visit_expr(self, e):
            try:
                dr = ida_xref.dr_R | ida_xref.XREF_USER
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
                    dr = ida_xref.dr_W | ida_xref.XREF_USER

                # &x
                if e.op == ida_hexrays.cot_ref:
                    e = e.x
                    dr = ida_xref.dr_O | ida_xref.XREF_USER

                # x.m, x->m
                if (e.op == ida_hexrays.cot_memref or e.op == ida_hexrays.cot_memptr):
                    member_ref = e.m

                    # The only way I could figure out how
                    # to get the structure/member associated with its use
                    typ = ida_typeinf.tinfo_t(e.x.type)
                    result_type = ida_typeinf.tinfo_t(e.type)

                    if e.op == ida_hexrays.cot_memptr:
                        typ.remove_ptr_or_array()

                    if not typ.is_udt():
                        log_message(
                            "warning",
                            "Member access base type is not a UDT",
                            function_ea=format_ea(self.cfunc.entry_ea),
                            access_ea=format_ea(ea),
                            member_ref=member_ref,
                            expr=describe_expr(e))
                        return 0

                    udt_tid = get_udt_tid(typ)
                    path, failure_reason = self.resolve_member_path(
                        typ,
                        member_ref,
                        result_type)

                    if udt_tid != ida_idaapi.BADADDR:
                        self.add_dref(
                            ea,
                            udt_tid,
                            dr,
                            struct_name=get_udt_name(typ))
                    else:
                        log_message(
                            "error",
                            "Failed to resolve UDT tid",
                            function_ea=format_ea(self.cfunc.entry_ea),
                            access_ea=format_ea(ea),
                            udt_name=get_udt_name(typ),
                            flags=flags_to_str(dr),
                            expr=describe_expr(e))

                    if path:
                        log_message(
                            "debug",
                            "Resolved member access",
                            function_ea=format_ea(self.cfunc.entry_ea),
                            access_ea=format_ea(ea),
                            base_type=get_udt_name(typ),
                            member_ref=member_ref,
                            result_type=get_type_name(result_type),
                            path=self.format_member_path(path))
                        for item in path:
                            if item["member_tid"] != ida_idaapi.BADADDR:
                                self.add_dref(
                                    ea,
                                    item["owner_tid"],
                                    dr,
                                    item["member_tid"],
                                    item["member_name"],
                                    item["owner_name"])
                            else:
                                log_message(
                                    "warning",
                                    "Resolved member path item without member tid",
                                    function_ea=format_ea(self.cfunc.entry_ea),
                                    access_ea=format_ea(ea),
                                    owner_name=item["owner_name"],
                                    member_name=item["member_name"],
                                    path=self.format_member_path(path))
                        if failure_reason:
                            log_message(
                                "warning",
                                "Resolved member path only partially",
                                function_ea=format_ea(self.cfunc.entry_ea),
                                access_ea=format_ea(ea),
                                base_type=get_udt_name(typ),
                                member_ref=member_ref,
                                result_type=get_type_name(result_type),
                                path=self.format_member_path(path),
                                reason=failure_reason,
                                expr=describe_expr(e))
                    else:
                        log_message(
                            "warning",
                            "Failed to resolve member path",
                            function_ea=format_ea(self.cfunc.entry_ea),
                            access_ea=format_ea(ea),
                            base_type=get_udt_name(typ),
                            member_ref=member_ref,
                            result_type=get_type_name(result_type),
                            reason=failure_reason,
                            expr=describe_expr(e))

                elif ida_hexrays.is_lvalue(e.op):
                    typ = ida_typeinf.tinfo_t(e.type)
                    udt_tid = get_udt_tid(typ)

                    if typ.is_udt() and udt_tid != ida_idaapi.BADADDR:
                        self.add_dref(
                            ea,
                            udt_tid,
                            dr,
                            struct_name=get_udt_name(typ))
                    elif typ.is_udt():
                        log_message(
                            "warning",
                            "Failed to resolve lvalue UDT tid",
                            function_ea=format_ea(self.cfunc.entry_ea),
                            access_ea=format_ea(ea),
                            udt_name=get_udt_name(typ),
                            expr=describe_expr(e))

                return 0
            except Exception:
                log_exception(
                    "visit_expr failed",
                    function_ea=format_ea(self.cfunc.entry_ea),
                    expr=describe_expr(e))
                return 0

    adder = xref_adder_t(cfunc)
    adder.apply_to_exprs(cfunc.body, None)


class RefereeHooks(ida_hexrays.Hexrays_Hooks):
    def __init__(self):
        ida_hexrays.Hexrays_Hooks.__init__(self)

    def maturity(self, cfunc, new_maturity):
        if new_maturity == ida_hexrays.CMAT_FINAL:
            log_message(
                "info",
                "Analyzing decompiled function",
                function_ea=format_ea(cfunc.entry_ea),
                maturity=new_maturity)
            try:
                add_struct_xrefs(cfunc)
            except Exception:
                log_exception(
                    "add_struct_xrefs failed from maturity hook",
                    function_ea=format_ea(cfunc.entry_ea),
                    maturity=new_maturity)
        return 0


class Referee(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_HIDE
    comment = "Adds struct xref info from decompilation"
    help = ""

    wanted_name = "Referee"
    wanted_hotkey = ""
    inited = False
    hooks = None

    def init(self):
        if not ida_hexrays.init_hexrays_plugin():
            log_message("error", "init_hexrays_plugin failed")
            return ida_idaapi.PLUGIN_SKIP

        self.hooks = RefereeHooks()
        if not self.hooks.hook():
            log_message("error", "Failed to hook Hex-Rays callbacks")
            return ida_idaapi.PLUGIN_SKIP
        log_message(
            "info",
            "{} is ready".format(self.wanted_name),
            hexrays_version=ida_hexrays.get_hexrays_version())
        self.inited = True
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        # never called
        pass

    def term(self):
        if self.inited:
            if self.hooks is not None:
                self.hooks.unhook()
            log_message("info", "Referee hooks removed")
            ida_hexrays.term_hexrays_plugin()


def PLUGIN_ENTRY():
    return Referee()


def flags_to_str(num):
    match = []
    if num & ida_xref.dr_R == ida_xref.dr_R:
        match.append('dr_R')
        num ^= ida_xref.dr_R
    if num & ida_xref.dr_O == ida_xref.dr_O:
        match.append('dr_O')
        num ^= ida_xref.dr_O
    if num & ida_xref.dr_W == ida_xref.dr_W:
        match.append('dr_W')
        num ^= ida_xref.dr_W
    if num & ida_xref.dr_I == ida_xref.dr_I:
        match.append('dr_I')
        num ^= ida_xref.dr_I
    if num & ida_xref.dr_T == ida_xref.dr_T:
        match.append('dr_T')
        num ^= ida_xref.dr_T
    if num & ida_xref.XREF_USER == ida_xref.XREF_USER:
        match.append('XREF_USER')
        num ^= ida_xref.XREF_USER
    if num & ida_xref.XREF_DATA == ida_xref.XREF_DATA:
        match.append('XREF_DATA')
        num ^= ida_xref.XREF_DATA
    res = ' | '.join(match)
    if num:
        res += ' unknown: 0x{:X}'.format(num)
    return res


def clear_output_window():
    ida_kernwin.process_ui_action('msglist:Clear')
