#   IDAPython script 
#
#   Bookmark all instances of calls to GetAsyncKeyState and GetKeyState which use 
#   a varying value (e.g. not const shift/ctrl/alt modifiers) for the nVirtKey arg.
#
#   Designed for x86, untested on x64.

import idaapi

def stricmp(x, y):
    return 0 if x.lower() == y.lower() else 1

# dll: dll name without extension
# return a dict of `import_name: address` for dll
def get_imports(dll):
    def imp_cb(ea, name, ord):
        imports[name] = ea
        return True

    imports = {}
    nimps = idaapi.get_import_module_qty()
    for i in xrange(0, nimps):
        name = idaapi.get_import_module_name(i)
        if stricmp(name, dll):
            continue
        idaapi.enum_import_names(i, imp_cb)
        break

    return imports

# return a list of all call xrefs to func_addr which use a register for the first argument
def enum_calls_using_var_arg(func_addr):
    if not func_addr or func_addr == BADADDR:
        return None

    walk_limit = 5
    varg_calls = []
    xrefs = {xref.frm for xref in XrefsTo(func_addr, 0) if idaapi.is_call_insn(xref.frm)}
    for xref in xrefs:
        walk = 0
        prev_insn = DecodePreviousInstruction(xref)

        # starting at the call instruction, walk the instructions in reverse order
        # until we find a push or hit the limit.
        while stricmp(prev_insn.get_canon_mnem(), "push") and walk < walk_limit:
            prev_insn = DecodePreviousInstruction(prev_insn.ea)
            walk = walk + 1
        if walk >= walk_limit:
            print "[!] Reached walk limit for xref at %x." % xref
            continue
        if prev_insn.Op1.type == o_reg:
            varg_calls.append(xref)

    return varg_calls

# bookmark slot range is [1 - 1024]
def get_next_free_mark_slot():
    i = 1
    while GetMarkedPos(i) != BADADDR and i < 1025:
        i = i + 1
    return i if i < 1024 else -1

# add items to bookmarks
def mark(func_name, xrefs):
    if not xrefs:
        return
    slot = get_next_free_mark_slot()
    if slot < 0 or slot + len(xrefs) > 1023:
        print "[!] Not enough mark slots."
        return
    i = 1
    for xref in xrefs:
        format_cmt = "%s:  %d" % (func_name, i)
        MarkPosition(xref, 0, 0, 0, slot, format_cmt)
        i = i + 1
        slot = slot + 1

user32 = get_imports('USER32')
gaks = enum_calls_using_var_arg(user32.get('GetAsyncKeyState'))
mark('GetAsyncKeyState', gaks)
gks = enum_calls_using_var_arg(user32.get('GetKeyState'))
mark('GetKeyState', gks)