"""Unicorn equivalence + negative-control test for Country_Recalculate SESE [0x00515EA6, 0x00516286) variant (a)."""
import json
from pathlib import Path
import struct
import pefile
import unicorn as u
from unicorn.x86_const import *

from test_unicorn import compare_fx, enable_sse_fpu, make_fx_seed

LAB = Path(__file__).resolve().parent
ROOT = LAB.parent.parent
BUILD = LAB / 'build'
BASE_EXE = ROOT / 'base-game/v2game.exe'

IMG_BASE = 0x00400000
VA_GLOBAL_MGR = 0x012587E4
VA_GLOBAL_WORLD = 0x012588E8
VA_CONST_250_5F = 0x00E45A40

VA_SESE_ENTRY = 0x00515EA6
VA_SESE_EXIT = 0x00516286

VA_FN_004A8300 = 0x004A8300
VA_FN_004D61D0 = 0x004D61D0
VA_FN_004E9B90 = 0x004E9B90
VA_FN_004A7BC0 = 0x004A7BC0
VA_FN_005F2AE0 = 0x005F2AE0
VA_FN_00511140 = 0x00511140
VA_FN_009692C0 = 0x009692C0
VA_FN_005163C0 = 0x005163C0
VA_FN_OP_NEW = 0x00AAE9AF
VA_FN_ROUND = 0x00401000
VA_FN_FTOL2 = 0x00B31C00

# Synthetic vtable method stubs in unused code region 0x00920000..0x00921000
VA_CMD_V28 = 0x00920100
VA_CMD_V2C = 0x00920200
VA_CMD_V00_DTOR = 0x00920300
VA_REL24_KIND_336 = 0x00920400
VA_REL24_KIND_93A = 0x00920500
VA_REL24_KIND_443 = 0x00920600

TOTAL_TAGS = 9


def u32(uc: u.Uc, addr: int) -> int:
    return struct.unpack('<I', uc.mem_read(addr, 4))[0]


def w32(uc: u.Uc, addr: int, val: int) -> None:
    uc.mem_write(addr, struct.pack('<I', val & 0xFFFFFFFF))


def run_sese_fixture(mode: str, total_tags: int = TOTAL_TAGS, mutate_reb: bool = False) -> dict:
    """
    mode: 'orig' or 'variant_a'
    mutate_reb: negative control corrupting the 'REB' check byte in variant (a)
    """
    pe = pefile.PE(str(BASE_EXE), fast_load=True)
    emu = u.Uc(u.UC_ARCH_X86, u.UC_MODE_32)
    enable_sse_fpu(emu)

    # Map code pages for SESE region & helper addresses + globals + heap + stack + blob
    for page in [
        0x00401000, 0x004A7000, 0x004A8000, 0x004D6000, 0x004E9000,
        0x00511000, 0x00515000, 0x005F2000, 0x00920000,
        0x00969000, 0x00AAE000, 0x00B31000, 0x00E45000, 0x01258000,
    ]:
        emu.mem_map(page, 0x2000 if page == 0x00515000 else 0x1000, u.UC_PROT_ALL)

    emu.mem_map(0x10000000, 0x20000, u.UC_PROT_READ | u.UC_PROT_WRITE)  # fixture + arena
    emu.mem_map(0x18000000, 0x10000, u.UC_PROT_READ | u.UC_PROT_WRITE)  # stack
    emu.mem_map(0x23450000, 0x2000, u.UC_PROT_ALL)                      # PIC blob

    # Copy exact SESE machine code [0x00515EA6, 0x00516286) and float constant 250.5f
    sese_bytes = pe.get_data(VA_SESE_ENTRY - IMG_BASE, VA_SESE_EXIT - VA_SESE_ENTRY)
    emu.mem_write(VA_SESE_ENTRY, sese_bytes)
    emu.mem_write(VA_CONST_250_5F, pe.get_data(VA_CONST_250_5F - IMG_BASE, 4))

    # Place sentinel at 0x00516286 (exit target)
    emu.mem_write(VA_SESE_EXIT, b'\x90')

    # Populate helper stubs as `ret` or `ret 4` so Unicorn hooks control exact state
    for addr in [
        VA_FN_004A8300, VA_FN_004D61D0, VA_FN_004E9B90, VA_FN_009692C0,
        VA_FN_005163C0, VA_FN_OP_NEW, VA_FN_ROUND, VA_FN_FTOL2,
        VA_CMD_V28, VA_CMD_V2C, VA_REL24_KIND_336, VA_REL24_KIND_93A, VA_REL24_KIND_443,
    ]:
        emu.mem_write(addr, b'\xC3')
    for addr in [VA_FN_004A7BC0, VA_FN_005F2AE0, VA_FN_00511140, VA_CMD_V00_DTOR]:
        emu.mem_write(addr, b'\xC2\x04\x00')  # ret 4

    # Layout synthetic objects in 0x10000000..
    world_ptr = 0x10000000      # 0x1000 size
    mgr_ptr = 0x10001000
    entries_arr = 0x10001100
    self_ptr = 0x10002000       # size 0x2000
    rel_ptrs = 0x10004000       # array of TOTAL_TAGS ptrs
    rels_base = 0x10004100      # each rel 0x100 B
    countries_base = 0x10005000 # each country 0x1500 B (tags 0..8)
    vtbl_base = 0x10003000      # vtables
    acc_arr = 0x10003800        # world+0xACC array
    acc_elems = 0x10003900      # 4 elements x 0x200 B
    lnodes = 0x10003E00         # linked list nodes
    arena = {'ptr': 0x10012000}

    w32(emu, VA_GLOBAL_WORLD, world_ptr)
    w32(emu, VA_GLOBAL_MGR, mgr_ptr)
    w32(emu, mgr_ptr + 0x00, total_tags)
    w32(emu, mgr_ptr + 0x04, entries_arr)

    w32(emu, world_ptr + 0xB0C, 0x18370101)
    w32(emu, world_ptr + 0xACC, acc_arr)

    # Vtables for cmd (v00, v28, v2C) and rel24 kinds
    cmd_vtbl = vtbl_base + 0x000
    w32(emu, cmd_vtbl + 0x00, VA_CMD_V00_DTOR)
    w32(emu, cmd_vtbl + 0x28, VA_CMD_V28)
    w32(emu, cmd_vtbl + 0x2C, VA_CMD_V2C)

    for off, fn in [(0x100, VA_REL24_KIND_336), (0x200, VA_REL24_KIND_93A), (0x300, VA_REL24_KIND_443)]:
        w32(emu, vtbl_base + off + 0x1C, fn)

    # Countries 0..8
    tags = [
        b'NON\x00', b'SPA\x00', b'REB\x00', b'DED\x00',
        b'DE3\x00', b'FRA\x00', b'ENG\x00', b'PRU\x00', b'RUS\x00',
    ]
    prov_sizes = [16, 16, 16, 0, 3, 8, 12, 16, 4]  # 3 -> (& ~3)==0 (filtered!)

    for i in range(TOTAL_TAGS):
        c = countries_base + i * 0x1500
        if i == 1:
            self_ptr = c
        w32(emu, entries_arr + i * 4, c)
        emu.mem_write(c + 0x1C, tags[i])
        w32(emu, c + 0x20, i)
        w32(emu, c + 0x9D8, 0x11000000)
        w32(emu, c + 0x9DC, 0x11000000 + prov_sizes[i])

    # Configure self (id=1, SPA)
    emu.mem_write(self_ptr + 0xCF4, b'\x01')
    emu.mem_write(self_ptr + 0xCF5, b'\x01')
    w32(emu, self_ptr + 0x7D8, 1)
    w32(emu, self_ptr + 0xCF8, 0x01020304)
    w32(emu, self_ptr + 0xCFC, 5)          # triggers cmd creation on other_id=5
    w32(emu, self_ptr + 0xBE8, rel_ptrs)
    w32(emu, self_ptr + 0xE64, 0x42)
    w32(emu, self_ptr + 0x1AC, 1000)
    w32(emu, self_ptr + 0x142C, 99)

    # Vector buffers for self: 0xD38, 0xD48, 0xD58, 0xD68, 0xD78, 0xEA4, 0xEB4
    vec_offsets = [0xD38, 0xD48, 0xD58, 0xD68, 0xD78, 0xEA4, 0xEB4]
    for idx_v, voff in enumerate(vec_offsets):
        vbuf = 0x10018000 + idx_v * 0x200
        w32(emu, self_ptr + voff + 0x00, vbuf)
        w32(emu, self_ptr + voff + 0x04, vbuf)
        w32(emu, self_ptr + voff + 0x08, vbuf + 0x200)

    # Configure relations 0..8
    for i in range(TOTAL_TAGS):
        r = rels_base + i * 0x100
        w32(emu, rel_ptrs + i * 4, r)
        w32(emu, r + 0x08, struct.unpack('<I', tags[i])[0])
        w32(emu, r + 0x0C, i)

    # Pre-populated cmd38 structs + world+0xA84 node
    cmd_ea4 = 0x10010000
    w32(emu, cmd_ea4 + 0x00, cmd_vtbl)
    cmd_del = 0x10010100
    w32(emu, cmd_del + 0x00, cmd_vtbl)
    node_a84 = 0x10010200
    w32(emu, node_a84 + 0x00, cmd_del)
    w32(emu, node_a84 + 0x08, 0)
    w32(emu, world_ptr + 0xA84, node_a84)  # list head for +0xA84
    w32(emu, world_ptr + 0xA88, node_a84)  # tail
    w32(emu, world_ptr + 0xA8C, 1)         # count

    # id=5 (FRA): cmd38 -> 0xEA4 branch (other+0x67C=1, rel+0x34=0)
    emu.mem_write(countries_base + 5 * 0x1500 + 0x67C, b'\x01')
    w32(emu, rels_base + 5 * 0x100 + 0x38, cmd_ea4)

    # id=6 (ENG): rel28 match, rel24 kind=0x336 match, cmd38 -> world+0xA84 unlink + dtor
    rel6 = rels_base + 6 * 0x100
    rel28_6 = 0x10010300
    w32(emu, rel28_6 + 0x0C, 6)
    w32(emu, rel6 + 0x28, rel28_6)
    rel24_6 = 0x10010400
    w32(emu, rel24_6 + 0x00, vtbl_base + 0x100)  # kind 0x336
    w32(emu, rel24_6 + 0x14, 6)
    w32(emu, rel6 + 0x24, rel24_6)
    w32(emu, rel6 + 0x38, cmd_del)

    # id=7 (PRU): rel24 kind=0x93A match -> hits both 0xD38 and 0xD48
    rel7 = rels_base + 7 * 0x100
    rel24_7 = 0x10010500
    w32(emu, rel24_7 + 0x00, vtbl_base + 0x200)  # kind 0x93A
    w32(emu, rel24_7 + 0x14, 7)
    w32(emu, rel7 + 0x24, rel24_7)

    # id=8 (RUS): rel20=0, rel24=0, exempt fails via rel+0x70=1 -> pushes 0xD68
    rel8 = rels_base + 8 * 0x100
    emu.mem_write(rel8 + 0x70, b'\x01')

    # Linked list [self+0x9F8] for Step 8 (3 elements: idx 0 -> owner 5 dom 0x42, idx 1 -> owner 6 dom 0x99, idx 2 -> owner 99)
    owners = [5, 6, 99]
    for k, ow in enumerate(owners):
        el = acc_elems + k * 0x200
        w32(emu, acc_arr + k * 4, el)
        w32(emu, el + 0x12C, ow)
        nd = lnodes + k * 16
        w32(emu, nd + 0, k)
        w32(emu, nd + 8, lnodes + (k + 1) * 16 if k + 1 < len(owners) else 0)
    w32(emu, self_ptr + 0x9F8, lnodes)

    trace = []

    def alloc_arena(n: int) -> int:
        p = arena['ptr']
        arena['ptr'] += (n + 15) & ~15
        return p

    def hook_helpers(uc, addr, size, ud):
        if addr == VA_FN_004A8300:
            s = uc.reg_read(UC_X86_REG_EAX)
            trace.append(('4A8300', s))
            uc.reg_write(UC_X86_REG_EAX, 1)
        elif addr == VA_FN_OP_NEW:
            sz = u32(uc, uc.reg_read(UC_X86_REG_ESP) + 4)
            p = alloc_arena(sz)
            trace.append(('op_new', sz, p))
            uc.reg_write(UC_X86_REG_EAX, p)
        elif addr == VA_FN_005163C0:
            buf = uc.reg_read(UC_X86_REG_EAX)
            w32(uc, buf + 0x00, cmd_vtbl)
            trace.append(('5163C0', buf))
            uc.reg_write(UC_X86_REG_EAX, buf)
        elif addr == VA_CMD_V28:
            cmd = uc.reg_read(UC_X86_REG_ECX)
            other_id = u32(uc, cmd + 0x14)
            r = u32(uc, u32(uc, self_ptr + 0xBE8) + other_id * 4)
            w32(uc, r + 0x20, 1)  # exercises volatile re-read at 0x00515FCB!
            trace.append(('cmd_v28', cmd, other_id))
        elif addr == VA_FN_004A7BC0:
            lst = uc.reg_read(UC_X86_REG_ESI)
            item = u32(uc, uc.reg_read(UC_X86_REG_ESP) + 4)
            nd = alloc_arena(16)
            tail = u32(uc, lst + 0x0C)
            cnt = u32(uc, lst + 0x10)
            w32(uc, nd + 0, item)
            w32(uc, nd + 4, tail)
            w32(uc, nd + 8, 0)
            if cnt == 0:
                w32(uc, lst + 0x08, nd)
            else:
                w32(uc, tail + 8, nd)
            w32(uc, lst + 0x0C, nd)
            w32(uc, lst + 0x10, cnt + 1)
            trace.append(('4A7BC0', lst, item))
        elif addr == VA_FN_005F2AE0:
            lst = uc.reg_read(UC_X86_REG_ESI)
            nd = u32(uc, uc.reg_read(UC_X86_REG_ESP) + 4)
            trace.append(('5F2AE0', lst, nd))
            if nd:
                prev_n = u32(uc, nd + 4)
                next_n = u32(uc, nd + 8)
                if prev_n:
                    w32(uc, prev_n + 8, next_n)
                else:
                    w32(uc, lst + 0, next_n)
                if next_n:
                    w32(uc, next_n + 4, prev_n)
                else:
                    w32(uc, lst + 4, prev_n)
                w32(uc, lst + 8, u32(uc, lst + 8) - 1)
            uc.reg_write(UC_X86_REG_EAX, 1 if nd else 0)
        elif addr == VA_CMD_V2C:
            cmd = uc.reg_read(UC_X86_REG_ECX)
            trace.append(('cmd_v2C', cmd))
        elif addr == VA_CMD_V00_DTOR:
            cmd = uc.reg_read(UC_X86_REG_ECX)
            flg = u32(uc, uc.reg_read(UC_X86_REG_ESP) + 4)
            trace.append(('cmd_dtor', cmd, flg))
        elif addr == VA_REL24_KIND_336:
            trace.append(('rel24_kind', uc.reg_read(UC_X86_REG_ECX), 0x336))
            uc.reg_write(UC_X86_REG_EAX, 0x336)
        elif addr == VA_REL24_KIND_93A:
            trace.append(('rel24_kind', uc.reg_read(UC_X86_REG_ECX), 0x93A))
            uc.reg_write(UC_X86_REG_EAX, 0x93A)
        elif addr == VA_REL24_KIND_443:
            trace.append(('rel24_kind', uc.reg_read(UC_X86_REG_ECX), 0x443))
            uc.reg_write(UC_X86_REG_EAX, 0x443)
        elif addr == VA_FN_004D61D0:
            item_p = uc.reg_read(UC_X86_REG_EAX)
            vec = uc.reg_read(UC_X86_REG_EDI)
            tag, oid = struct.unpack('<II', uc.mem_read(item_p, 8))
            end = u32(uc, vec + 4)
            uc.mem_write(end, struct.pack('<II', tag, oid))
            w32(uc, vec + 4, end + 8)
            trace.append(('4D61D0', vec - self_ptr, tag, oid))
        elif addr == VA_FN_004E9B90:
            item_p = uc.reg_read(UC_X86_REG_EAX)
            vec = uc.reg_read(UC_X86_REG_EDI)
            ptr = u32(uc, item_p)
            end = u32(uc, vec + 4)
            w32(uc, end, ptr)
            w32(uc, vec + 4, end + 4)
            trace.append(('4E9B90', vec - self_ptr, ptr))
        elif addr == VA_FN_00511140:
            tag_p = uc.reg_read(UC_X86_REG_EDX)
            other = u32(uc, uc.reg_read(UC_X86_REG_ESP) + 4)
            oid = u32(uc, other + 0x20)
            res = 1 if oid == 5 else 0
            trace.append(('511140', tag_p - self_ptr, oid, res))
            uc.reg_write(UC_X86_REG_EAX, res)
        elif addr == VA_FN_009692C0:
            arg = uc.reg_read(UC_X86_REG_EAX)
            elem = arg - 0x1A8
            oid = u32(uc, elem + 0x12C)
            dom = 0x42 if oid == 5 else 0x99
            trace.append(('9692C0', oid, dom))
            uc.reg_write(UC_X86_REG_EAX, dom)
        elif addr == VA_FN_ROUND:
            fbits = u32(uc, uc.reg_read(UC_X86_REG_ESP) + 4)
            trace.append(('401000', fbits))
        elif addr == VA_FN_FTOL2:
            trace.append(('ftol2',))
            uc.reg_write(UC_X86_REG_EAX, 250)

    emu.hook_add(u.UC_HOOK_CODE, hook_helpers)

    if mode == 'variant_a':
        blob = bytearray((BUILD / 'cr_sese.bin').read_bytes())
        meta = json.loads((BUILD / 'cr_sese_build.json').read_text())
        cfg_off = meta['offsets']['cr_sese_config']
        entry_va = 0x23450000 + meta['offsets']['cr_sese_entry']
        blob[cfg_off:cfg_off + 28] = struct.pack('<7I', IMG_BASE, VA_SESE_EXIT, 0, 0, 0, 0, 0)
        if mutate_reb:
            # Negative control: flip 'REB' compare constant byte 0x52 -> 0x53 in blob
            idx_reb = blob.find(b'\x52\x45\x42\x00')
            if idx_reb != -1:
                blob[idx_reb] = 0x53
            else:
                # Or break total_tags check / [esp+0x18] write by corrupting IMG_BASE in config
                blob[cfg_off + 4:cfg_off + 8] = struct.pack('<I', VA_SESE_EXIT)
                # Flip cmp eax, 0x424552 imm byte
                pos = blob.find(b'\x52\x45\x42')
                assert pos != -1, 'Could not locate REB immediate for negative control'
                blob[pos] = 0x58
        emu.mem_write(0x23450000, bytes(blob))
        emu.mem_protect(0x23450000, 0x2000, u.UC_PROT_READ | u.UC_PROT_EXEC)
        rel = (entry_va - (VA_SESE_ENTRY + 5)) & 0xFFFFFFFF
        emu.mem_write(VA_SESE_ENTRY, b'\xE9' + struct.pack('<I', rel) + b'\x90')
    elif mode != 'orig':
        raise ValueError(mode)

    # Seed FXSAVE state before SESE entry
    fx_seed = make_fx_seed()
    emu.mem_write(0x18008000, fx_seed)

    # Set up caller stack frame at 0x18006000
    esp0 = 0x18006000
    ebp0 = 0x18007000
    w32(emu, esp0 + 0x14, world_ptr)
    w32(emu, esp0 + 0x18, 0xDEADBEEF)  # must become total_tags
    w32(emu, esp0 + 0x20, 0xAAAA2020)  # preserved
    w32(emu, esp0 + 0x28, mgr_ptr)
    w32(emu, esp0 + 0x3C, 0xBBBB3C3C)  # preserved
    w32(emu, esp0 + 0x54, 0xCCCC5454)  # preserved

    emu.reg_write(UC_X86_REG_ESP, esp0)
    emu.reg_write(UC_X86_REG_EBP, ebp0)
    emu.reg_write(UC_X86_REG_EBX, self_ptr)
    emu.reg_write(UC_X86_REG_EFLAGS, 0x00000202)

    # Restore FXSAVE before SESE entry using blob scratch page? Map tiny fx page:
    emu.mem_map(0x20000000, 0x1000, u.UC_PROT_ALL)
    emu.mem_write(0x20000000, b'\x0F\xAE\x0D' + struct.pack('<I', 0x18008000) + b'\x90')
    emu.emu_start(0x20000000, 0x20000007)

    emu.emu_start(VA_SESE_ENTRY, VA_SESE_EXIT, count=500000)

    emu.mem_write(0x20000100, b'\x0F\xAE\x05' + struct.pack('<I', 0x18008400) + b'\x90')
    eflags_after = emu.reg_read(UC_X86_REG_EFLAGS)
    ebx_after = emu.reg_read(UC_X86_REG_EBX)
    ebp_after = emu.reg_read(UC_X86_REG_EBP)
    esp_after = emu.reg_read(UC_X86_REG_ESP)
    emu.emu_start(0x20000100, 0x20000107)
    fx_after = bytes(emu.mem_read(0x18008400, 512))

    # Capture vector dumps + counters + world lists + relations
    vecs = {}
    for idx_v, voff in enumerate(vec_offsets):
        vbuf = 0x10018000 + idx_v * 0x200
        end = u32(emu, self_ptr + voff + 4)
        vecs[hex(voff)] = bytes(emu.mem_read(vbuf, end - vbuf))

    return {
        'ebx': ebx_after,
        'ebp': ebp_after,
        'esp': esp_after,
        'df': (eflags_after >> 10) & 1,
        'slot_18': u32(emu, esp0 + 0x18),
        'slot_20': u32(emu, esp0 + 0x20),
        'slot_3c': u32(emu, esp0 + 0x3C),
        'slot_54': u32(emu, esp0 + 0x54),
        'counters': tuple(u32(emu, self_ptr + o) for o in (0x1AC, 0xDD8, 0xDDC, 0xDE0)),
        'vecs': vecs,
        'rels': bytes(emu.mem_read(rels_base, TOTAL_TAGS * 0x100)),
        'world_list_head': u32(emu, world_ptr + 0xA84),
        'world_list_count': u32(emu, world_ptr + 0xA8C),
        'trace': trace,
        'fx_seed': fx_seed,
        'fx_after': fx_after,
    }


def assert_equiv(orig: dict, cand: dict) -> None:
    assert orig['ebx'] == cand['ebx'], ('EBX mismatch', hex(orig['ebx']), hex(cand['ebx']))
    assert orig['ebp'] == cand['ebp'], ('EBP mismatch', hex(orig['ebp']), hex(cand['ebp']))
    assert orig['esp'] == cand['esp'], ('ESP mismatch', hex(orig['esp']), hex(cand['esp']))
    assert orig['df'] == 0 and cand['df'] == 0, ('DF != 0', orig['df'], cand['df'])
    assert orig['slot_18'] == cand['slot_18'], ('[esp+0x18] mismatch', orig['slot_18'], cand['slot_18'])
    assert orig['slot_20'] == cand['slot_20'] == 0xAAAA2020
    assert orig['slot_3c'] == cand['slot_3c'] == 0xBBBB3C3C
    assert orig['slot_54'] == cand['slot_54'] == 0xCCCC5454
    assert orig['counters'] == cand['counters'], ('counters mismatch', orig['counters'], cand['counters'])
    assert orig['vecs'] == cand['vecs'], 'vector memory mismatch'
    assert orig['rels'] == cand['rels'], 'relations memory mismatch'
    assert orig['world_list_head'] == cand['world_list_head']
    assert orig['world_list_count'] == cand['world_list_count']
    assert orig['trace'] == cand['trace'], ('helper trace mismatch', orig['trace'], cand['trace'])
    # variant (a) preserves 100% of 512B FXSAVE (including XMM0); orig 0x0051624E only overwrote caller-volatile XMM0 with 250.5f
    compare_fx(cand['fx_seed'], cand['fx_after'], 'var_a_preserves_full_fxsave')
    orig_fx_norm = bytearray(orig['fx_after'])
    if any(t[0] == '401000' for t in orig['trace']):
        assert orig_fx_norm[160:176] == bytes.fromhex('00807a43000000000000000000000000')
        orig_fx_norm[160:176] = cand['fx_after'][160:176]
    compare_fx(bytes(orig_fx_norm), cand['fx_after'], 'orig_vs_var_a_fxsave')


def run_sparse_varc_fixture(
    mode: str,
    total_tags: int = 220,
    varc_mode: int = 2,
    pre_seed: bool = False,
    corrupt_idx: int | None = None,
    corrupt_val: int | None = None,
) -> dict:
    """
    220-tag sparse fixture (40 living, 180 dead, matching late-game Vic2 density).
    mode: 'orig' or 'variant_c'
    varc_mode: 1=validate, 2=prod
    """
    pe = pefile.PE(str(BASE_EXE), fast_load=True)
    emu = u.Uc(u.UC_ARCH_X86, u.UC_MODE_32)
    enable_sse_fpu(emu)

    for page in [
        0x00401000, 0x004A7000, 0x004A8000, 0x004D6000, 0x004E9000,
        0x00511000, 0x00515000, 0x005F2000, 0x00920000,
        0x00969000, 0x00AAE000, 0x00B31000, 0x00E45000, 0x01258000,
    ]:
        emu.mem_map(page, 0x2000 if page == 0x00515000 else 0x1000, u.UC_PROT_ALL)

    emu.mem_map(0x10000000, 0x300000, u.UC_PROT_READ | u.UC_PROT_WRITE)
    emu.mem_map(0x18000000, 0x10000, u.UC_PROT_READ | u.UC_PROT_WRITE)
    emu.mem_map(0x23450000, 0x2000, u.UC_PROT_ALL)

    sese_bytes = pe.get_data(VA_SESE_ENTRY - IMG_BASE, VA_SESE_EXIT - VA_SESE_ENTRY)
    emu.mem_write(VA_SESE_ENTRY, sese_bytes)
    emu.mem_write(VA_CONST_250_5F, pe.get_data(VA_CONST_250_5F - IMG_BASE, 4))
    emu.mem_write(VA_SESE_EXIT, b'\x90')

    va_mismatch_cb = 0x00920700
    for addr in [
        VA_FN_004A8300, VA_FN_004D61D0, VA_FN_004E9B90, VA_FN_009692C0,
        VA_FN_005163C0, VA_FN_OP_NEW, VA_FN_ROUND, VA_FN_FTOL2,
        VA_CMD_V28, VA_CMD_V2C, VA_REL24_KIND_336, VA_REL24_KIND_93A, VA_REL24_KIND_443,
        va_mismatch_cb,
    ]:
        emu.mem_write(addr, b'\xC3')
    for addr in [VA_FN_004A7BC0, VA_FN_005F2AE0, VA_FN_00511140, VA_CMD_V00_DTOR]:
        emu.mem_write(addr, b'\xC2\x04\x00')

    world_ptr = 0x10000000
    mgr_ptr = 0x10001000
    entries_arr = 0x10001100
    varc_state_va = 0x10002000
    vtbl_base = 0x10003000
    rel_ptrs = 0x10004000
    rels_base = 0x10005000
    countries_base = 0x10020000
    acc_arr = 0x10003800
    acc_elems = 0x10003900
    lnodes = 0x10003E00
    arena = {'ptr': 0x10280000}

    w32(emu, VA_GLOBAL_WORLD, world_ptr)
    w32(emu, VA_GLOBAL_MGR, mgr_ptr)
    w32(emu, mgr_ptr + 0x00, total_tags)
    w32(emu, mgr_ptr + 0x04, entries_arr)
    w32(emu, world_ptr + 0xB0C, 0x18370101)
    w32(emu, world_ptr + 0xACC, acc_arr)

    cmd_vtbl = vtbl_base
    w32(emu, cmd_vtbl + 0x00, VA_CMD_V00_DTOR)
    w32(emu, cmd_vtbl + 0x28, VA_CMD_V28)
    w32(emu, cmd_vtbl + 0x2C, VA_CMD_V2C)
    for off, fn in [(0x100, VA_REL24_KIND_336), (0x200, VA_REL24_KIND_93A), (0x300, VA_REL24_KIND_443)]:
        w32(emu, vtbl_base + off + 0x1C, fn)

    # Living set: exactly 40 indices including self=1, plus 5,6,7,8 and 35 scattered >=12; id=0 is NON, id=2 is REB
    living_ids = {1, 5, 6, 7, 8}
    i_cand = 12
    while len(living_ids) < 40 and i_cand < total_tags:
        living_ids.add(i_cand)
        i_cand += 5

    self_ptr = countries_base + 1 * 0x1500
    tags_bytes = []
    for i in range(total_tags):
        c = countries_base + i * 0x1500
        if i == 0:
            t = b'NON\x00'
        elif i == 1:
            t = b'SPA\x00'
        elif i == 2:
            t = b'REB\x00'
        else:
            t = bytes([65 + (i % 26), 65 + ((i // 26) % 26), 48 + (i % 10), 0])
        tags_bytes.append(t)
        w32(emu, entries_arr + i * 4, c)
        emu.mem_write(c + 0x1C, t)
        w32(emu, c + 0x20, i)
        w32(emu, c + 0x9D8, 0x11000000)
        # Keep id=2 (REB) having prov_size=16 to confirm 'REB' exclusion bit=0; id=3 dead(0); id=4 dead(3 & ~3 == 0)
        if i == 2 or i in living_ids:
            psz = 16
        elif i == 4:
            psz = 3
        else:
            psz = 0
        w32(emu, c + 0x9DC, 0x11000000 + psz)

        r = rels_base + i * 0x100
        w32(emu, rel_ptrs + i * 4, r)
        w32(emu, r + 0x08, struct.unpack('<I', t)[0])
        w32(emu, r + 0x0C, i)
        if i >= 12 and (i in living_ids) and (i % 2 == 0):
            emu.mem_write(r + 0x70, b'\x01')

    emu.mem_write(self_ptr + 0xCF4, b'\x01')
    emu.mem_write(self_ptr + 0xCF5, b'\x01')
    w32(emu, self_ptr + 0x7D8, 1)
    w32(emu, self_ptr + 0xCFC, 5)
    w32(emu, self_ptr + 0xBE8, rel_ptrs)
    w32(emu, self_ptr + 0xE64, 0x42)
    w32(emu, self_ptr + 0x1AC, 1000)
    w32(emu, self_ptr + 0x142C, 99)

    vec_offsets = [0xD38, 0xD48, 0xD58, 0xD68, 0xD78, 0xEA4, 0xEB4]
    for idx_v, voff in enumerate(vec_offsets):
        vbuf = 0x10290000 + idx_v * 0x1000
        w32(emu, self_ptr + voff + 0x00, vbuf)
        w32(emu, self_ptr + voff + 0x04, vbuf)
        w32(emu, self_ptr + voff + 0x08, vbuf + 0x1000)

    cmd_ea4 = 0x10003400
    w32(emu, cmd_ea4 + 0x00, cmd_vtbl)
    cmd_del = 0x10003500
    w32(emu, cmd_del + 0x00, cmd_vtbl)
    node_a84 = 0x10003600
    w32(emu, node_a84 + 0x00, cmd_del)
    w32(emu, world_ptr + 0xA84, node_a84)
    w32(emu, world_ptr + 0xA88, node_a84)
    w32(emu, world_ptr + 0xA8C, 1)

    emu.mem_write(countries_base + 5 * 0x1500 + 0x67C, b'\x01')
    w32(emu, rels_base + 5 * 0x100 + 0x38, cmd_ea4)

    rel6 = rels_base + 6 * 0x100
    rel28_6 = 0x10003680
    w32(emu, rel28_6 + 0x0C, 6)
    w32(emu, rel6 + 0x28, rel28_6)
    rel24_6 = 0x100036C0
    w32(emu, rel24_6 + 0x00, vtbl_base + 0x100)
    w32(emu, rel24_6 + 0x14, 6)
    w32(emu, rel6 + 0x24, rel24_6)
    w32(emu, rel6 + 0x38, cmd_del)

    rel7 = rels_base + 7 * 0x100
    rel24_7 = 0x10003700
    w32(emu, rel24_7 + 0x00, vtbl_base + 0x200)
    w32(emu, rel24_7 + 0x14, 7)
    w32(emu, rel7 + 0x24, rel24_7)

    emu.mem_write(rels_base + 8 * 0x100 + 0x70, b'\x01')

    owners = [5, 6, 99]
    for k, ow in enumerate(owners):
        el = acc_elems + k * 0x200
        w32(emu, acc_arr + k * 4, el)
        w32(emu, el + 0x12C, ow)
        nd = lnodes + k * 16
        w32(emu, nd + 0, k)
        w32(emu, nd + 8, lnodes + (k + 1) * 16 if k + 1 < len(owners) else 0)
    w32(emu, self_ptr + 0x9F8, lnodes)

    if pre_seed:
        words = [0] * 128
        for lid in living_ids:
            words[lid >> 5] |= (1 << (lid & 31))
        if corrupt_idx is not None and corrupt_val is not None:
            if corrupt_val:
                words[corrupt_idx >> 5] |= (1 << (corrupt_idx & 31))
            else:
                words[corrupt_idx >> 5] &= ~(1 << (corrupt_idx & 31))
        for w_i, val in enumerate(words):
            w32(emu, varc_state_va + w_i * 4, val)
        # initialized=1, dirty=0, total_tags, entries_ptr, exe_base, validate_mode
        w32(emu, varc_state_va + 512, 1)
        w32(emu, varc_state_va + 516, 0)
        w32(emu, varc_state_va + 520, total_tags)
        w32(emu, varc_state_va + 524, entries_arr)
        w32(emu, varc_state_va + 528, IMG_BASE)
        w32(emu, varc_state_va + 532, 1 if varc_mode == 1 else 0)

    w32(emu, varc_state_va + 552, va_mismatch_cb)  # CRVarCState.mismatch_cb

    trace = []
    mismatches = []

    def alloc_arena(n: int) -> int:
        p = arena['ptr']
        arena['ptr'] += (n + 15) & ~15
        return p

    def hook_helpers(uc, addr, size, ud):
        if addr == va_mismatch_cb:
            sp = uc.reg_read(UC_X86_REG_ESP)
            mismatches.append((u32(uc, sp + 4), u32(uc, sp + 8), u32(uc, sp + 12), u32(uc, sp + 16)))
        elif addr == VA_FN_004A8300:
            s = uc.reg_read(UC_X86_REG_EAX)
            trace.append(('4A8300', s))
            uc.reg_write(UC_X86_REG_EAX, 1)
        elif addr == VA_FN_OP_NEW:
            sz = u32(uc, uc.reg_read(UC_X86_REG_ESP) + 4)
            p = alloc_arena(sz)
            trace.append(('op_new', sz, p))
            uc.reg_write(UC_X86_REG_EAX, p)
        elif addr == VA_FN_005163C0:
            buf = uc.reg_read(UC_X86_REG_EAX)
            w32(uc, buf + 0x00, cmd_vtbl)
            trace.append(('5163C0', buf))
            uc.reg_write(UC_X86_REG_EAX, buf)
        elif addr == VA_CMD_V28:
            cmd = uc.reg_read(UC_X86_REG_ECX)
            other_id = u32(uc, cmd + 0x14)
            r = u32(uc, u32(uc, self_ptr + 0xBE8) + other_id * 4)
            w32(uc, r + 0x20, 1)
            trace.append(('cmd_v28', cmd, other_id))
        elif addr == VA_FN_004A7BC0:
            lst = uc.reg_read(UC_X86_REG_ESI)
            item = u32(uc, uc.reg_read(UC_X86_REG_ESP) + 4)
            nd = alloc_arena(16)
            tail = u32(uc, lst + 0x0C)
            cnt = u32(uc, lst + 0x10)
            w32(uc, nd + 0, item)
            w32(uc, nd + 4, tail)
            w32(uc, nd + 8, 0)
            if cnt == 0:
                w32(uc, lst + 0x08, nd)
            else:
                w32(uc, tail + 8, nd)
            w32(uc, lst + 0x0C, nd)
            w32(emu, lst + 0x10, cnt + 1)
            trace.append(('4A7BC0', lst, item))
        elif addr == VA_FN_005F2AE0:
            lst = uc.reg_read(UC_X86_REG_ESI)
            nd = u32(uc, uc.reg_read(UC_X86_REG_ESP) + 4)
            trace.append(('5F2AE0', lst, nd))
            if nd:
                prev_n = u32(uc, nd + 4)
                next_n = u32(uc, nd + 8)
                if prev_n:
                    w32(uc, prev_n + 8, next_n)
                else:
                    w32(uc, lst + 0, next_n)
                if next_n:
                    w32(uc, next_n + 4, prev_n)
                else:
                    w32(uc, lst + 4, prev_n)
                w32(uc, lst + 8, u32(uc, lst + 8) - 1)
            uc.reg_write(UC_X86_REG_EAX, 1 if nd else 0)
        elif addr == VA_CMD_V2C:
            trace.append(('cmd_v2C', uc.reg_read(UC_X86_REG_ECX)))
        elif addr == VA_CMD_V00_DTOR:
            trace.append(('cmd_dtor', uc.reg_read(UC_X86_REG_ECX), u32(uc, uc.reg_read(UC_X86_REG_ESP) + 4)))
        elif addr == VA_REL24_KIND_336:
            trace.append(('rel24_kind', uc.reg_read(UC_X86_REG_ECX), 0x336))
            uc.reg_write(UC_X86_REG_EAX, 0x336)
        elif addr == VA_REL24_KIND_93A:
            trace.append(('rel24_kind', uc.reg_read(UC_X86_REG_ECX), 0x93A))
            uc.reg_write(UC_X86_REG_EAX, 0x93A)
        elif addr == VA_FN_004D61D0:
            item_p = uc.reg_read(UC_X86_REG_EAX)
            vec = uc.reg_read(UC_X86_REG_EDI)
            tag, oid = struct.unpack('<II', uc.mem_read(item_p, 8))
            end = u32(uc, vec + 4)
            uc.mem_write(end, struct.pack('<II', tag, oid))
            w32(uc, vec + 4, end + 8)
            trace.append(('4D61D0', vec - self_ptr, tag, oid))
        elif addr == VA_FN_004E9B90:
            item_p = uc.reg_read(UC_X86_REG_EAX)
            vec = uc.reg_read(UC_X86_REG_EDI)
            ptr = u32(uc, item_p)
            end = u32(uc, vec + 4)
            w32(uc, end, ptr)
            w32(uc, vec + 4, end + 4)
            trace.append(('4E9B90', vec - self_ptr, ptr))
        elif addr == VA_FN_00511140:
            tag_p = uc.reg_read(UC_X86_REG_EDX)
            other = u32(uc, uc.reg_read(UC_X86_REG_ESP) + 4)
            oid = u32(uc, other + 0x20)
            res = 1 if oid == 5 else 0
            trace.append(('511140', tag_p - self_ptr, oid, res))
            uc.reg_write(UC_X86_REG_EAX, res)
        elif addr == VA_FN_009692C0:
            elem = uc.reg_read(UC_X86_REG_EAX) - 0x1A8
            oid = u32(uc, elem + 0x12C)
            dom = 0x42 if oid == 5 else 0x99
            trace.append(('9692C0', oid, dom))
            uc.reg_write(UC_X86_REG_EAX, dom)
        elif addr == VA_FN_ROUND:
            trace.append(('401000', u32(uc, uc.reg_read(UC_X86_REG_ESP) + 4)))
        elif addr == VA_FN_FTOL2:
            trace.append(('ftol2',))
            uc.reg_write(UC_X86_REG_EAX, 250)

    emu.hook_add(u.UC_HOOK_CODE, hook_helpers)

    if mode == 'variant_c':
        blob = bytearray((BUILD / 'cr_sese_varc.bin').read_bytes())
        meta = json.loads((BUILD / 'cr_sese_varc_build.json').read_text())
        cfg_off = meta['offsets']['cr_sese_config']
        entry_va = 0x23450000 + meta['offsets']['cr_sese_entry']
        blob[cfg_off:cfg_off + 28] = struct.pack('<7I', IMG_BASE, VA_SESE_EXIT, 0, 0, varc_state_va, varc_mode, 0)
        emu.mem_write(0x23450000, bytes(blob))
        emu.mem_protect(0x23450000, 0x2000, u.UC_PROT_READ | u.UC_PROT_EXEC)
        rel = (entry_va - (VA_SESE_ENTRY + 5)) & 0xFFFFFFFF
        emu.mem_write(VA_SESE_ENTRY, b'\xE9' + struct.pack('<I', rel) + b'\x90')
    elif mode != 'orig':
        raise ValueError(mode)

    fx_seed = make_fx_seed()
    emu.mem_write(0x18008000, fx_seed)
    esp0 = 0x18006000
    ebp0 = 0x18007000
    w32(emu, esp0 + 0x14, world_ptr)
    w32(emu, esp0 + 0x18, 0xDEADBEEF)
    w32(emu, esp0 + 0x20, 0xAAAA2020)
    w32(emu, esp0 + 0x28, mgr_ptr)
    w32(emu, esp0 + 0x3C, 0xBBBB3C3C)
    w32(emu, esp0 + 0x54, 0xCCCC5454)
    emu.reg_write(UC_X86_REG_ESP, esp0)
    emu.reg_write(UC_X86_REG_EBP, ebp0)
    emu.reg_write(UC_X86_REG_EBX, self_ptr)
    emu.reg_write(UC_X86_REG_EFLAGS, 0x00000202)

    emu.mem_map(0x20000000, 0x1000, u.UC_PROT_ALL)
    emu.mem_write(0x20000000, b'\x0F\xAE\x0D' + struct.pack('<I', 0x18008000) + b'\x90')
    emu.emu_start(0x20000000, 0x20000007)

    emu.emu_start(VA_SESE_ENTRY, VA_SESE_EXIT, count=1500000)

    emu.mem_write(0x20000100, b'\x0F\xAE\x05' + struct.pack('<I', 0x18008400) + b'\x90')
    eflags_after = emu.reg_read(UC_X86_REG_EFLAGS)
    ebx_after = emu.reg_read(UC_X86_REG_EBX)
    ebp_after = emu.reg_read(UC_X86_REG_EBP)
    esp_after = emu.reg_read(UC_X86_REG_ESP)
    emu.emu_start(0x20000100, 0x20000107)
    fx_after = bytes(emu.mem_read(0x18008400, 512))

    vecs = {}
    for idx_v, voff in enumerate(vec_offsets):
        vbuf = 0x10290000 + idx_v * 0x1000
        end = u32(emu, self_ptr + voff + 4)
        vecs[hex(voff)] = bytes(emu.mem_read(vbuf, end - vbuf))

    return {
        'ebx': ebx_after,
        'ebp': ebp_after,
        'esp': esp_after,
        'df': (eflags_after >> 10) & 1,
        'slot_18': u32(emu, esp0 + 0x18),
        'slot_20': u32(emu, esp0 + 0x20),
        'slot_3c': u32(emu, esp0 + 0x3C),
        'slot_54': u32(emu, esp0 + 0x54),
        'counters': tuple(u32(emu, self_ptr + o) for o in (0x1AC, 0xDD8, 0xDDC, 0xDE0)),
        'vecs': vecs,
        'rels': bytes(emu.mem_read(rels_base, total_tags * 0x100)),
        'world_list_head': u32(emu, world_ptr + 0xA84),
        'world_list_count': u32(emu, world_ptr + 0xA8C),
        'trace': trace,
        'fx_seed': fx_seed,
        'fx_after': fx_after,
        'mismatch_count': u32(emu, varc_state_va + 536),
        'last_mismatch': (
            u32(emu, varc_state_va + 540),
            u32(emu, varc_state_va + 544),
            u32(emu, varc_state_va + 548),
        ),
        'mismatches_cb': mismatches,
        'alive_bits_0_7': [u32(emu, varc_state_va + 4 * k) for k in range(7)],
    }


def main() -> None:
    # 1. Full multi-country/relation/list equivalence (total_tags = 9)
    orig = run_sese_fixture('orig', total_tags=TOTAL_TAGS)
    var_a = run_sese_fixture('variant_a', total_tags=TOTAL_TAGS)
    assert_equiv(orig, var_a)
    assert var_a['slot_18'] == TOTAL_TAGS
    assert var_a['counters'] == (1000 + 0x3E8 + 250, 1, 2, 1), var_a['counters']
    assert var_a['world_list_head'] != 0 and var_a['world_list_count'] == 1

    # 2. Empty country_mgr early exit (total_tags = 0)
    orig0 = run_sese_fixture('orig', total_tags=0)
    var_a0 = run_sese_fixture('variant_a', total_tags=0)
    assert_equiv(orig0, var_a0)
    assert var_a0['slot_18'] == 0 and var_a0['trace'] == []

    # 3. Negative control: mutated variant (a) MUST be caught!
    bad = run_sese_fixture('variant_a', total_tags=TOTAL_TAGS, mutate_reb=True)
    caught = False
    try:
        assert_equiv(orig, bad)
    except AssertionError:
        caught = True
    assert caught, 'Negative control failed: equivalence check did not catch REB filter mutation!'

    # 4. Variant (c) sparse 220-tag fixture (40 living / 180 dead): lazy-init + steady-state + validate
    orig_220 = run_sparse_varc_fixture('orig', total_tags=220)
    varc_lazy = run_sparse_varc_fixture('variant_c', total_tags=220, varc_mode=2, pre_seed=False)
    varc_steady = run_sparse_varc_fixture('variant_c', total_tags=220, varc_mode=2, pre_seed=True)
    varc_val_ok = run_sparse_varc_fixture('variant_c', total_tags=220, varc_mode=1, pre_seed=True)
    for label, res in (('lazy', varc_lazy), ('steady', varc_steady), ('validate_ok', varc_val_ok)):
        assert_equiv(orig_220, res)
        assert res['slot_18'] == 220
        assert res['mismatch_count'] == 0, (label, res['mismatch_count'])
        assert res['mismatches_cb'] == []
        # Verify REB (bit 2) and NON (bit 0) stay 0 in alive_bits[0]
        assert (res['alive_bits_0_7'][0] & 0x5) == 0, hex(res['alive_bits_0_7'][0])

    # 5. Variant (c) validate negative controls: missing bit (7) and extra bit (3 dead, 2 REB)
    neg_miss = run_sparse_varc_fixture('variant_c', total_tags=220, varc_mode=1, pre_seed=True, corrupt_idx=7, corrupt_val=0)
    assert neg_miss['mismatch_count'] == 1 and neg_miss['last_mismatch'] == (7, 1, 0), neg_miss['last_mismatch']
    assert neg_miss['mismatches_cb'] == [(7, 1, 0, 1)]
    assert_equiv(orig_220, neg_miss)  # Repaired and executed SESE body EXACTLY ONCE

    neg_extra_dead = run_sparse_varc_fixture('variant_c', total_tags=220, varc_mode=1, pre_seed=True, corrupt_idx=3, corrupt_val=1)
    assert neg_extra_dead['mismatch_count'] == 1 and neg_extra_dead['last_mismatch'] == (3, 0, 1)
    assert neg_extra_dead['mismatches_cb'] == [(3, 0, 1, 1)]
    assert_equiv(orig_220, neg_extra_dead)

    neg_extra_reb = run_sparse_varc_fixture('variant_c', total_tags=220, varc_mode=1, pre_seed=True, corrupt_idx=2, corrupt_val=1)
    assert neg_extra_reb['mismatch_count'] == 1 and neg_extra_reb['last_mismatch'] == (2, 0, 1)
    assert neg_extra_reb['mismatches_cb'] == [(2, 0, 1, 1)]
    assert_equiv(orig_220, neg_extra_reb)

    print(
        'Unicorn Country_Recalculate SESE equivalence PASS: 7/7 checks verified '
        f'(var_a 9-tag trace len={len(var_a["trace"])}, total_tags=0, var_a REB neg-control, '
        f'var_c 220-tag [40 living/180 dead] trace len={len(varc_steady["trace"])}, '
        'var_c validate missing/extra/REB neg-controls caught & single-exec).'
    )


if __name__ == '__main__':
    main()
