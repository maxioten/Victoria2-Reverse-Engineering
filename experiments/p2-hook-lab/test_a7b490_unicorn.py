"""Unicorn equivalence & safety suite for Paso B HighPerfWinClock (0x00A7B0F0 + 0x00A7B490 + 0x00A7B850)."""
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
VA_CTOR_TAIL = 0x00A7B42A
VA_CTOR_SKIP = 0x00A7B433
VA_CTOR_END = 0x00A7B48B
VA_DTOR = 0x00A7B490
VA_DTOR_END = 0x00A7B4D6
VA_ATEXIT = 0x00A7B850
VA_ATEXIT_END = 0x00A7B892
VA_UNLINK = 0x00A7B8A0
VA_UNLINK_END = 0x00A7B909
VA_OP_DELETE = 0x00AAE91B
VA_OP_NEW = 0x00AAE9AF
VA_BASE_VTABLE = 0x00E388A8
VA_DERIVED_VTABLE = 0x00E43A88
VA_HEAD = 0x013F0758
VA_TAIL = 0x013F075C
VA_COUNT = 0x013F0760
VA_DEFER_FLAG = 0x013F0764


def find_map_symbol_rva(map_path: Path, sym: str) -> int:
    for line in map_path.read_text().splitlines():
        parts = line.strip().split()
        if parts and parts[-1] == sym:
            return int(parts[0], 16)
    raise RuntimeError(f'Symbol {sym} not found in {map_path}')


def make_cfg_bytes(orig_target: int, handler_fn: int, mode: int, arg_bytes: int, flags: int, user_data: int) -> bytes:
    return struct.pack('<IIIIIIII', orig_target, handler_fn, mode, arg_bytes, flags, 0xFFFFFFFF, user_data, 0)


def setup_v2_emu() -> tuple[u.Uc, dict]:
    pe = pefile.PE(str(BASE_EXE), fast_load=True)
    emu = u.Uc(u.UC_ARCH_X86, u.UC_MODE_32)
    enable_sse_fpu(emu)

    # Map code pages for 0x00A7B000..0x00A7C000 and 0x00AAE000..0x00AAF000
    emu.mem_map(0x00A7B000, 0x1000, u.UC_PROT_ALL)
    emu.mem_map(0x00AAE000, 0x1000, u.UC_PROT_ALL)
    # Map .bss globals 0x013F0000..0x013F1000
    emu.mem_map(0x013F0000, 0x1000, u.UC_PROT_READ | u.UC_PROT_WRITE)
    # Map fake heap objects + nodes 0x10000000..0x10004000
    emu.mem_map(0x10000000, 0x4000, u.UC_PROT_READ | u.UC_PROT_WRITE)
    # Map stack + sentinel return page
    emu.mem_map(0x18000000, 0x10000, u.UC_PROT_READ | u.UC_PROT_WRITE)
    emu.mem_map(0x20000000, 0x1000, u.UC_PROT_ALL)  # sentinel ret target

    # Copy exact original machine code slices from base-game/v2game.exe
    for va, end in [
        (VA_CTOR_TAIL, VA_CTOR_END),
        (VA_DTOR, VA_DTOR_END),
        (VA_ATEXIT, VA_ATEXIT_END),
        (VA_UNLINK, VA_UNLINK_END),
    ]:
        emu.mem_write(va, pe.get_data(va - IMG_BASE, end - va))

    # Map build/hook.bin at rebased PIC address 0x23450000 and build/v2p2.dll at 0x30000000
    blob = bytearray((BUILD / 'hook.bin').read_bytes())
    meta = json.loads((BUILD / 'build.json').read_text())
    offsets = meta['offsets']
    blob_base = 0x23450000

    v2p2_pe = pefile.PE(str(BUILD / 'v2p2.dll'), fast_load=False)
    dll_base = 0x30000000
    v2p2_pe.relocate_image(dll_base)
    dll_img = v2p2_pe.get_memory_mapped_image(ImageBase=dll_base)
    dll_map_size = (len(dll_img) + 0xFFF) & ~0xFFF
    emu.mem_map(dll_base, dll_map_size, u.UC_PROT_ALL)
    emu.mem_write(dll_base, dll_img)
    handler_rva = find_map_symbol_rva(BUILD / 'v2p2.map', '_p2_dtor_a7b490_handler')
    handler_va = dll_base + handler_rva

    emu.mem_map(blob_base, 0x1000, u.UC_PROT_READ | u.UC_PROT_EXEC | u.UC_PROT_WRITE)
    cfg = make_cfg_bytes(VA_DTOR, handler_va, 1, 4, 0, IMG_BASE)
    cfg_off = offsets['p2_hook_config']
    blob[cfg_off:cfg_off + len(cfg)] = cfg
    emu.mem_write(blob_base, bytes(blob))
    # Seal blob page RX (W^X)
    emu.mem_protect(blob_base, 0x1000, u.UC_PROT_READ | u.UC_PROT_EXEC)

    # Place sentinel ret at 0x20000000
    emu.mem_write(0x20000000, b'\x90')

    # Dirtying cdecl operator delete stub at VA_OP_DELETE:
    # Intentionally dirties XMM0, ST(0), EFLAGS, EAX, ECX, EDX before ret!
    del_stub = bytes([
        0x55,                                # push ebp
        0x89, 0xE5,                          # mov ebp, esp
        0xD9, 0xE8,                          # fld1 (leaves x87 stack dirty)
        0x0F, 0x57, 0xC0,                    # xorps xmm0, xmm0 (clobbers xmm0)
        0xF9,                                # stc (clobbers CF)
        0xB8, 0xAA, 0xBB, 0xCC, 0xDD,        # mov eax, 0xddccbbaa
        0xB9, 0x11, 0x22, 0x33, 0x44,        # mov ecx, 0x44332211
        0xBA, 0x55, 0x66, 0x77, 0x88,        # mov edx, 0x88776655
        0x5D,                                # pop ebp
        0xC3,                                # ret
    ])
    emu.mem_write(VA_OP_DELETE, del_stub)
    emu.mem_write(VA_OP_NEW, b'\x31\xC0\xC3')  # xor eax, eax; ret (sentinel; must never run in patched ctor)

    info = {
        'blob_entry': blob_base + offsets['p2_hook_entry'],
        'handler_va': handler_va,
        'ret_stop': 0x20000000,
    }
    return emu, info


def run_dtor_case(use_p2: bool, flags_arg: int, populated_list: bool) -> dict:
    emu, info = setup_v2_emu()
    this_ptr = 0x10000100
    emu.mem_write(this_ptr, struct.pack('<I', VA_DERIVED_VTABLE))

    if populated_list:
        node_a, node_b, node_c = 0x10001000, 0x10001020, 0x10001040
        emu.mem_write(node_a, struct.pack('<IIII', 0x10000200, 0, node_b, 0))
        emu.mem_write(node_b, struct.pack('<IIII', this_ptr, node_a, node_c, 0))
        emu.mem_write(node_c, struct.pack('<IIII', 0x10000300, node_b, 0, 0))
        emu.mem_write(VA_HEAD, struct.pack('<IIII', node_a, node_c, 3, 0))
    else:
        emu.mem_write(VA_HEAD, struct.pack('<IIII', 0, 0, 0, 0))

    deletes = []
    vtable_at_delete = []
    new_calls = []

    def hook_code(uc, address, size, user_data):
        if address == VA_OP_DELETE:
            esp_now = uc.reg_read(UC_X86_REG_ESP)
            arg0 = struct.unpack('<I', uc.mem_read(esp_now + 4, 4))[0]
            deletes.append(arg0)
            if arg0 == this_ptr:
                vt = struct.unpack('<I', uc.mem_read(this_ptr, 4))[0]
                vtable_at_delete.append(vt)
        elif address == VA_OP_NEW:
            new_calls.append(address)

    emu.hook_add(u.UC_HOOK_CODE, hook_code)

    # Seed FXSAVE state on stack and load via fxrstor
    fx_seed = make_fx_seed()
    emu.mem_write(0x18008000, fx_seed)
    emu.mem_write(0x20000100, b'\x0F\xAE\x0D' + struct.pack('<I', 0x18008000) + b'\x90')
    emu.emu_start(0x20000100, 0x20000107)

    # Initial stack for __thiscall(ECX=this_ptr, [esp+4]=flags_arg)
    esp0 = 0x18007000
    emu.mem_write(esp0, struct.pack('<II', info['ret_stop'], flags_arg))
    emu.reg_write(UC_X86_REG_ESP, esp0)
    emu.reg_write(UC_X86_REG_ECX, this_ptr)
    emu.reg_write(UC_X86_REG_EAX, 0xCAFEBABE)
    emu.reg_write(UC_X86_REG_EBX, 0x12345678)
    emu.reg_write(UC_X86_REG_EDX, 0x9ABCDEF0)
    emu.reg_write(UC_X86_REG_ESI, 0x55667788)
    emu.reg_write(UC_X86_REG_EDI, 0x99AABBCC)
    emu.reg_write(UC_X86_REG_EBP, 0x18009000)
    # Set CF=1, PF=1, ZF=1, DF=1, OF=1, IF=1
    eflags_init = 0x00000202 | (1 << 0) | (1 << 2) | (1 << 6) | (1 << 10) | (1 << 11)
    emu.reg_write(UC_X86_REG_EFLAGS, eflags_init)

    start_pc = info['blob_entry'] if use_p2 else VA_DTOR
    emu.emu_start(start_pc, info['ret_stop'], count=200000)

    # Capture FXSAVE after call (clear DF first or not — fxsave doesn't care)
    emu.mem_write(0x20000200, b'\x0F\xAE\x05' + struct.pack('<I', 0x18008400) + b'\x90')
    eflags_after = emu.reg_read(UC_X86_REG_EFLAGS)
    eax_after = emu.reg_read(UC_X86_REG_EAX)
    esp_after = emu.reg_read(UC_X86_REG_ESP)
    gprs_after = {
        'ebx': emu.reg_read(UC_X86_REG_EBX),
        'ecx': emu.reg_read(UC_X86_REG_ECX),
        'edx': emu.reg_read(UC_X86_REG_EDX),
        'esi': emu.reg_read(UC_X86_REG_ESI),
        'edi': emu.reg_read(UC_X86_REG_EDI),
        'ebp': emu.reg_read(UC_X86_REG_EBP),
    }
    emu.emu_start(0x20000200, 0x20000207)
    fx_after = bytes(emu.mem_read(0x18008400, 512))

    vtable_after = struct.unpack('<I', emu.mem_read(this_ptr, 4))[0]
    globals_after = struct.unpack('<IIII', emu.mem_read(VA_HEAD, 16))
    return {
        'eax': eax_after,
        'esp': esp_after,
        'esp_delta': esp_after - esp0,
        'eflags_init': eflags_init,
        'eflags_after': eflags_after,
        'gprs': gprs_after,
        'vtable_after': vtable_after,
        'vtable_at_delete': vtable_at_delete,
        'deletes': deletes,
        'globals_after': globals_after,
        'fx_seed': fx_seed,
        'fx_after': fx_after,
    }


def verify_ctor_skip_and_atexit() -> None:
    emu, info = setup_v2_emu()
    # Apply the exact 6-byte inline patch at 0x00A7B433: add esp, 4; jmp short 0x00A7B476; nop
    emu.mem_write(VA_CTOR_SKIP, b'\x83\xC4\x04\xEB\x3E\x90')
    emu.mem_write(VA_HEAD, struct.pack('<IIII', 0, 0, 0, 0))

    op_calls = []
    emu.hook_add(
        u.UC_HOOK_CODE,
        lambda uc, addr, sz, ud: op_calls.append(addr) if addr in (VA_OP_NEW, VA_OP_DELETE) else None,
    )

    # Set up GDT: 0x08=FS(base fs_base), 0x10=flat 32-bit CS, 0x18=flat 32-bit DS/ES/SS
    fs_base = 0x10003000
    gdt_base = 0x10003800
    fs_desc = struct.pack('<HHBBBB', 0x0FFF, fs_base & 0xFFFF, (fs_base >> 16) & 0xFF, 0x93, 0x40, (fs_base >> 24) & 0xFF)
    cs_desc = struct.pack('<HHBBBB', 0xFFFF, 0, 0, 0x9B, 0xCF, 0)
    ds_desc = struct.pack('<HHBBBB', 0xFFFF, 0, 0, 0x93, 0xCF, 0)
    emu.mem_write(gdt_base + 0x08, fs_desc)
    emu.mem_write(gdt_base + 0x10, cs_desc)
    emu.mem_write(gdt_base + 0x18, ds_desc)
    emu.reg_write(UC_X86_REG_GDTR, (0, gdt_base, 0x3F, 0))
    emu.reg_write(UC_X86_REG_CS, 0x10)
    emu.reg_write(UC_X86_REG_DS, 0x18)
    emu.reg_write(UC_X86_REG_ES, 0x18)
    emu.reg_write(UC_X86_REG_SS, 0x18)
    emu.reg_write(UC_X86_REG_FS, 0x08)

    # Initialize FPU and load ST(0) = 10000000.0 (freq) as set before 0x00A7B42A
    freq_addr = 0x10002000
    emu.mem_write(freq_addr, struct.pack('<d', 10000000.0))
    emu.mem_write(0x20000300, b'\xDB\xE3\xDD\x05' + struct.pack('<I', freq_addr) + b'\x90')  # fninit; fld qword [freq_addr]
    emu.emu_start(0x20000300, 0x20000308)

    this_ptr = 0x10000100
    ebp0 = 0x18009000
    esp0 = ebp0 - 0x20
    saved_seh = 0x18009FFC
    saved_ebp = 0x1800A000
    saved_ebx = 0x11112222
    saved_esi = 0x33334444
    saved_edi = 0x55556666
    dummy_arg = 0xCAFE0001

    emu.mem_write(ebp0 - 0x0C, struct.pack('<I', saved_seh))
    emu.mem_write(ebp0, struct.pack('<III', saved_ebp, info['ret_stop'], dummy_arg))
    # 0x00A7B479..0x00A7B484 expects [esp]=saved_edi, saved_esi, saved_ebx before mov esp, ebp
    emu.mem_write(esp0, struct.pack('<III', saved_edi, saved_esi, saved_ebx))
    emu.reg_write(UC_X86_REG_ESP, esp0)
    emu.reg_write(UC_X86_REG_EBP, ebp0)
    emu.reg_write(UC_X86_REG_ESI, this_ptr)

    emu.emu_start(VA_CTOR_TAIL, info['ret_stop'], count=200000)

    assert op_calls == [], f'Patched ctor must not call new/delete, got {op_calls}'
    assert emu.reg_read(UC_X86_REG_EAX) == this_ptr
    assert emu.reg_read(UC_X86_REG_ESP) == ebp0 + 12  # popped saved_ebp + retaddr + 4-byte arg
    assert emu.reg_read(UC_X86_REG_EBP) == saved_ebp
    assert emu.reg_read(UC_X86_REG_EBX) == saved_ebx
    assert emu.reg_read(UC_X86_REG_ESI) == saved_esi
    assert emu.reg_read(UC_X86_REG_EDI) == saved_edi
    inv_freq = struct.unpack('<d', emu.mem_read(this_ptr + 0x18, 8))[0]
    assert abs(inv_freq - 1e-7) < 1e-18, inv_freq
    assert struct.unpack('<IIII', emu.mem_read(VA_HEAD, 16)) == (0, 0, 0, 0)
    assert struct.unpack('<I', emu.mem_read(fs_base, 4))[0] == saved_seh

    # Now execute real atexit cleanup 0x00A7B850 with {0,0,0}
    esp_ax = 0x18007000
    emu.mem_write(esp_ax, struct.pack('<I', info['ret_stop']))
    emu.reg_write(UC_X86_REG_ESP, esp_ax)
    emu.emu_start(VA_ATEXIT, info['ret_stop'], count=200000)
    assert op_calls == [], f'atexit with empty list must not call operator delete, got {op_calls}'
    assert emu.reg_read(UC_X86_REG_ESP) == esp_ax + 4
    assert struct.unpack('<IIII', emu.mem_read(VA_HEAD, 16)) == (0, 0, 0, 0)


def main() -> None:
    this_ptr = 0x10000100

    # 1. Original dtor on empty list & populated list (flags = 0 and 1)
    orig_empty_0 = run_dtor_case(use_p2=False, flags_arg=0, populated_list=False)
    orig_empty_1 = run_dtor_case(use_p2=False, flags_arg=1, populated_list=False)
    orig_pop_0 = run_dtor_case(use_p2=False, flags_arg=0, populated_list=True)
    orig_pop_1 = run_dtor_case(use_p2=False, flags_arg=1, populated_list=True)

    assert orig_empty_0['eax'] == this_ptr and orig_empty_0['esp_delta'] == 8
    assert orig_empty_0['vtable_after'] == VA_BASE_VTABLE and orig_empty_0['deletes'] == []
    assert orig_empty_1['eax'] == this_ptr and orig_empty_1['esp_delta'] == 8
    assert orig_empty_1['vtable_at_delete'] == [VA_BASE_VTABLE] and orig_empty_1['deletes'] == [this_ptr]

    assert orig_pop_0['eax'] == this_ptr and orig_pop_0['esp_delta'] == 8
    assert orig_pop_0['vtable_after'] == VA_BASE_VTABLE and orig_pop_0['deletes'] == [0x10001020]
    assert orig_pop_0['globals_after'][2] == 2
    assert orig_pop_1['eax'] == this_ptr and orig_pop_1['esp_delta'] == 8
    assert orig_pop_1['vtable_at_delete'] == [VA_BASE_VTABLE]
    assert orig_pop_1['deletes'] == [0x10001020, this_ptr]
    assert orig_pop_1['globals_after'][2] == 2

    # 2. P2 PIC replacement across flags = 0 and 1 (equivalent to original minus node unlink)
    p2_0 = run_dtor_case(use_p2=True, flags_arg=0, populated_list=False)
    p2_1 = run_dtor_case(use_p2=True, flags_arg=1, populated_list=False)

    for res, expected_orig, exp_del in [(p2_0, orig_empty_0, []), (p2_1, orig_empty_1, [this_ptr])]:
        assert res['eax'] == expected_orig['eax'] == this_ptr
        assert res['esp_delta'] == expected_orig['esp_delta'] == 8  # return addr + 4B flags
        assert res['deletes'] == exp_del
        if not exp_del:
            assert res['vtable_after'] == expected_orig['vtable_after'] == VA_BASE_VTABLE
        else:
            assert res['vtable_at_delete'] == expected_orig['vtable_at_delete'] == [VA_BASE_VTABLE]
        assert res['globals_after'] == (0, 0, 0, 0)
        assert res['eflags_after'] == res['eflags_init'], (hex(res['eflags_after']), hex(res['eflags_init']))
        assert res['gprs'] == {
            'ebx': 0x12345678,
            'ecx': this_ptr,
            'edx': 0x9ABCDEF0,
            'esi': 0x55667788,
            'edi': 0x99AABBCC,
            'ebp': 0x18009000,
        }
        compare_fx(res['fx_seed'], res['fx_after'], f'p2_dtor_flags={int(bool(exp_del))}')

    # 3. Paired ctor inline skip + atexit
    verify_ctor_skip_and_atexit()

    print('Unicorn HighPerfWinClock equivalence PASS: 7/7 checks verified (orig empty/pop x flags 0/1, P2 PIC x flags 0/1 w/ FXSAVE+EFLAGS, ctor skip + atexit).')


if __name__ == '__main__':
    main()
