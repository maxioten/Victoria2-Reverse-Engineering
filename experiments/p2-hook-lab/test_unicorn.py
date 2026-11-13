"""Unicorn x86-32 verification of P2 PIC hook GPR, EFLAGS, stack, and FXSAVE preservation."""
import json
from pathlib import Path
import struct
import unicorn as u
from unicorn.x86_const import *

LAB = Path(__file__).resolve().parent
BUILD = LAB / 'build'


def enable_sse_fpu(emu: u.Uc) -> None:
    cr0 = emu.reg_read(UC_X86_REG_CR0)
    cr0 = (cr0 & ~(1 << 2)) | (1 << 1) | (1 << 5)  # clear EM, set MP + NE
    emu.reg_write(UC_X86_REG_CR0, cr0)
    cr4 = emu.reg_read(UC_X86_REG_CR4)
    cr4 |= (1 << 9) | (1 << 10)  # OSFXSR + OSXMMEXCPT
    emu.reg_write(UC_X86_REG_CR4, cr4)


def make_fx_seed() -> bytes:
    buf = bytearray(512)
    # FCW=0x027F (53-bit PC, masked), FSW=0x0000, FTW=0xFF (all 8 valid)
    struct.pack_into('<HHBBH', buf, 0, 0x027F, 0x0000, 0xFF, 0, 0)
    # MXCSR=0x1F80, MXCSR_MASK=0xFFFF
    struct.pack_into('<II', buf, 24, 0x1F80, 0xFFFF)
    # 8 non-trivial 80-bit x87 st(0)..st(7) values (normal/finite extended floats)
    for i in range(8):
        mant = 0x8000000000000000 | ((i + 1) * 0x0111222233334444 & 0x7FFFFFFFFFFFFFFF)
        exp_sign = 0x3FFF + i  # ~1.0 * 2^i
        struct.pack_into('<QH', buf, 32 + i * 16, mant, exp_sign)
    # 8 non-trivial 128-bit XMM0..XMM7 values
    for i in range(8):
        lo = 0xA0B0C0D0E0F00000 | (i * 0x0101010101010101)
        hi = 0x1122334455667700 | (i * 0x11)
        struct.pack_into('<QQ', buf, 160 + i * 16, lo, hi)
    return bytes(buf)


def compare_fx(before: bytes, after: bytes, label: str) -> None:
    assert len(before) == 512 and len(after) == 512
    # Compare FCW(0..2), FSW(2..4), FTW(4..5), MXCSR(24..28), ST0..7 (10B each), XMM0..7 (16B each)
    assert before[0:5] == after[0:5], (label, 'x87 ctrl/status/tag mismatch', before[0:5].hex(), after[0:5].hex())
    assert before[24:28] == after[24:28], (label, 'MXCSR mismatch', before[24:28].hex(), after[24:28].hex())
    for i in range(8):
        b_st = before[32 + i * 16: 32 + i * 16 + 10]
        a_st = after[32 + i * 16: 32 + i * 16 + 10]
        assert b_st == a_st, (label, f'ST({i}) mismatch', b_st.hex(), a_st.hex())
    for i in range(8):
        b_xmm = before[160 + i * 16: 160 + (i + 1) * 16]
        a_xmm = after[160 + i * 16: 160 + (i + 1) * 16]
        assert b_xmm == a_xmm, (label, f'XMM{i} mismatch', b_xmm.hex(), a_xmm.hex())


def run_case(
    blob: bytes,
    offsets: dict,
    blob_base: int,
    entry_sym: str,
    mode: int,
    arg_bytes: int,
    flags: int,
    use_mock_handler: bool,
    direction_flag: int,
    expect_handled: bool,
) -> None:
    emu = u.Uc(u.UC_ARCH_X86, u.UC_MODE_32)
    enable_sse_fpu(emu)

    stub_base = 0x20000000
    stack_base = 0x18000000
    data_base = 0x21000000

    emu.mem_map(blob_base, 0x1000, u.UC_PROT_READ | u.UC_PROT_WRITE)
    emu.mem_map(stub_base, 0x2000, u.UC_PROT_ALL)
    emu.mem_map(stack_base, 0x10000, u.UC_PROT_READ | u.UC_PROT_WRITE)
    emu.mem_map(data_base, 0x2000, u.UC_PROT_READ | u.UC_PROT_WRITE)

    # Mock original target at stub_base + 0x200: `ret` or `ret arg_bytes`
    orig_target = stub_base + 0x200
    if arg_bytes == 0:
        emu.mem_write(orig_target, b'\xc3')
    else:
        emu.mem_write(orig_target, b'\xc2' + struct.pack('<H', arg_bytes))

    # Mock C handler at stub_base + 0x400 (simulates custom __usercall handler modifying eax & esi and dirtying x87/XMM/GPRs):
    # int __cdecl mock_handler(P2SavedState *regs, P2FxSave *fx, const P2HookConfig *cfg)
    #   mov eax, [esp+4]      ; regs
    #   cmp dword ptr [eax+0x20], 0x11223344  ; verify regs->eax
    #   jne fail
    #   cmp dword ptr [eax+0x08], 0x66778899  ; verify regs->esi
    #   jne fail
    #   cmp dword ptr [eax+0x2C], 0xCAFEBABE  ; verify regs->args[0]
    #   jne fail
    #   mov dword ptr [eax+0x20], 0x1337BEEF  ; set return EAX
    #   mov dword ptr [eax+0x08], 0xFEEDFACE  ; set output ESI
    #   ; Intentionally dirty volatile ECX, EDX, XMM0, and push onto x87 stack before returning 1:
    #   mov ecx, 0xBAD00001
    #   mov edx, 0xBAD00002
    #   pxor xmm0, xmm0
    #   fld1
    #   mov eax, 1
    #   ret
    mock_handler_va = stub_base + 0x400
    mock_fail_va = stub_base + 0x480
    mock_code = bytes([
        0x8B, 0x44, 0x24, 0x04,                          # mov eax, [esp+4]
        0x81, 0x78, 0x20, 0x44, 0x33, 0x22, 0x11,        # cmp dword ptr [eax+0x20], 0x11223344
        0x75, 0x30,                                      # jne fail
        0x81, 0x78, 0x08, 0x99, 0x88, 0x77, 0x66,        # cmp dword ptr [eax+0x08], 0x66778899
        0x75, 0x27,                                      # jne fail
        0x81, 0x78, 0x2C, 0xBE, 0xBA, 0xFE, 0xCA,        # cmp dword ptr [eax+0x2C], 0xCAFEBABE
        0x75, 0x1E,                                      # jne fail
        0xC7, 0x40, 0x20, 0xEF, 0xBE, 0x37, 0x13,        # mov dword ptr [eax+0x20], 0x1337BEEF
        0xC7, 0x40, 0x08, 0xCE, 0xFA, 0xED, 0xFE,        # mov dword ptr [eax+0x08], 0xFEEDFACE
        0xB9, 0x01, 0x00, 0xD0, 0xBA,                    # mov ecx, 0xBAD00001
        0xBA, 0x02, 0x00, 0xD0, 0xBA,                    # mov edx, 0xBAD00002
        0x66, 0x0F, 0xEF, 0xC0,                          # pxor xmm0, xmm0
        0xD9, 0xE8,                                      # fld1
        0xB8, 0x01, 0x00, 0x00, 0x00,                    # mov eax, 1
        0xC3,                                            # ret
    ])
    assert len(mock_code) <= 0x80
    emu.mem_write(mock_handler_va, mock_code)
    emu.mem_write(mock_fail_va, b'\x31\xc0\xc3')  # xor eax, eax; ret (would cause fallback -> test asserts!)

    # Write PIC blob + seal config + VirtualProtect RX
    cfg_bytes = struct.pack(
        '<8I',
        orig_target,
        mock_handler_va if use_mock_handler else 0,
        mode,
        arg_bytes,
        flags,
        0xFFFFFFFF,
        0,
        0,
    )
    patched_blob = bytearray(blob)
    cfg_off = offsets['p2_hook_config']
    patched_blob[cfg_off:cfg_off + 32] = cfg_bytes
    emu.mem_write(blob_base, bytes(patched_blob))
    emu.mem_protect(blob_base, 0x1000, u.UC_PROT_READ | u.UC_PROT_EXEC)

    # Seed FXSAVE at data_base + 0x000, capture FXSAVE at data_base + 0x400 (at orig_target) and +0x800 (at caller_ret)
    fx_seed = make_fx_seed()
    emu.mem_write(data_base, fx_seed)
    fx_orig_buf = data_base + 0x400
    fx_ret_buf = data_base + 0x800

    # Build caller harness at stub_base + 0x000:
    #   fxrstor [data_base]
    #   call hook_entry
    # caller_ret:
    #   fxsave [fx_ret_buf]
    #   hlt / stop
    caller_va = stub_base
    hook_va = blob_base + offsets[entry_sym]
    caller_ret_va = stub_base + 7 + 5  # 7 bytes fxrstor + 5 bytes call rel32
    rel = (hook_va - caller_ret_va) & 0xFFFFFFFF
    caller_code = (
        b'\x0f\xae\x0d' + struct.pack('<I', data_base) +      # fxrstor ds:[data_base]
        b'\xe8' + struct.pack('<I', rel) +                    # call hook_va
        b'\x0f\xae\x05' + struct.pack('<I', fx_ret_buf) +     # fxsave ds:[fx_ret_buf]
        b'\xf4'                                               # hlt
    )
    emu.mem_write(caller_va, caller_code)

    # Stack setup: caller pushes arg0, arg1, arg2 BEFORE calling hook_entry
    sp_before_call = stack_base + 0x8000
    emu.mem_write(sp_before_call, struct.pack('<3I', 0xCAFEBABE, 0xDEADBEEF, 0x12345678))
    emu.reg_write(UC_X86_REG_ESP, sp_before_call)

    canaries = {
        UC_X86_REG_EAX: 0x11223344,
        UC_X86_REG_ECX: 0x22334455,
        UC_X86_REG_EDX: 0x33445566,
        UC_X86_REG_EBX: 0x44556677,
        UC_X86_REG_EBP: 0x55667788,
        UC_X86_REG_ESI: 0x66778899,
        UC_X86_REG_EDI: 0x778899AA,
    }
    for reg, val in canaries.items():
        emu.reg_write(reg, val)

    # CF=1(0), PF=1(2), AF=1(4), ZF=1(6), SF=1(7), IF=1(9), DF=direction_flag(10), OF=1(11)
    eflags_in = 0x202 | (1 << 0) | (1 << 2) | (1 << 4) | (1 << 6) | (1 << 7) | (1 << 11) | (direction_flag << 10)
    emu.reg_write(UC_X86_REG_EFLAGS, eflags_in)

    orig_entry_snapshot = {}
    def on_orig_entry(uc, address, size, user):
        orig_entry_snapshot['gprs'] = {r: uc.reg_read(r) for r in canaries}
        orig_entry_snapshot['esp'] = uc.reg_read(UC_X86_REG_ESP)
        orig_entry_snapshot['eflags'] = uc.reg_read(UC_X86_REG_EFLAGS)
        orig_entry_snapshot['top_stack'] = struct.unpack('<4I', bytes(uc.mem_read(orig_entry_snapshot['esp'], 16)))
        # Verify DF=0 was cleaned on entry to C, and restored before orig_target!
        # Execute standalone fxsave via temporary instruction or read ST/XMM via Unicorn?
        # Even cleaner: inspect all GPRs/EFLAGS/stack here AND run fxsave at fx_orig_buf via tiny wrapper if needed;
        # Wait: let's insert fxsave [fx_orig_buf] at orig_target itself before ret!

    if not expect_handled:
        # Put fxsave [fx_orig_buf] + ret/ret N at orig_target so we verify exact 512B FXSAVE inside original_target!
        orig_code = b'\x0f\xae\x05' + struct.pack('<I', fx_orig_buf) + (
            b'\xc3' if arg_bytes == 0 else b'\xc2' + struct.pack('<H', arg_bytes)
        )
        emu.mem_write(orig_target, orig_code)
        emu.hook_add(u.UC_HOOK_CODE, on_orig_entry, begin=orig_target, end=orig_target)

    stop_va = caller_ret_va + 7  # hlt
    emu.emu_start(caller_va, stop_va, count=100000)
    assert emu.reg_read(UC_X86_REG_EIP) == stop_va

    eflags_mask = 0xCD5  # OF, DF, SF, ZF, AF, PF, CF
    label = f'{entry_sym} base=0x{blob_base:08X} mode={mode} argB={arg_bytes} mock={use_mock_handler} df={direction_flag}'

    if not expect_handled:
        assert orig_entry_snapshot, f'{label}: fallback never reached orig_target'
        assert orig_entry_snapshot['gprs'] == canaries, (label, 'GPR mismatch at orig_target', orig_entry_snapshot['gprs'])
        assert (orig_entry_snapshot['eflags'] & eflags_mask) == (eflags_in & eflags_mask), (
            label, hex(orig_entry_snapshot['eflags']), hex(eflags_in)
        )
        assert orig_entry_snapshot['esp'] == sp_before_call - 4, (label, 'ESP at orig_target')
        assert orig_entry_snapshot['top_stack'] == (caller_ret_va, 0xCAFEBABE, 0xDEADBEEF, 0x12345678), (
            label, 'Stack at orig_target', [hex(x) for x in orig_entry_snapshot['top_stack']]
        )
        compare_fx(fx_seed, bytes(emu.mem_read(fx_orig_buf, 512)), label + ' [orig_target]')
    else:
        assert not orig_entry_snapshot, f'{label}: handled path unexpectedly called orig_target'

    # Check state back at caller_ret
    assert emu.reg_read(UC_X86_REG_ESP) == sp_before_call + arg_bytes, (
        label, 'ESP mismatch after return', hex(emu.reg_read(UC_X86_REG_ESP)), hex(sp_before_call + arg_bytes)
    )
    assert (emu.reg_read(UC_X86_REG_EFLAGS) & eflags_mask) == (eflags_in & eflags_mask), (
        label, 'EFLAGS mismatch after return'
    )
    if use_mock_handler and expect_handled:
        assert emu.reg_read(UC_X86_REG_EAX) == 0x1337BEEF, label
        assert emu.reg_read(UC_X86_REG_ESI) == 0xFEEDFACE, label
        for reg in [UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EBX, UC_X86_REG_EBP, UC_X86_REG_EDI]:
            assert emu.reg_read(reg) == canaries[reg], (label, reg)
    else:
        for reg, val in canaries.items():
            assert emu.reg_read(reg) == val, (label, reg)

    compare_fx(fx_seed, bytes(emu.mem_read(fx_ret_buf, 512)), label + ' [caller_ret]')


def main() -> None:
    meta = json.loads((BUILD / 'build.json').read_text())
    blob = (BUILD / 'hook.bin').read_bytes()
    offsets = meta['offsets']

    cases = [
        # (blob_base, entry_sym, mode, arg_bytes, flags, use_mock, df, expect_handled)
        (0x23450000, 'p2_hook_entry',    0, 0, 0, False, 0, False),  # mode=OFF fallback
        (0x23450000, 'p2_hook_entry',    1, 4, 0, False, 1, False),  # mode=PROD handler=0 fallback with DF=1 & ret 4
        (0x23450000, 'p2_pic_nop_entry', 1, 4, 0, False, 1, False),  # Config B NOP trampoline with DF=1
        (0x23450000, 'p2_hook_entry',    1, 0, 1, False, 0, True),   # handled arg_bytes=0 (ret $4)
        (0x23450000, 'p2_hook_entry',    1, 8, 1, False, 1, True),   # handled arg_bytes=8 (ret $12) + DF=1
        (0x23450000, 'p2_hook_entry',    1, 4, 0, True,  1, True),   # handled custom __usercall (EAX+ESI writeback, dirty C side)
        (0x41230000, 'p2_hook_entry',    1, 4, 0, True,  0, True),   # PIC rebase invariance (.Lhandled)
        (0x41230000, 'p2_hook_entry',    1, 4, 0, False, 0, False),  # PIC rebase invariance (.Lfallback)
        (0x23450000, 'p2_hook_entry',    2, 4, 1, False, 0, False),  # mode=SHADOW without shadow flag -> safe fallback
        (0x23450000, 'p2_hook_entry',    1, 16, 1, False, 0, False), # unsupported arg_bytes=16 -> fail-safe fallback
    ]
    for args in cases:
        run_case(blob, offsets, *args)
    print(f'Unicorn verification PASS: {len(cases)}/{len(cases)} cases verified (GPR/EFLAGS/DF/ESP/512B FXSAVE/PIC rebase).')


if __name__ == '__main__':
    main()
