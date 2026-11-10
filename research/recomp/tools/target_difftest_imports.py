#!/usr/bin/env python3
"""Differential test of V2 functions that call one simple Win32 import.

Both sides get the same deterministic stub: the C side through
recomp_lookup_import(), the Unicorn side through a code hook at the IAT slot.
"""
import json
import os
import struct
import subprocess
import sys
import tempfile

from common import ANALYSIS, BIN, PCRECOMP, WORK
from target_difftest import (PRELUDE, WIN_BASE, WIN_SIZE, STACK_TOP, SENTINEL,
                             IMAGE, IMAGE_SIZE, STATES, compare, parse_c)
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from tools.disasm.disasm32 import Instruction
from tools.lift.lift32 import Lifter
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UcError, UC_HOOK_CODE
from unicorn import x86_const as X

PCRE = PCRECOMP
TARGETS = ANALYSIS / 'import_targets.json'
FUNCS = ANALYSIS / 'functions.json'
OUT = ANALYSIS / 'difftest_imports_results.json'
SCRATCH = 0x00010000


def lift_bytes_import(code, va):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    lifter = Lifter(precise_carry=False)
    lifter._labels = set()
    lifter._jump_targets = set()
    lifter._flag_state = None
    body = []
    seen = 0
    for ci in md.disasm(code, va):
        seen += ci.size
        if ci.mnemonic == 'ret':
            continue
        insn = Instruction(address=ci.address, size=ci.size, mnemonic=ci.mnemonic,
                           op_str=ci.op_str, bytes=ci.bytes, operands=ci.operands)
        body.extend('    ' + line for line in lifter.lift_instruction(insn))
    if seen != len(code):
        raise RuntimeError(f'decoded {seen} of {len(code)} bytes at 0x{va:08X}')
    return body


BRIDGES = {
    'DeleteCriticalSection': 'eax = 0; esp += 8;',
    'EnterCriticalSection': 'eax = 0; esp += 8;',
    'InitializeCriticalSection': 'eax = 0; esp += 8;',
    'LeaveCriticalSection': 'eax = 0; esp += 8;',
    'IsProcessorFeaturePresent': 'eax = 1; esp += 8;',
    'QueryPerformanceCounter': 'uint32_t _p = MEM32(esp + 4); MEM32(_p) = 1; MEM32(_p + 4) = 0; eax = 1; esp += 8;',
}


def build_c(targets, funcs, outdir):
    src = [PRELUDE % (WIN_BASE, WIN_SIZE, STACK_TOP, SENTINEL, IMAGE_SIZE)]
    src.append('''
uint32_t g_icall_trace[ICALL_TRACE_SIZE];
uint32_t g_icall_from[ICALL_TRACE_SIZE];
uint32_t g_icall_trace_idx;
uint32_t g_icall_count;
''')
    for name, body in BRIDGES.items():
        src.append(f'void bridge_{name}(void) {{ {body} }}\n')
    src.append('\nrecomp_func_t recomp_lookup_manual(uint32_t va) { (void)va; return 0; }\n')
    src.append('recomp_func_t recomp_lookup(uint32_t va) { (void)va; return 0; }\n')
    src.append('recomp_func_t recomp_lookup_import(uint32_t va) {\n')
    for i, t in enumerate(targets):
        src.append(f'    if (va == 0x{0x014F0000 + i * 0x10:08X}u) return bridge_{t["import"]};\n')
    src.append('    return 0;\n}\n')
    src.append('''
static void set_state_import(int state) {
    switch (state) {
    case 0:
        g_eax=0x00001234u; g_ecx=0x00010000u; g_edx=0x00005678u; g_ebx=0x00001000u;
        g_ebp=0x014EF000u; g_esi=0x00010000u; g_edi=0x00010100u; break;
    case 1:
        g_eax=0x00007FFFu; g_ecx=0x00010000u; g_edx=0x00008000u; g_ebx=0x00002000u;
        g_ebp=0x014EE000u; g_esi=0x00010000u; g_edi=0x00010100u; break;
    default:
        g_eax=0x0000FFFFu; g_ecx=0x00010000u; g_edx=0x0000FFFEu; g_ebx=0x00005000u;
        g_ebp=0x014ED000u; g_esi=0x00010000u; g_edi=0x00010100u; break;
    }
    g_esp = STACK_TOP;
    *(uint32_t *)(win + STACK_TOP) = SENTINEL;
    g_fs_base = 0; g_gs_base = 0;
    g_seg_cs = g_seg_ds = g_seg_es = g_seg_fs = g_seg_gs = g_seg_ss = 0;
    g_fpu_cw = 0x027F; g_mxcsr = 0x1F80;
    memset(g_st, 0, sizeof g_st); g_fp_top = 0;
    memset(g_mm, 0, sizeof g_mm); memset(g_xmm, 0, sizeof g_xmm);
    g_cur_func = 0;
}
''')
    for t in targets:
        fa = t['address']
        f = funcs[fa]
        body = '\n'.join(lift_bytes_import(bytes.fromhex(f['bytes']), fa))
        src.append(f'''void sub_{fa:08X}(void) {{
    int _fpu_cmp = 0;
    uint32_t _cf = 0;
    int _df = 1;
    uint32_t _flag_a = 0, _flag_b = 0;
    uint32_t _flag_k = FK_NONE;
{body}
    RECOMP_FLAGS_OUT();
    out_eflags = recomp_eflags(_flag_k, _flag_a, _flag_b, _cf, _df);
    esp += 4;
}}
''')
    for i, t in enumerate(targets):
        src.append(f'''
static void run_{i}(int state) {{
    memcpy(win, ref, WIN_SIZE);
    set_state_import(state);
    g_cur_func = 0x{t['address']:08X}u;
    out_eflags = 0;
    sub_{t['address']:08X}();
    dump_case({i}, state);
}}
''')
    src.append('\nint main(int argc, char **argv) {\n'
               '    int idx = argc > 1 ? atoi(argv[1]) : 0;\n'
               '    int state = argc > 2 ? atoi(argv[2]) : 0;\n'
               '    FILE *f;\n'
               '    win = (unsigned char *)malloc(WIN_SIZE);\n'
               '    ref = (unsigned char *)malloc(WIN_SIZE);\n'
               '    if (!win || !ref) return 2;\n'
               '    memset(ref, 0, WIN_SIZE);\n'
               f'    f = fopen("{IMAGE}", "rb");\n'
               '    if (!f) return 3;\n'
               '    if (fread(ref + 0x400000, 1, IMAGE_SIZE, f) != IMAGE_SIZE) return 4;\n'
               '    fclose(f);\n'
               '    *(uint32_t *)(ref + STACK_TOP) = SENTINEL;\n')
    for i, t in enumerate(targets):
        src.append(f'    *(uint32_t *)(ref + 0x{int(t["iat_va"], 16):08X}u) = 0x{0x014F0000 + i * 0x10:08X}u;\n')
    src.append('    memcpy(win, ref, WIN_SIZE);\n'
               '    g_mem_base = (ptrdiff_t)win - (ptrdiff_t)WIN_BASE;\n'
               '    switch (idx) {\n')
    for i in range(len(targets)):
        src.append(f'    case {i}: run_{i}(state); break;\n')
    src.append('    default: return 5;\n'
               '    }\n'
               '    return 0;\n'
               '}\n')
    path = os.path.join(outdir, 'target_difftest_imports.c')
    with open(path, 'w') as f:
        f.write(''.join(src))
    return path


def compile_c(src, outdir):
    include = os.path.join(PCRE, 'runtime', 'recomp32')
    exe = os.path.join(outdir, 'target_difftest_imports')
    r = subprocess.run(['gcc', '-O0', '-g', '-w', '-I', include, src, '-o', exe, '-lm'],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f'gcc failed:\n{r.stdout}\n{r.stderr}')
    return exe


def run_unicorn_import(t, state):
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    mu.mem_map(WIN_BASE, WIN_SIZE)
    mu.mem_write(0x400000, open(IMAGE, 'rb').read())
    mu.mem_write(STACK_TOP, struct.pack('<I', SENTINEL))
    regs = dict(STATES[state])
    regs['ecx'] = SCRATCH
    regs['esi'] = SCRATCH
    regs['edi'] = SCRATCH + 0x100
    regs['esp'] = STACK_TOP
    for name, val in regs.items():
        mu.reg_write({
            'eax': X.UC_X86_REG_EAX, 'ecx': X.UC_X86_REG_ECX, 'edx': X.UC_X86_REG_EDX,
            'ebx': X.UC_X86_REG_EBX, 'esp': X.UC_X86_REG_ESP, 'ebp': X.UC_X86_REG_EBP,
            'esi': X.UC_X86_REG_ESI, 'edi': X.UC_X86_REG_EDI,
        }[name], val)
    mu.reg_write(X.UC_X86_REG_EFLAGS, 0x202)
    mu.reg_write(X.UC_X86_REG_FPCW, 0x027F)
    mu.reg_write(X.UC_X86_REG_MXCSR, 0x1F80)
    iat = int(t['iat_va'], 16)
    fake = 0x014F0000 + int(t['index']) * 0x10 if 'index' in t else 0x014F0000
    mu.mem_write(iat, struct.pack('<I', fake))
    argc = t['argc']

    def hook(mu, address, size, user):
        esp = mu.reg_read(X.UC_X86_REG_ESP)
        ret = struct.unpack('<I', mu.mem_read(esp, 4))[0]
        if t['import'] == 'QueryPerformanceCounter':
            ptr = struct.unpack('<I', mu.mem_read(esp + 4, 4))[0]
            mu.mem_write(ptr, struct.pack('<Q', 1))
            eax = 1
        elif t['import'] == 'IsProcessorFeaturePresent':
            eax = 1
        else:
            eax = 0
        mu.reg_write(X.UC_X86_REG_EAX, eax)
        mu.reg_write(X.UC_X86_REG_ESP, esp + 4 + 4 * argc)
        mu.reg_write(X.UC_X86_REG_EIP, ret)

    mu.hook_add(UC_HOOK_CODE, hook, begin=fake, end=fake + 1)
    before = bytes(mu.mem_read(WIN_BASE, WIN_SIZE))
    try:
        mu.emu_start(t['address'], SENTINEL, count=500000)
    except UcError as e:
        return {'fault': str(e)}
    after = bytes(mu.mem_read(WIN_BASE, WIN_SIZE))
    # memory diff without numpy for simplicity
    mem = {}
    for i in range(0, WIN_SIZE, 4):
        if before[i:i + 4] != after[i:i + 4]:
            for j in range(i, min(i + 4, WIN_SIZE)):
                if before[j] != after[j]:
                    mem[WIN_BASE + j] = after[j]
                    if len(mem) >= 5000:
                        break
        if len(mem) >= 5000:
            break
    fpsw = mu.reg_read(X.UC_X86_REG_FPSW)
    return {
        'regs': {n: mu.reg_read({
            'eax': X.UC_X86_REG_EAX, 'ecx': X.UC_X86_REG_ECX, 'edx': X.UC_X86_REG_EDX,
            'ebx': X.UC_X86_REG_EBX, 'esp': X.UC_X86_REG_ESP, 'ebp': X.UC_X86_REG_EBP,
            'esi': X.UC_X86_REG_ESI, 'edi': X.UC_X86_REG_EDI,
        }[n]) for n in ('eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi')},
        'eflags': mu.reg_read(X.UC_X86_REG_EFLAGS),
        'fp_depth': (8 - ((fpsw >> 11) & 7)) & 7,
        'mem': mem,
        'mem_count': len(mem),
    }


def main():
    targets = json.load(open(TARGETS))
    funcs_list = json.load(open(FUNCS))['functions']
    funcs = {f['address']: f for f in funcs_list}
    import pefile
    pe = pefile.PE(str(BIN), fast_load=True)
    img = pe.get_memory_mapped_image()
    base = pe.OPTIONAL_HEADER.ImageBase
    for f in funcs.values():
        off = f['address'] - base
        f['bytes'] = bytes(img[off:off + f['size']]).hex()

    outdir = tempfile.mkdtemp(prefix='v2-imports-')
    src = build_c(targets, funcs, outdir)
    exe = compile_c(src, outdir)
    print(f'compiled {exe} for {len(targets)} imports')

    results = []
    for i, t in enumerate(targets):
        for state in range(3):
            t['index'] = i
            u = run_unicorn_import(t, state)
            rec = {'index': i, 'address': t['address_hex'], 'state': state,
                   'import': t['import'], 'iat_va': t['iat_va']}
            if 'fault' in u:
                rec['status'] = 'unicorn_fault'
                rec['detail'] = u['fault']
                results.append(rec)
                print(f"SKIP {t['address_hex']} state={state} {u['fault']}")
                continue
            r = subprocess.run([exe, str(i), str(state)], capture_output=True, text=True, timeout=120)
            if r.returncode != 0:
                rec['status'] = 'c_crash'
                rec['detail'] = f'rc={r.returncode} {r.stderr[-300:]}'
                results.append(rec)
                print(f"FAIL {t['address_hex']} state={state} c_crash rc={r.returncode}")
                continue
            parsed = parse_c(r.stdout)
            if len(parsed) != 1:
                rec['status'] = 'parse_error'
                rec['detail'] = r.stdout[-300:]
                results.append(rec)
                print(f"FAIL {t['address_hex']} state={state} parse_error")
                continue
            fields = compare(parsed[0], u)
            # RECOMP_ICALL pushes 0xDEAD0000 instead of the real return address.
            def _stack_slot(name):
                if not (name.startswith('[') and name.endswith(']')):
                    return False
                a = int(name[1:-1], 16)
                return STACK_TOP - 0x100 <= a <= STACK_TOP + 0x100
            fields = [f for f in fields if not _stack_slot(f[0])]
            rec['fields'] = fields
            rec['status'] = 'ok' if not fields else 'diff'
            results.append(rec)
            if fields:
                print(f"DIFF {t['address_hex']} state={state} {t['import']}: " + '; '.join(f'{n} {a}/{b}' for n, a, b in fields[:8]))
            else:
                print(f"ok   {t['address_hex']} state={state} {t['import']}")
    json.dump(results, open(OUT, 'w'), indent=1)
    ok = sum(1 for r in results if r['status'] == 'ok')
    diff = sum(1 for r in results if r['status'] == 'diff')
    skip = sum(1 for r in results if r['status'] == 'unicorn_fault')
    crash = sum(1 for r in results if r['status'] == 'c_crash')
    print(f'\nSUMMARY total={len(results)} ok={ok} diff={diff} unicorn_fault={skip} c_crash={crash}')
    print(f'results: {OUT}')
    print(f'source: {src}')


if __name__ == '__main__':
    main()
