#!/usr/bin/env python3
"""Differential test of non-leaf V2 functions (internal call closure)."""
import json
import os
import subprocess
import sys
import tempfile

from common import ANALYSIS, BIN, PCRECOMP, WORK
from target_difftest import (PRELUDE, WIN_BASE, WIN_SIZE, STACK_TOP, SENTINEL,
                             IMAGE, IMAGE_SIZE, STATES, run_unicorn,
                             compare, parse_c)
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from tools.disasm.disasm32 import Instruction
from tools.lift.lift32 import Lifter

PCRE = PCRECOMP
TARGETS = ANALYSIS / 'nonleaf_targets.json'
FUNCS = ANALYSIS / 'functions.json'
OUT = ANALYSIS / 'difftest_nonleaf_results.json'

FUNC_TMPL = r'''
void sub_%08X(void) {
    int _fpu_cmp = 0;
    uint32_t _cf = 0;
    int _df = 1;
    uint32_t _flag_a = 0, _flag_b = 0;
    uint32_t _flag_k = FK_NONE;
%s
    RECOMP_FLAGS_OUT();
    out_eflags = recomp_eflags(_flag_k, _flag_a, _flag_b, _cf, _df);
    esp += 4; /* the dropped ret */
}
'''

RUN_TMPL = r'''
static void run_%d(int state) {
    memcpy(win, ref, WIN_SIZE);
    set_state(state);
    g_cur_func = 0x%08Xu;
    out_eflags = 0;
    sub_%08X();
    dump_case(%d, state);
}
'''


def lift_bytes_nl(code, va):
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


def build_c(targets, funcs, outdir):
    src = [PRELUDE % (WIN_BASE, WIN_SIZE, STACK_TOP, SENTINEL, IMAGE_SIZE)]
    # forward declarations for every closure function
    for t in targets:
        for a in t['closure']:
            src.append(f'void sub_{int(a, 16):08X}(void);\n')
    src.append('\n')
    for t in targets:
        for a in t['closure']:
            fa = int(a, 16)
            f = funcs[fa]
            body = '\n'.join(lift_bytes_nl(bytes.fromhex(f['bytes']), fa))
            src.append(FUNC_TMPL % (fa, body))
    for i, t in enumerate(targets):
        src.append(RUN_TMPL % (i, t['address'], t['address'], i))
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
               '    *(uint32_t *)(ref + STACK_TOP) = SENTINEL;\n'
               '    memcpy(win, ref, WIN_SIZE);\n'
               '    g_mem_base = (ptrdiff_t)win - (ptrdiff_t)WIN_BASE;\n'
               '    switch (idx) {\n')
    for i in range(len(targets)):
        src.append(f'    case {i}: run_{i}(state); break;\n')
    src.append('    default: return 5;\n'
               '    }\n'
               '    return 0;\n'
               '}\n')
    path = os.path.join(outdir, 'target_difftest_nonleaf.c')
    with open(path, 'w') as f:
        f.write(''.join(src))
    return path


def compile_c(src, outdir):
    include = os.path.join(PCRE, 'runtime', 'recomp32')
    exe = os.path.join(outdir, 'target_difftest_nonleaf')
    r = subprocess.run(['gcc', '-O0', '-g', '-w', '-I', include, src, '-o', exe, '-lm'],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f'gcc failed:\n{r.stdout}\n{r.stderr}')
    return exe


def main():
    targets = json.load(open(TARGETS))
    funcs_list = json.load(open(FUNCS))['functions']
    funcs = {f['address']: f for f in funcs_list}
    # Add bytes from the image to each function record.
    import pefile
    pe = pefile.PE(str(BIN), fast_load=True)
    img = pe.get_memory_mapped_image()
    base = pe.OPTIONAL_HEADER.ImageBase
    for f in funcs.values():
        off = f['address'] - base
        f['bytes'] = bytes(img[off:off + f['size']]).hex()

    outdir = tempfile.mkdtemp(prefix='v2-nonleaf-')
    src = build_c(targets, funcs, outdir)
    exe = compile_c(src, outdir)
    print(f'compiled {exe} for {len(targets)} roots')

    results = []
    for i, t in enumerate(targets):
        for state in range(3):
            u = run_unicorn({'address': t['address']}, state)
            rec = {'index': i, 'address': t['address_hex'], 'state': state,
                   'closure': t['closure'], 'size': t['size']}
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
            # RECOMP_CALL pushes 0xDEAD0000 instead of the real return address;
            # ignore the top-of-stack slots where that difference lives.
            def _stack_slot(name):
                if not (name.startswith('[') and name.endswith(']')):
                    return False
                a = int(name[1:-1], 16)
                return STACK_TOP - 0x100 <= a <= STACK_TOP + 0x100
            fields = [f for f in fields if not _stack_slot(f[0])]
            rec['fields'] = fields
            rec['mem_count_c'] = parsed[0].get('mem_count', 0)
            rec['mem_count_u'] = u.get('mem_count', 0)
            rec['status'] = 'ok' if not fields else 'diff'
            results.append(rec)
            if fields:
                print(f"DIFF {t['address_hex']} state={state}: " + '; '.join(f'{n} {a}/{b}' for n, a, b in fields[:8]))
            else:
                print(f"ok   {t['address_hex']} state={state} closure={len(t['closure'])} mem={u.get('mem_count',0)}")
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
