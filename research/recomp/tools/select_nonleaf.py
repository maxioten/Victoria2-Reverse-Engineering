#!/usr/bin/env python3
"""Select non-leaf V2 functions whose closure is branchless and import-free."""
import json
import os
from collections import deque

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_MEM, X86_OP_IMM
from common import ANALYSIS, BIN

PE = BIN
FUNCS = ANALYSIS / 'functions.json'
OUT = ANALYSIS / 'nonleaf_targets.json'

pe = pefile.PE(PE, fast_load=True)
img = pe.get_memory_mapped_image()
image_base = pe.OPTIONAL_HEADER.ImageBase
funcs = json.load(open(FUNCS))['functions']
by_addr = {f['address']: f for f in funcs}
md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True
BAD = {'int', 'int3', 'sysenter', 'syscall', 'cpuid', 'rdtsc', 'hlt', 'in', 'out',
       'iret', 'iretd', 'fsin', 'fcos', 'fsincos', 'fpatan', 'fyl2x', 'f2xm1',
       'fscale', 'fxtract', 'fyl2xp1', 'fninit', 'finit', 'wait', 'fwait'}
BRANCH = {'jmp', 'ljmp', 'loop', 'loope', 'loopne', 'jecxz', 'jrcxz'}


def inspect(f):
    va = f['address']
    size = f['size']
    off = va - image_base
    if off < 0 or off + size > len(img):
        return None, 'out-of-image'
    code = bytes(img[off:off + size])
    ins = list(md.disasm(code, va))
    if not ins or sum(i.size for i in ins) != size:
        return None, 'decode'
    for i in ins:
        m = i.mnemonic
        if m in BAD:
            return None, f'bad:{m}'
        if 'fs:' in i.op_str or 'gs:' in i.op_str:
            return None, 'fs/gs'
        if m in BRANCH or (m.startswith('j') and m != 'jmp'):
            return None, 'branch'
        if m == 'ret' and i.op_str:
            return None, 'ret-imm'
        if m == 'call':
            if not i.operands:
                return None, 'call-no-operand'
            if i.operands[0].type != X86_OP_IMM:
                return None, 'indirect-or-import-call'
        for op in i.operands:
            if op.type == X86_OP_MEM:
                if op.mem.base == 0 and not (0 <= op.mem.disp < 0x01500000):
                    return None, 'abs-out'
    return ins, None


def closure(root):
    seen = set()
    q = deque([root])
    total_ins = 0
    while q:
        f = q.popleft()
        if f['address'] in seen:
            continue
        seen.add(f['address'])
        ins, why = inspect(f)
        if why:
            return None, f'{f["address"]:08X}:{why}'
        total_ins += len(ins)
        if total_ins > 600:
            return None, 'too-many-insns'
        for t in f.get('calls_to') or []:
            if t not in by_addr:
                return None, f'missing-callee:{t:08X}'
            q.append(by_addr[t])
        if len(seen) > 8:
            return None, 'closure>8'
    return seen, None


cands = []
reasons = {}
for f in funcs:
    if not f.get('calls_to') or f.get('is_thunk'):
        continue
    if not (40 <= f['size'] <= 500):
        continue
    seen, why = closure(f)
    if why:
        reasons[why.split(':')[0]] = reasons.get(why.split(':')[0], 0) + 1
        continue
    root_ins, _ = inspect(f)
    cands.append({
        'address': f['address'],
        'address_hex': f'0x{f["address"]:08X}',
        'size': f['size'],
        'entry_kind': f.get('entry_kind'),
        'closure': [f'0x{x:08X}' for x in sorted(seen)],
        'closure_size': len(seen),
        'root_insns': len(root_ins),
        'root_calls': [f'0x{x:08X}' for x in f.get('calls_to') or []],
    })

json.dump(cands, open(ANALYSIS / 'nonleaf_candidates_all.json', 'w'), indent=1)
cands.sort(key=lambda c: (-c['closure_size'], -c['size'], c['address']))
# Prefer diverse call signatures and larger roots, not just tiny wrappers.
selected = []
seen_sig = set()
for c in cands:
    sig = tuple(c['root_calls'])
    if sig in seen_sig:
        continue
    selected.append(c)
    seen_sig.add(sig)
    if len(selected) >= 20:
        break
if len(selected) < 20:
    selected += [c for c in cands if c not in selected][:20 - len(selected)]
json.dump(selected, open(OUT, 'w'), indent=1)
print('candidates', len(cands), 'rejected', reasons)
print('selected', len(selected))
for c in selected:
    print(f"{c['address_hex']} size={c['size']:3d} closure={c['closure_size']} calls={c['root_calls']} insns={c['root_insns']}")
