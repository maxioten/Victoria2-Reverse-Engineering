#!/usr/bin/env python3
"""Find small branchless functions that call one simple Win32 import."""
import json
import os
from collections import Counter

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_MEM, X86_OP_IMM
from common import ANALYSIS, BIN

PE = BIN
FUNCS = ANALYSIS / 'functions.json'
PEJSON = ANALYSIS / 'pe_analysis.json'
OUT = ANALYSIS / 'import_targets.json'

pe = pefile.PE(PE, fast_load=True)
img = pe.get_memory_mapped_image()
base = pe.OPTIONAL_HEADER.ImageBase
funcs = json.load(open(FUNCS))['functions']
peinfo = json.load(open(PEJSON))
iat = {}
for imp in peinfo['imports']:
    va = base + imp['iat_rva']
    iat[va] = (imp['dll'], imp['name'] or f'ordinal_{imp["ordinal"]}')

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True
BRANCH = {'jmp', 'ljmp', 'loop', 'loope', 'loopne', 'jecxz', 'jrcxz'}
BAD = {'int', 'int3', 'sysenter', 'syscall', 'cpuid', 'rdtsc', 'hlt', 'in', 'out',
       'iret', 'iretd', 'fsin', 'fcos', 'fsincos', 'fpatan', 'fyl2x', 'f2xm1',
       'fscale', 'fxtract', 'fyl2xp1', 'fninit', 'finit', 'wait', 'fwait'}

# imports we can model deterministically in both Unicorn and C
SIMPLE0 = {'GetTickCount', 'GetCurrentThreadId', 'GetCurrentProcessId', 'GetLastError',
           'GetVersion', 'GetACP', 'GetOEMCP', 'GetProcessHeap', 'GetCommandLineA',
           'GetSystemTimeAsFileTime', 'QueryPerformanceCounter', 'QueryPerformanceFrequency',
           'Sleep', 'IsProcessorFeaturePresent', 'EnterCriticalSection',
           'LeaveCriticalSection', 'DeleteCriticalSection', 'InitializeCriticalSection',
           'GetSystemTime', 'GetLocalTime'}
SIMPLE1 = {'Sleep', 'IsProcessorFeaturePresent', 'EnterCriticalSection',
           'LeaveCriticalSection', 'DeleteCriticalSection', 'InitializeCriticalSection',
           'GetSystemTimeAsFileTime', 'QueryPerformanceCounter', 'QueryPerformanceFrequency',
           'GetSystemTime', 'GetLocalTime'}

cands = []
reasons = Counter()
for f in funcs:
    if f.get('calls_to') or f.get('is_thunk'):
        continue
    if not (16 <= f['size'] <= 200):
        continue
    off = f['address'] - base
    code = bytes(img[off:off + f['size']])
    ins = list(md.disasm(code, f['address']))
    if not ins or sum(i.size for i in ins) != f['size']:
        reasons['decode'] += 1
        continue
    imp_calls = []
    bad = None
    for i in ins:
        m = i.mnemonic
        if m in BAD:
            bad = f'bad:{m}'; break
        if m in BRANCH or (m.startswith('j') and m != 'jmp'):
            bad = 'branch'; break
        if m == 'ret' and i.op_str:
            bad = 'ret-imm'; break
        if 'fs:' in i.op_str or 'gs:' in i.op_str:
            bad = 'fs/gs'; break
        if m == 'call':
            if not i.operands:
                bad = 'call-no-operand'; break
            op = i.operands[0]
            if op.type == X86_OP_MEM and op.mem.base == 0 and op.mem.disp in iat:
                imp_calls.append((i.address, op.mem.disp, iat[op.mem.disp]))
            else:
                bad = 'non-import-call'; break
    if bad:
        reasons[bad] += 1
        continue
    if len(imp_calls) != 1:
        reasons[f'import-calls:{len(imp_calls)}'] += 1
        continue
    call_va, iat_va, (dll, name) = imp_calls[0]
    if name not in SIMPLE0:
        reasons[f'import:{name}'] += 1
        continue
    cands.append({
        'address': f['address'],
        'address_hex': f'0x{f["address"]:08X}',
        'size': f['size'],
        'entry_kind': f.get('entry_kind'),
        'import': name,
        'dll': dll,
        'iat_va': f'0x{iat_va:08X}',
        'call_va': f'0x{call_va:08X}',
        'argc': 1 if name in SIMPLE1 else 0,
    })

cands.sort(key=lambda c: (c['import'], c['size'], c['address']))
# pick up to 20, one per import name first
selected = []
seen = set()
for c in cands:
    if c['import'] in seen:
        continue
    selected.append(c); seen.add(c['import'])
    if len(selected) >= 20: break
for c in cands:
    if len(selected) >= 20: break
    if c not in selected: selected.append(c)
json.dump(selected, open(OUT, 'w'), indent=1)
print('candidates', len(cands), 'rejected', reasons.most_common(15))
print('selected', len(selected))
for c in selected:
    print(f"{c['address_hex']} size={c['size']:3d} import={c['import']} argc={c['argc']} iat={c['iat_va']} call={c['call_va']}")
