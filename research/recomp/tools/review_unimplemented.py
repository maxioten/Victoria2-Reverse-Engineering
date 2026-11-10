#!/usr/bin/env python3
"""Classify every function that contains an UNIMPLEMENTED instruction.

Evidence per function: callers, data references, prologue, byte statistics,
decoded instructions, and the unimplemented mnemonics.  The verdict is
deliberately conservative: `data-like` means "looks like data and has no
callers", not "proven data".
"""
import json
import math
import os
import struct
from collections import Counter, defaultdict

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from common import ANALYSIS, BIN

PE = BIN
FUNCS = ANALYSIS / 'functions.json'
UNIMPL = ANALYSIS / 'unimplemented.json'
OUT_JSON = ANALYSIS / 'unimplemented_review.json'
OUT_MD = ANALYSIS / 'unimplemented_review.md'

pe = pefile.PE(PE, fast_load=True)
img = pe.get_memory_mapped_image()
image_base = pe.OPTIONAL_HEADER.ImageBase
funcs = json.load(open(FUNCS))['functions']
by_addr = {f['address']: f for f in funcs}
callers = defaultdict(list)
for f in funcs:
    for t in f.get('calls_to') or []:
        callers[t].append(f['address'])
u = json.load(open(UNIMPL))
addrs = {int(k, 16): v for k, v in u['addresses'].items()}

# Group instruction addresses by the function that contains them.
func_sites = defaultdict(list)
for a, insn in addrs.items():
    f = by_addr.get(a)
    if f:
        func_sites[f['address']].append((a, insn))
        continue
    # fall back: the nearest function start <= a
    cands = [x for x in funcs if x['address'] <= a < x['address'] + x['size']]
    if cands:
        f = max(cands, key=lambda x: x['address'])
        func_sites[f['address']].append((a, insn))

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True
WEIRD = {'aad', 'aam', 'daa', 'das', 'aaa', 'aas', 'bound', 'salc', 'ljmp',
         'lcall', 'insd', 'int', 'fisttp', 'pavgb', 'pause'}
PROLOGUES = (b'\x55\x8b\xec', b'\x55\x89\xe5', b'\x8b\xff\x55\x8b\xec',
             b'\x53\x8b\xdc', b'\x53\x56\x57', b'\x56\x57', b'\x53\x55')

rows = []
for fa, sites in sorted(func_sites.items()):
    f = by_addr[fa]
    off = fa - image_base
    size = f['size']
    code = bytes(img[off:off + min(size, 512)])
    n = len(code)
    stats = {
        'zero_pct': round(100.0 * code.count(0) / n, 1) if n else 0,
        'x11_pct': round(100.0 * code.count(0x11) / n, 1) if n else 0,
        'cc_pct': round(100.0 * code.count(0xCC) / n, 1) if n else 0,
        'printable_pct': round(100.0 * sum(1 for b in code if 32 <= b < 127) / n, 1) if n else 0,
        'entropy': round(-sum((c / n) * math.log2(c / n) for c in Counter(code).values()), 2) if n else 0,
    }
    prologue = any(code.startswith(p) for p in PROLOGUES)
    insns = list(md.disasm(code, fa))
    mn = Counter(i.mnemonic for i in insns)
    weird = sum(v for k, v in mn.items() if k in WEIRD)
    data_refs = sum(1 for i in range(0, len(img) - 4)
                    if struct.unpack_from('<I', img, i)[0] == fa)
    # A crude but useful "looks like a pointer table" check.
    ptr_like = 0
    for i in range(0, min(len(code), 64) - 3, 4):
        v = struct.unpack_from('<I', code, i)[0]
        if image_base <= v < image_base + len(img):
            ptr_like += 1
    only_pause = all(x.split()[0] == 'pause' for _, x in sites)
    if only_pause and callers.get(fa):
        verdict = 'code-reachable, pause benign'
    elif prologue or (callers.get(fa) and weird < 4):
        verdict = 'code-reachable' if callers.get(fa) else 'code-unreachable'
    elif not callers.get(fa) and (stats['x11_pct'] > 20 or stats['zero_pct'] > 20
                                  or stats['entropy'] < 1.5
                                  or weird >= 4 or ptr_like >= 3):
        verdict = 'data-like (probable)'
    else:
        verdict = 'uncertain'
    rows.append({
        'address': f'0x{fa:08X}',
        'name': f'sub_{fa:08X}',
        'size': size,
        'entry_kind': f.get('entry_kind'),
        'callers': len(callers.get(fa, [])),
        'caller_sample': [f'0x{x:08X}' for x in callers.get(fa, [])[:5]],
        'data_refs': data_refs,
        'prologue': prologue,
        'first_bytes': code[:16].hex(),
        'first_insns': [f'{i.mnemonic} {i.op_str}'.strip() for i in insns[:8]],
        'weird_insns': weird,
        'ptr_like_words_in_first_64': ptr_like,
        'byte_stats': stats,
        'unimplemented': [{'address': f'0x{a:08X}', 'insn': x} for a, x in sorted(sites)],
        'unimplemented_mnemonics': dict(Counter(x.split()[0] for _, x in sites)),
        'verdict': verdict,
    })

# Some aliases overlap a larger definition and share its sites.  Add them
# explicitly so the 13 generated definitions are all accounted for.
existing = {int(r["address"], 16) for r in rows}
dups = []
for r in list(rows):
    fa = int(r['address'], 16)
    sites = [int(x['address'], 16) for x in r['unimplemented']]
    for f in funcs:
        if f['address'] in existing:
            continue
        if all(f['address'] <= a < f['address'] + f['size'] for a in sites):
            d = dict(r)
            d['address'] = f'0x{f["address"]:08X}'
            d['name'] = f'sub_{f["address"]:08X}'
            d['size'] = f['size']
            d['entry_kind'] = f.get('entry_kind')
            d['duplicate_of'] = r['name']
            d['unique_sites'] = False
            d['verdict'] = r['verdict'] + ', alias de ' + r['name']
            dups.append(d)
            existing.add(f['address'])
rows.extend(dups)

json.dump(rows, open(OUT_JSON, 'w'), indent=1)
with open(OUT_MD, 'w') as f:
    f.write('# Revisión de funciones con UNIMPLEMENTED\n\n')
    f.write('Veredicto conservador: `data-like (probable)` significa que parece dato y no tiene llamadores, no que esté probado.\n\n')
    f.write('| Función | Tamaño | Callers | Data refs | Prólogo | UNIMPL | Veredicto |\n')
    f.write('|---|---:|---:|---:|---|---:|---|\n')
    for r in rows:
        f.write(f"| `{r['name']}` | {r['size']} | {r['callers']} | {r['data_refs']} | "
                f"{'sí' if r['prologue'] else 'no'} | {len(r['unimplemented'])} | {r['verdict']} |\n")
    f.write('\n## Detalle\n\n')
    for r in rows:
        f.write(f"### `{r['name']}` — {r['verdict']}\n\n")
        f.write(f"- Entry kind: `{r['entry_kind']}`; size {r['size']}; callers {r['callers']} {r['caller_sample']}\n")
        f.write(f"- Data refs en la imagen: {r['data_refs']}; palabras pointer-like en primeros 64 B: {r['ptr_like_words_in_first_64']}\n")
        f.write(f"- Primeros bytes: `{r['first_bytes']}`; prólogo: {'sí' if r['prologue'] else 'no'}\n")
        f.write(f"- Primeras instrucciones: `{'; '.join(r['first_insns'])}`\n")
        f.write(f"- Byte stats: {r['byte_stats']}; instrucciones raras: {r['weird_insns']}\n")
        f.write(f"- UNIMPLEMENTED: {r['unimplemented_mnemonics']}\n\n")

print(f'wrote {OUT_JSON} and {OUT_MD} ({len(rows)} functions)')
for r in rows:
    print(f"{r['name']} size={r['size']} callers={r['callers']} data_refs={r['data_refs']} "
          f"prologue={r['prologue']} unimpl={len(r['unimplemented'])} -> {r['verdict']}")
