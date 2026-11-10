#!/usr/bin/env python3
import glob
import json
import os
import re
import sys
from common import ANALYSIS, GEN

OUT = ANALYSIS / 'generated_metrics.json'

files = sorted(glob.glob(os.path.join(GEN, 'recomp_*.c')))
total_bytes = 0
total_lines = 0
counts = {
    'error_lifting': 0,
    'failed_comment': 0,
    'unimplemented': 0,
    'rt_unimpl': 0,
    'stub_calls': 0,
    'function_defs': 0,
}
samples = {'error_lifting': [], 'unimplemented': []}
for p in files:
    with open(p, 'r', errors='replace') as f:
        text = f.read()
    total_bytes += len(text)
    total_lines += text.count('\n')
    counts['error_lifting'] += text.count('/* ERROR lifting')
    counts['failed_comment'] += text.count('/* FAILED */')
    counts['unimplemented'] += text.count('UNIMPLEMENTED')
    counts['rt_unimpl'] += text.count('RT_UNIMPL')
    counts['stub_calls'] += text.count('STUB(')
    counts['function_defs'] += len(re.findall(r'^void sub_[0-9A-Fa-f]+\(void\)', text, re.M))
    for m in re.finditer(r'/\* ERROR lifting[^\n]*', text):
        if len(samples['error_lifting']) < 20:
            samples['error_lifting'].append(m.group(0))
    for m in re.finditer(r'[^\n]*UNIMPLEMENTED[^\n]*', text):
        if len(samples['unimplemented']) < 20:
            samples['unimplemented'].append(m.group(0).strip())

funcs_header = os.path.join(GEN, 'recomp_funcs.h')
header_decls = 0
if os.path.exists(funcs_header):
    with open(funcs_header, errors='replace') as f:
        header_decls = len(re.findall(r'^void sub_[0-9A-Fa-f]+\(void\);', f.read(), re.M))

dispatch = os.path.join(GEN, 'recomp_dispatch.c')
dispatch_count = None
if os.path.exists(dispatch):
    with open(dispatch, errors='replace') as f:
        m = re.search(r'recomp_dispatch_count = (\d+);', f.read())
        if m:
            dispatch_count = int(m.group(1))

stats = None
for name in ('functions_full.json', 'functions.json'):
    p = ANALYSIS / name
    if os.path.exists(p):
        try:
            stats = json.load(open(p)).get('stats')
            stats['source'] = name
            break
        except Exception:
            pass

metrics = {
    'generated_c_files': len(files),
    'generated_bytes': total_bytes,
    'generated_lines': total_lines,
    'counts': counts,
    'header_declarations': header_decls,
    'dispatch_count': dispatch_count,
    'disasm_stats': stats,
    'samples': samples,
}
json.dump(metrics, open(OUT, 'w'), indent=1)
print(json.dumps(metrics, indent=1))
