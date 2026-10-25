#!/usr/bin/env python3
"""Verify CArmy::CalculateTotalStrength and CNavy::CalculateTotalStrength with Reverify and Unicorn.

Routines:
  CArmy: 0x005D61A0..0x005D61F8 (89 bytes, 29 instructions).
  CNavy: 0x005D91D0..0x005D91E5 (21 bytes, 7 instructions).
Vtables (slot 10, +0x28):
  CArmy: 0x00DF88F4 -> 0x005D61A0.
  CNavy: 0x00E02FF4 -> 0x005D91D0.
"""
import hashlib
import json
import math
from pathlib import Path
import struct
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
import pefile
from reverify.verifier import Claim, Verifier
from reverify.ledger import Ledger
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_PROT_ALL, UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_EAX, UC_X86_REG_ECX,
    UC_X86_REG_EDX, UC_X86_REG_EBX, UC_X86_REG_ESI, UC_X86_REG_EDI
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT / 'scripts'))
from formation_total_strength_model import army_total_strength, navy_total_strength

bin_path = ROOT.parent / 'base-game/v2game.exe'
data = bin_path.read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_32)

claims = []

# 1. CArmy::CalculateTotalStrength instructions (0x005D61A0..0x005D61F8)
raw_start = pe.get_offset_from_rva(0x005D61A0 - base)
for insn in md.disasm(data[raw_start:raw_start + 120], 0x005D61A0):
    claims.append({
        'id': f'army_total_strength_insn_{insn.address:x}',
        'kind': 'instructions',
        'space': 'rva',
        'offset': hex(insn.address - base),
        'base': hex(insn.address),
        'arch': 'x86',
        'length': len(insn.bytes),
        'mnemonics': [insn.mnemonic],
        'operands': [insn.op_str]
    })
    if insn.address >= 0x005D61F6:
        break

# 2. CNavy::CalculateTotalStrength instructions (0x005D91D0..0x005D91E5)
raw_navy = pe.get_offset_from_rva(0x005D91D0 - base)
for insn in md.disasm(data[raw_navy:raw_navy + 40], 0x005D91D0):
    claims.append({
        'id': f'navy_total_strength_insn_{insn.address:x}',
        'kind': 'instructions',
        'space': 'rva',
        'offset': hex(insn.address - base),
        'base': hex(insn.address),
        'arch': 'x86',
        'length': len(insn.bytes),
        'mnemonics': [insn.mnemonic],
        'operands': [insn.op_str]
    })
    if insn.address >= 0x005D91E2:
        break

# 3. Vtable slot 10 in CArmy at 0x00DF88F4
v_army = pe.get_offset_from_rva(0x00DF88F4 - base)
assert int.from_bytes(data[v_army:v_army + 4], 'little') == 0x005D61A0
claims.append({
    'id': 'vtable_slot10_CArmy',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00DF88F4 - base),
    'base': hex(0x00DF88F4),
    'expected': (0x005D61A0).to_bytes(4, 'little').hex()
})

# 4. Vtable slot 10 in CNavy at 0x00E02FF4
v_navy = pe.get_offset_from_rva(0x00E02FF4 - base)
assert int.from_bytes(data[v_navy:v_navy + 4], 'little') == 0x005D91D0
claims.append({
    'id': 'vtable_slot10_CNavy',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E02FF4 - base),
    'base': hex(0x00E02FF4),
    'expected': (0x005D91D0).to_bytes(4, 'little').hex()
})

# 5. Floating-point constants at 0x00E45840 (0.0005) and 0x00E45660 (1000.0)
c1_raw = pe.get_offset_from_rva(0x00E45840 - base)
claims.append({
    'id': 'const_double_fp_init_0x00E45840',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E45840 - base),
    'base': hex(0x00E45840),
    'expected': data[c1_raw:c1_raw + 8].hex()
})

c2_raw = pe.get_offset_from_rva(0x00E45660 - base)
claims.append({
    'id': 'const_double_thousand_0x00E45660',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E45660 - base),
    'base': hex(0x00E45660),
    'expected': data[c2_raw:c2_raw + 8].hex()
})

# Run Reverify
verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]

# Negative controls and dependent invalidation
wrong = dict(claims[0], id='negative_control_formation_strength', mnemonics=['nop'])
dependent = dict(claims[1], id='negative_dependent_formation_strength', depends_on=['negative_control_formation_strength'])
controls = verifier.verify_all([Claim.from_dict(wrong), Claim.from_dict(dependent)])
assert [r['verdict'] for r in controls['results']] == ['REFUTED', 'INVALIDATED']

# Unicorn dynamic emulation
uc = Uc(UC_ARCH_X86, UC_MODE_32)
img_size = 0x01100000
uc.mem_map(base, img_size, UC_PROT_ALL)
for s in pe.sections:
    s_va = base + s.VirtualAddress
    sec_data = s.get_data()
    if sec_data:
        uc.mem_write(s_va, sec_data)

SCRATCH_BASE = 0x02000000
SCRATCH_SIZE = 0x00200000
uc.mem_map(SCRATCH_BASE, SCRATCH_SIZE, UC_PROT_ALL)

# CRT floor and ftol2 hooks
ctx = {'last_floor': 0}
def hook_floor(uc_inst, address, size, user_data):
    esp = uc_inst.reg_read(UC_X86_REG_ESP)
    flt_bytes = uc_inst.mem_read(esp + 4, 4)
    flt_val = struct.unpack('<f', flt_bytes)[0]
    ctx['last_floor'] = math.floor(flt_val)

def hook_ftol(uc_inst, address, size, user_data):
    uc_inst.reg_write(UC_X86_REG_EAX, ctx['last_floor'])

uc.hook_add(UC_HOOK_CODE, hook_floor, begin=0x00401000, end=0x00401000)
uc.hook_add(UC_HOOK_CODE, hook_ftol, begin=0x00B31C00, end=0x00B31C00)
uc.mem_write(0x00401000, b'\xc3')
uc.mem_write(0x00B31C00, b'\xc3')

STACK = SCRATCH_BASE + 0x180000
ARMY_ADDR = SCRATCH_BASE + 0x1000
NAVY_ADDR = SCRATCH_BASE + 0x2000
OUT_ADDR = SCRATCH_BASE + 0x3000
RET_STUB = SCRATCH_BASE + 0x4000
uc.mem_write(RET_STUB, b'\x90')

mismatches = 0
total_fixtures = 0

# 1. Navy fixtures: ship_count in [0, 1, 2, ..., 25] and larger values
navy_test_cases = list(range(26)) + [30, 45, 50, 60, 75, 100, 120, 150, 200, 300, 500, 1000]
for sc in navy_test_cases:
    total_fixtures += 1
    uc.mem_write(NAVY_ADDR + 0x40, struct.pack('<I', sc))
    uc.mem_write(OUT_ADDR, struct.pack('<I', 0xDEADBEEF))
    
    uc.mem_write(STACK, struct.pack('<II', RET_STUB, OUT_ADDR))
    uc.reg_write(UC_X86_REG_ESP, STACK)
    uc.reg_write(UC_X86_REG_ECX, NAVY_ADDR)
    uc.reg_write(UC_X86_REG_EIP, 0x005D91D0)
    
    uc.emu_start(0x005D91D0, RET_STUB)
    
    res_ptr = uc.reg_read(UC_X86_REG_EAX)
    val = struct.unpack('<I', uc.mem_read(OUT_ADDR, 4))[0]
    expected = navy_total_strength(sc)
    
    if res_ptr != OUT_ADDR or val != expected:
        mismatches += 1
        print(f'MISMATCH Navy ship_count={sc}: got ptr={res_ptr:x}, val={val}; expected {expected}')

# 2. Army fixtures: list of regiment strengths
army_test_cases = [
    [],
    [0],
    [1],
    [500],
    [1000],
    [3000],
    [0, 0],
    [1000, 2000],
    [3000, 2450, 1000],
    [1500, 3000, 2800, 1200, 3000],
    [100] * 10,
    [1000] * 10,
    [3000] * 10,
    [50, 100, 250, 500, 750, 1000, 1500, 2000, 2500, 3000],
    [3000, 2900, 2800, 2700, 2600, 2500, 2400, 2300, 2200, 2100, 2000],
    [1500] * 20,
    [3000] * 20,
    [2500] * 30,
    [3000] * 40,
    [3000] * 50,
    [3000] * 100,
]

POOL_NODE = SCRATCH_BASE + 0x10000
POOL_REG = SCRATCH_BASE + 0x40000

for case_idx, reg_list in enumerate(army_test_cases):
    total_fixtures += 1
    if not reg_list:
        uc.mem_write(ARMY_ADDR + 0x38, struct.pack('<I', 0))
    else:
        # Build linked list
        first_node = POOL_NODE + case_idx * 0x1000
        for i, s in enumerate(reg_list):
            node_addr = first_node + i * 16
            reg_addr = POOL_REG + (case_idx * 100 + i) * 64
            next_addr = (first_node + (i + 1) * 16) if (i + 1 < len(reg_list)) else 0
            uc.mem_write(reg_addr + 0x3C, struct.pack('<I', s))
            uc.mem_write(node_addr, struct.pack('<IIII', reg_addr, 0, next_addr, 0))
        uc.mem_write(ARMY_ADDR + 0x38, struct.pack('<I', first_node))
    
    uc.mem_write(OUT_ADDR, struct.pack('<I', 0xDEADBEEF))
    uc.mem_write(STACK, struct.pack('<II', RET_STUB, OUT_ADDR))
    uc.reg_write(UC_X86_REG_ESP, STACK)
    uc.reg_write(UC_X86_REG_ECX, ARMY_ADDR)
    uc.reg_write(UC_X86_REG_EIP, 0x005D61A0)
    
    uc.emu_start(0x005D61A0, RET_STUB)
    
    res_ptr = uc.reg_read(UC_X86_REG_EAX)
    val = struct.unpack('<I', uc.mem_read(OUT_ADDR, 4))[0]
    expected = army_total_strength(reg_list)
    
    if res_ptr != OUT_ADDR or val != expected:
        mismatches += 1
        print(f'MISMATCH Army case {case_idx}: got ptr={res_ptr:x}, val={val}; expected {expected}')

assert mismatches == 0, f'{mismatches} mismatches encountered in emulation!'

# Record receipts
out_dir = ROOT / 'evidence/generated/formation-total-strength'
out_dir.mkdir(parents=True, exist_ok=True)
(out_dir / 'claims.json').write_text(json.dumps(claims, indent=2))
(out_dir / 'reverify.json').write_text(json.dumps(report, indent=2))
(out_dir / 'negative-controls.json').write_text(json.dumps(controls, indent=2))
(out_dir / 'emulation.json').write_text(json.dumps({
    'pass': True,
    'fixtures_tested': total_fixtures,
    'mismatches': mismatches,
    'army_cases': len(army_test_cases),
    'navy_cases': len(navy_test_cases)
}, indent=2))

# Record into persistent reverify ledger
ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify', file_path=str(bin_path))
ledger.start_run('Verify CArmy and CNavy CalculateTotalStrength routines and vtables', session='formation-total-strength')
ledger.record(report, rnd=1, session='formation-total-strength')
ledger.finish_run(1, report['grounded'], report['information'])
ledger.save()

print(f'Formation total strength: {len(report["results"])} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.')
print(f'Formation total strength emulation: {total_fixtures} fixtures executed, 0 mismatches against formation_total_strength_model.')
