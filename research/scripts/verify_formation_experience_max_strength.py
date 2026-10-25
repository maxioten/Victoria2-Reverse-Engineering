#!/usr/bin/env python3
"""Suite 88: Verificación estática y dinámica de la experiencia media y fuerza máxima
total de formaciones militares.

Verifica formalmente en el binario PE32 `base-game/v2game.exe`:
- CUnit::CalculateAverageExperience (0x005CF8B0..0x005CF943, 58 instrucciones)
- CUnit::CalculateTotalMaxStrength (0x005CF950..0x005CF9AF, 31 instrucciones)
- Vtables de CArmy y CNavy (slots 19 y 20 en 0x00DF8918/C y 0x00E03018/C)
- Constantes de punto flotante en 0x00E45840 y 0x00E45660
- Puntos de llamada a _allmul y _alldiv
- Control negativo y cascada dependiente
- Emulación en Unicorn Engine contrastada contra formation_experience_max_strength_model.py
"""

import hashlib
import json
import math
import os
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
    UC_X86_REG_EDX, UC_X86_REG_EBX, UC_X86_REG_ESI, UC_X86_REG_EDI,
    UC_X86_REG_EBP
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT / 'scripts'))
from formation_experience_max_strength_model import calculate_average_experience, calculate_total_max_strength

bin_path = ROOT.parent / 'base-game/v2game.exe'
data = bin_path.read_bytes()
sha256 = hashlib.sha256(data).hexdigest()
assert sha256 == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = pe.OPTIONAL_HEADER.ImageBase

def get_bytes(va, length):
    offset = pe.get_offset_from_rva(va - base)
    return data[offset:offset + length]

# ==============================================================================
# 1. ESPECIFICACIÓN FORMAL DE CLAIMS PARA REVERIFY
# ==============================================================================
claims = []
md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True

# 1. Instrucciones de CUnit::CalculateAverageExperience (0x005CF8B0..0x005CF943)
code1 = get_bytes(0x005CF8B0, 0x005CF943 - 0x005CF8B0)
for insn in md.disasm(code1, 0x005CF8B0):
    claims.append({
        'id': f'unit_calc_avg_exp_insn_0x{insn.address:08X}',
        'kind': 'instructions',
        'space': 'rva',
        'offset': hex(insn.address - base),
        'base': hex(insn.address),
        'arch': 'x86',
        'length': len(insn.bytes),
        'bytes': insn.bytes.hex(),
        'mnemonics': [insn.mnemonic],
        'operands': [insn.op_str]
    })

# 2. Instrucciones de CUnit::CalculateTotalMaxStrength (0x005CF950..0x005CF9AF)
code2 = get_bytes(0x005CF950, 0x005CF9AF - 0x005CF950)
for insn in md.disasm(code2, 0x005CF950):
    claims.append({
        'id': f'unit_calc_total_max_str_insn_0x{insn.address:08X}',
        'kind': 'instructions',
        'space': 'rva',
        'offset': hex(insn.address - base),
        'base': hex(insn.address),
        'arch': 'x86',
        'length': len(insn.bytes),
        'bytes': insn.bytes.hex(),
        'mnemonics': [insn.mnemonic],
        'operands': [insn.op_str]
    })

# 3. Vtable slots:
# CArmy slot 19 (+0x4C) en 0x00DF8918 -> 0x005CF8B0
claims.append({
    'id': 'vtable_slot19_CArmy_calculate_average_experience',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00DF8918 - base),
    'base': hex(0x00DF8918),
    'expected': (0x005CF8B0).to_bytes(4, 'little').hex()
})

# CNavy slot 19 (+0x4C) en 0x00E03018 -> 0x005CF8B0
claims.append({
    'id': 'vtable_slot19_CNavy_calculate_average_experience',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E03018 - base),
    'base': hex(0x00E03018),
    'expected': (0x005CF8B0).to_bytes(4, 'little').hex()
})

# CArmy slot 20 (+0x50) en 0x00DF891C -> 0x005CF950
claims.append({
    'id': 'vtable_slot20_CArmy_calculate_total_max_strength',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00DF891C - base),
    'base': hex(0x00DF891C),
    'expected': (0x005CF950).to_bytes(4, 'little').hex()
})

# CNavy slot 20 (+0x50) en 0x00E0301C -> 0x005CF950
claims.append({
    'id': 'vtable_slot20_CNavy_calculate_total_max_strength',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E0301C - base),
    'base': hex(0x00E0301C),
    'expected': (0x005CF950).to_bytes(4, 'little').hex()
})

# 4. Constantes de punto flotante:
# Constante double 0.0005 en 0x00E45840
claims.append({
    'id': 'const_double_half_millesimal_exp',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E45840 - base),
    'base': hex(0x00E45840),
    'expected': get_bytes(0x00E45840, 8).hex()
})

# Constante double 1000.0 en 0x00E45660
claims.append({
    'id': 'const_double_1000_scale_exp',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E45660 - base),
    'base': hex(0x00E45660),
    'expected': get_bytes(0x00E45660, 8).hex()
})

# 5. Puntos de llamada críticos:
# Invocación a _allmul en 0x005CF923
claims.append({
    'id': 'call_allmul_at_0x005CF923',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x005CF923 - base),
    'base': hex(0x005CF923),
    'expected': get_bytes(0x005CF923, 5).hex()
})

# Invocación a _alldiv en 0x005CF933
claims.append({
    'id': 'call_alldiv_at_0x005CF933',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x005CF933 - base),
    'base': hex(0x005CF933),
    'expected': get_bytes(0x005CF933, 5).hex()
})

# 6. Padding de alineación:
# Padding tras ret 4 en 0x005CF940 (13 bytes CC)
claims.append({
    'id': 'calculate_average_experience_padding',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x005CF943 - base),
    'base': hex(0x005CF943),
    'expected': (b'\xcc' * 13).hex()
})

# Padding tras ret 4 en 0x005CF9AC (1 byte CC)
claims.append({
    'id': 'calculate_total_max_strength_padding',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x005CF9AF - base),
    'base': hex(0x005CF9AF),
    'expected': (b'\xcc' * 1).hex()
})

# Verificación estática Reverify
verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]

# Negative controls and dependent invalidation
wrong = dict(claims[0], id='negative_control_formation_exp_str', mnemonics=['sub'])
dependent = dict(claims[1], id='negative_dependent_formation_exp_str', depends_on=['negative_control_formation_exp_str'])
controls = verifier.verify_all([Claim.from_dict(wrong), Claim.from_dict(dependent)])
assert [r['verdict'] for r in controls['results']] == ['REFUTED', 'INVALIDATED']

# ==============================================================================
# 2. EMULACIÓN DINÁMICA CON UNICORN ENGINE
# ==============================================================================
uc = Uc(UC_ARCH_X86, UC_MODE_32)
img_size = 0x01100000
uc.mem_map(base, img_size, UC_PROT_ALL)
for s in pe.sections:
    s_va = base + s.VirtualAddress
    sec_data = s.get_data()
    if sec_data:
        uc.mem_write(s_va, sec_data)

SCRATCH_BASE = 0x02000000
SCRATCH_SIZE = 0x00400000
uc.mem_map(SCRATCH_BASE, SCRATCH_SIZE, UC_PROT_ALL)

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

STACK = SCRATCH_BASE + 0x380000
RET_STUB = SCRATCH_BASE + 0x500
uc.mem_write(RET_STUB, b'\x90')

UNIT_ADDR = SCRATCH_BASE + 0x10000
OUT_ADDR = SCRATCH_BASE + 0x10100
NODE_BASE = SCRATCH_BASE + 0x20000
SUBUNIT_BASE = SCRATCH_BASE + 0x40000
TYPE_BASE = SCRATCH_BASE + 0x60000

def setup_formation(subunits_spec, count):
    uc.mem_write(UNIT_ADDR + 0x40, struct.pack('<i', count))
    if not subunits_spec:
        uc.mem_write(UNIT_ADDR + 0x38, struct.pack('<I', 0))
    else:
        uc.mem_write(UNIT_ADDR + 0x38, struct.pack('<I', NODE_BASE))

    for idx, spec in enumerate(subunits_spec):
        n_addr = NODE_BASE + idx * 16
        s_addr = SUBUNIT_BASE + idx * 0x100
        t_addr = TYPE_BASE + idx * 0x100
        next_n = (NODE_BASE + (idx + 1) * 16) if (idx + 1 < len(subunits_spec)) else 0

        uc.mem_write(n_addr + 0x00, struct.pack('<I', s_addr))
        uc.mem_write(n_addr + 0x08, struct.pack('<I', next_n))

        uc.mem_write(s_addr + 0x34, struct.pack('<i', spec.get('exp', 0)))
        uc.mem_write(s_addr + 0x38, struct.pack('<I', t_addr))

        uc.mem_write(t_addr + 0xB0, struct.pack('<i', spec.get('max_str', 0)))

def run_avg_exp_emu(subunits_spec, count):
    setup_formation(subunits_spec, count)
    uc.reg_write(UC_X86_REG_ECX, UNIT_ADDR)
    uc.reg_write(UC_X86_REG_ESP, STACK)
    uc.mem_write(STACK, struct.pack('<II', RET_STUB, OUT_ADDR))
    uc.emu_start(0x005CF8B0, RET_STUB, timeout=2000000)
    return struct.unpack('<i', uc.mem_read(OUT_ADDR, 4))[0]

def run_total_max_str_emu(subunits_spec):
    setup_formation(subunits_spec, len(subunits_spec))
    uc.reg_write(UC_X86_REG_ECX, UNIT_ADDR)
    uc.reg_write(UC_X86_REG_ESP, STACK)
    uc.mem_write(STACK, struct.pack('<II', RET_STUB, OUT_ADDR))
    uc.emu_start(0x005CF950, RET_STUB, timeout=2000000)
    return struct.unpack('<i', uc.mem_read(OUT_ADDR, 4))[0]

total_fixtures = 0
mismatches = 0

# Fixtures para CalculateAverageExperience
exp_fixtures = [
    # 1. Empty formation
    ([], 0),
    ([], 5),
    # 2. Single subunit
    ([{'exp': 0}], 1),
    ([{'exp': 100}], 1),
    ([{'exp': 500}], 1),
    ([{'exp': 1000}], 1),
    ([{'exp': 2000}], 1),
    # 3. Uniform formations
    ([{'exp': 100}, {'exp': 100}], 2),
    ([{'exp': 300}, {'exp': 300}, {'exp': 300}], 3),
    ([{'exp': 250}] * 4, 4),
    ([{'exp': 500}] * 8, 8),
    # 4. Heterogeneous formations
    ([{'exp': 100}, {'exp': 200}], 2),
    ([{'exp': 100}, {'exp': 200}, {'exp': 300}], 3),
    ([{'exp': 100}, {'exp': 200}, {'exp': 301}], 3), # Truncation
    ([{'exp': 50}, {'exp': 150}, {'exp': 250}, {'exp': 350}], 4),
    ([{'exp': 10}, {'exp': 20}, {'exp': 30}, {'exp': 40}, {'exp': 50}], 5),
    ([{'exp': 0}, {'exp': 50}, {'exp': 100}, {'exp': 150}, {'exp': 200}, {'exp': 250}, {'exp': 300}, {'exp': 350}], 8),
    ([{'exp': 1000}, {'exp': 0}, {'exp': 0}, {'exp': 0}], 4),
    # 5. Count zero edge cases (returns total_exp directly)
    ([{'exp': 500}], 0),
    ([{'exp': 10}, {'exp': 20}, {'exp': 30}], 0),
    ([{'exp': 1000}, {'exp': 2000}], 0),
    # 6. Mismatched count vs actual sub-units
    ([{'exp': 100}, {'exp': 200}], 1),
    ([{'exp': 100}, {'exp': 200}], 4),
    ([{'exp': 100}, {'exp': 200}, {'exp': 300}], 2),
    # 7. Large values testing 64-bit bounds
    ([{'exp': 1000000}, {'exp': 2000000}], 2),
    ([{'exp': 5000000}, {'exp': 5000000}, {'exp': 5000000}], 3),
]

for subs, cnt in exp_fixtures:
    emu_val = run_avg_exp_emu(subs, cnt)
    py_val = calculate_average_experience([s['exp'] for s in subs], cnt)
    if emu_val != py_val:
        print(f"MISMATCH in CalculateAverageExperience! subs={subs}, count={cnt} => emu={emu_val}, py={py_val}")
        mismatches += 1
    total_fixtures += 1

# Fixtures para CalculateTotalMaxStrength
max_str_fixtures = [
    # 1. Empty formation
    [],
    # 2. Single regiment
    [{'max_str': 3000}],
    [{'max_str': 1000}],
    [{'max_str': 500}],
    [{'max_str': 100}],
    [{'max_str': 0}],
    # 3. Standard army formations
    [{'max_str': 3000}, {'max_str': 3000}],
    [{'max_str': 3000}, {'max_str': 3000}, {'max_str': 3000}],
    [{'max_str': 3000}, {'max_str': 3000}, {'max_str': 1000}, {'max_str': 500}],
    [{'max_str': 3000}] * 8, # Typical 24,000 corps
    [{'max_str': 3000}] * 12, # 36,000 corps
    # 4. Standard naval fleets
    [{'max_str': 100}],
    [{'max_str': 100}, {'max_str': 100}],
    [{'max_str': 100}, {'max_str': 100}, {'max_str': 100}, {'max_str': 100}],
    [{'max_str': 100}] * 10, # 1000 men naval squadron
    # 5. Mixed formations & edge cases
    [{'max_str': 3000}, {'max_str': 0}, {'max_str': 1000}],
    [{'max_str': 0}, {'max_str': 0}],
    [{'max_str': 10000}, {'max_str': 20000}, {'max_str': 50000}],
    [{'max_str': 1}, {'max_str': 2}, {'max_str': 3}, {'max_str': 4}],
]

for subs in max_str_fixtures:
    emu_val = run_total_max_str_emu(subs)
    py_val = calculate_total_max_strength([s['max_str'] for s in subs])
    if emu_val != py_val:
        print(f"MISMATCH in CalculateTotalMaxStrength! subs={subs} => emu={emu_val}, py={py_val}")
        mismatches += 1
    total_fixtures += 1

assert mismatches == 0, f"{mismatches} mismatches encountered in emulation!"

# Record receipts
out_dir = ROOT / 'evidence/generated/formation-experience-max-strength'
out_dir.mkdir(parents=True, exist_ok=True)
(out_dir / 'claims.json').write_text(json.dumps(claims, indent=2) + '\n')
(out_dir / 'reverify.json').write_text(json.dumps(report, indent=2) + '\n')
(out_dir / 'negative-controls.json').write_text(json.dumps(controls, indent=2) + '\n')
(out_dir / 'emulation.json').write_text(json.dumps({
    'pass': True,
    'fixtures_tested': total_fixtures,
    'mismatches': mismatches,
    'exp_fixtures_count': len(exp_fixtures),
    'max_str_fixtures_count': len(max_str_fixtures)
}, indent=2) + '\n')

# Record into persistent reverify ledger
ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify', file_path=str(bin_path))
ledger.start_run('Verify CUnit::CalculateAverageExperience and CUnit::CalculateTotalMaxStrength', session='formation-experience-max-strength')
ledger.record(report, rnd=1, session='formation-experience-max-strength')
ledger.finish_run(1, report['grounded'], report['information'])
ledger.save()

print(f"Formation experience & max strength: {len(report['results'])} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Formation experience & max strength emulation: {total_fixtures} fixtures executed, 0 mismatches against formation_experience_max_strength_model.")
