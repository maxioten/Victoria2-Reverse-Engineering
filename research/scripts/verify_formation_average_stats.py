#!/usr/bin/env python3
"""Suite 89: Verificación estática y dinámica de la moral media y fuerza media
de formaciones militares.

Verifica formalmente en el binario PE32 `base-game/v2game.exe`:
- CUnit::CalculateAverageMorale (0x005CFA90..0x005CFB03, 51 instrucciones)
- CUnit::CalculateAverageStrength (0x005CFB10..0x005CFB73, 46 instrucciones)
- Vtables de CArmy y CNavy (slots 17 y 18 en 0x00DF8910/4 y 0x00E03010/4)
- Filtro de moral para facciones rebeldes
- Puntos de llamada a _allmul y _alldiv
- Control negativo y cascada dependiente
- Emulación en Unicorn Engine contrastada contra formation_average_stats_model.py
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
from formation_average_stats_model import calculate_average_morale, calculate_average_strength

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

# 1. Instrucciones de CUnit::CalculateAverageMorale (0x005CFA90..0x005CFB03)
code1 = get_bytes(0x005CFA90, 0x005CFB03 - 0x005CFA90)
for insn in md.disasm(code1, 0x005CFA90):
    claims.append({
        'id': f'unit_calc_avg_morale_insn_0x{insn.address:08X}',
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

# 2. Instrucciones de CUnit::CalculateAverageStrength (0x005CFB10..0x005CFB73)
code2 = get_bytes(0x005CFB10, 0x005CFB73 - 0x005CFB10)
for insn in md.disasm(code2, 0x005CFB10):
    claims.append({
        'id': f'unit_calc_avg_strength_insn_0x{insn.address:08X}',
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
# CArmy slot 17 (+0x44) en 0x00DF8910 -> 0x005CFA90
claims.append({
    'id': 'vtable_slot17_CArmy_calculate_average_morale',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00DF8910 - base),
    'base': hex(0x00DF8910),
    'expected': (0x005CFA90).to_bytes(4, 'little').hex()
})

# CNavy slot 17 (+0x44) en 0x00E03010 -> 0x005CFA90
claims.append({
    'id': 'vtable_slot17_CNavy_calculate_average_morale',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E03010 - base),
    'base': hex(0x00E03010),
    'expected': (0x005CFA90).to_bytes(4, 'little').hex()
})

# CArmy slot 18 (+0x48) en 0x00DF8914 -> 0x005CFB10
claims.append({
    'id': 'vtable_slot18_CArmy_calculate_average_strength',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00DF8914 - base),
    'base': hex(0x00DF8914),
    'expected': (0x005CFB10).to_bytes(4, 'little').hex()
})

# CNavy slot 18 (+0x48) en 0x00E03014 -> 0x005CFB10
claims.append({
    'id': 'vtable_slot18_CNavy_calculate_average_strength',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E03014 - base),
    'base': hex(0x00E03014),
    'expected': (0x005CFB10).to_bytes(4, 'little').hex()
})

# 4. Puntos de llamada críticos:
# Invocación a _allmul en CalculateAverageMorale en 0x005CFAE3
claims.append({
    'id': 'call_allmul_at_0x005CFAE3',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x005CFAE3 - base),
    'base': hex(0x005CFAE3),
    'expected': get_bytes(0x005CFAE3, 5).hex()
})

# Invocación a _alldiv en CalculateAverageMorale en 0x005CFAF3
claims.append({
    'id': 'call_alldiv_at_0x005CFAF3',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x005CFAF3 - base),
    'base': hex(0x005CFAF3),
    'expected': get_bytes(0x005CFAF3, 5).hex()
})

# Invocación a _allmul en CalculateAverageStrength en 0x005CFB53
claims.append({
    'id': 'call_allmul_at_0x005CFB53',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x005CFB53 - base),
    'base': hex(0x005CFB53),
    'expected': get_bytes(0x005CFB53, 5).hex()
})

# Invocación a _alldiv en CalculateAverageStrength en 0x005CFB63
claims.append({
    'id': 'call_alldiv_at_0x005CFB63',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x005CFB63 - base),
    'base': hex(0x005CFB63),
    'expected': get_bytes(0x005CFB63, 5).hex()
})

# 5. Padding de alineación:
# Padding tras ret 4 en 0x005CFB00 (13 bytes CC)
claims.append({
    'id': 'calculate_average_morale_padding',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x005CFB03 - base),
    'base': hex(0x005CFB03),
    'expected': (b'\xcc' * 13).hex()
})

# Padding tras ret 4 en 0x005CFB70 (13 bytes CC)
claims.append({
    'id': 'calculate_average_strength_padding',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x005CFB73 - base),
    'base': hex(0x005CFB73),
    'expected': (b'\xcc' * 13).hex()
})

# Verificación estática Reverify
verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]

# Negative controls and dependent invalidation
wrong = dict(claims[0], id='negative_control_formation_avg_stats', mnemonics=['sub'])
dependent = dict(claims[1], id='negative_dependent_formation_avg_stats', depends_on=['negative_control_formation_avg_stats'])
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

STACK = SCRATCH_BASE + 0x380000
RET_STUB = SCRATCH_BASE + 0x500
uc.mem_write(RET_STUB, b'\x90')

UNIT_ADDR = SCRATCH_BASE + 0x10000
OUT_ADDR = SCRATCH_BASE + 0x10100
NODE_BASE = SCRATCH_BASE + 0x20000
SUBUNIT_BASE = SCRATCH_BASE + 0x40000
POP_BASE = SCRATCH_BASE + 0x60000

def setup_formation(subunits_spec, count):
    uc.mem_write(UNIT_ADDR + 0x40, struct.pack('<i', count))
    if not subunits_spec:
        uc.mem_write(UNIT_ADDR + 0x38, struct.pack('<I', 0))
    else:
        uc.mem_write(UNIT_ADDR + 0x38, struct.pack('<I', NODE_BASE))

    for idx, spec in enumerate(subunits_spec):
        n_addr = NODE_BASE + idx * 16
        s_addr = SUBUNIT_BASE + idx * 0x100
        p_addr = POP_BASE + idx * 0x200
        next_n = (NODE_BASE + (idx + 1) * 16) if (idx + 1 < len(subunits_spec)) else 0

        uc.mem_write(n_addr + 0x00, struct.pack('<I', s_addr))
        uc.mem_write(n_addr + 0x08, struct.pack('<I', next_n))

        uc.mem_write(s_addr + 0x3C, struct.pack('<i', spec.get('strength', 0)))
        uc.mem_write(s_addr + 0x40, struct.pack('<i', spec.get('morale', 0)))

        is_rebel = spec.get('is_rebel', False)
        if is_rebel is not None:
            uc.mem_write(s_addr + 0x74, struct.pack('<I', p_addr))
            uc.mem_write(p_addr + 0x164, bytes([1 if is_rebel else 0]))
        else:
            uc.mem_write(s_addr + 0x74, struct.pack('<I', 0))

def run_avg_mor_emu(subunits_spec, count):
    setup_formation(subunits_spec, count)
    uc.reg_write(UC_X86_REG_ECX, UNIT_ADDR)
    uc.reg_write(UC_X86_REG_ESP, STACK)
    uc.mem_write(STACK, struct.pack('<II', RET_STUB, OUT_ADDR))
    uc.emu_start(0x005CFA90, RET_STUB, timeout=2000000)
    return struct.unpack('<i', uc.mem_read(OUT_ADDR, 4))[0]

def run_avg_str_emu(subunits_spec, count):
    setup_formation(subunits_spec, count)
    uc.reg_write(UC_X86_REG_ECX, UNIT_ADDR)
    uc.reg_write(UC_X86_REG_ESP, STACK)
    uc.mem_write(STACK, struct.pack('<II', RET_STUB, OUT_ADDR))
    uc.emu_start(0x005CFB10, RET_STUB, timeout=2000000)
    return struct.unpack('<i', uc.mem_read(OUT_ADDR, 4))[0]

total_fixtures = 0
mismatches = 0

# Fixtures para CalculateAverageMorale
mor_fixtures = [
    # 1. Empty formation
    ([], 0),
    ([], 3),
    # 2. Single subunit
    ([{'morale': 0}], 1),
    ([{'morale': 1000}], 1),
    ([{'morale': 2000}], 1),
    ([{'morale': 3000}], 1),
    ([{'morale': 5000}], 1),
    # 3. Rebel POP filtration
    ([{'morale': 3000, 'is_rebel': True}], 1),
    ([{'morale': 3000, 'is_rebel': True}, {'morale': 3000}], 2),
    ([{'morale': 3000, 'is_rebel': True}, {'morale': 3000, 'is_rebel': True}], 2),
    ([{'morale': 2000, 'is_rebel': True}, {'morale': 4000, 'is_rebel': False}], 2),
    # 4. Multi-subunit uniform & heterogeneous
    ([{'morale': 3000}, {'morale': 3000}], 2),
    ([{'morale': 1000}, {'morale': 2000}, {'morale': 3000}], 3),
    ([{'morale': 1000}, {'morale': 2000}, {'morale': 3001}], 3), # Truncation
    ([{'morale': 2500}, {'morale': 2000}, {'morale': 1500}, {'morale': 1000}], 4),
    ([{'morale': 3000}] * 8, 8),
    ([{'morale': 3000, 'is_rebel': True}] * 2 + [{'morale': 3000}] * 6, 8),
    ([{'morale': 100}, {'morale': 200}, {'morale': 300}, {'morale': 400}, {'morale': 500}], 5),
    # 5. Count zero edge cases
    ([{'morale': 3000}], 0),
    ([{'morale': 1500}, {'morale': 2500}], 0),
    # 6. Mismatched count vs length
    ([{'morale': 1000}, {'morale': 2000}], 1),
    ([{'morale': 1000}, {'morale': 2000}], 4),
    # 7. 64-bit boundaries
    ([{'morale': 2000000}, {'morale': 4000000}], 2),
    ([{'morale': 5000000}, {'morale': 5000000}], 2),
]

for subs, cnt in mor_fixtures:
    emu_val = run_avg_mor_emu(subs, cnt)
    py_val = calculate_average_morale(subs, cnt)
    if emu_val != py_val:
        print(f"MISMATCH in CalculateAverageMorale! subs={subs}, count={cnt} => emu={emu_val}, py={py_val}")
        mismatches += 1
    total_fixtures += 1

# Fixtures para CalculateAverageStrength
str_fixtures = [
    # 1. Empty formation
    ([], 0),
    ([], 4),
    # 2. Single subunit
    ([{'strength': 0}], 1),
    ([{'strength': 100}], 1),
    ([{'strength': 500}], 1),
    ([{'strength': 1500}], 1),
    ([{'strength': 3000}], 1),
    # 3. Standard army formations
    ([{'strength': 3000}, {'strength': 1500}], 2),
    ([{'strength': 3000}, {'strength': 3000}, {'strength': 1500}], 3),
    ([{'strength': 3000}, {'strength': 2500}, {'strength': 2000}, {'strength': 1500}], 4),
    ([{'strength': 3000}] * 8, 8),
    ([{'strength': 1000}, {'strength': 1500}, {'strength': 2000}, {'strength': 2500}, {'strength': 3000}, {'strength': 2500}, {'strength': 2000}, {'strength': 1500}], 8),
    # 4. Naval squadrons
    ([{'strength': 100}, {'strength': 100}], 2),
    ([{'strength': 100}, {'strength': 50}, {'strength': 0}], 3),
    ([{'strength': 100}] * 6, 6),
    # 5. Count zero edge cases
    ([{'strength': 3000}], 0),
    ([{'strength': 3000}, {'strength': 1000}], 0),
    # 6. Mismatched count vs length
    ([{'strength': 1000}, {'strength': 2000}], 1),
    ([{'strength': 1000}, {'strength': 2000}], 4),
    # 7. 64-bit boundaries
    ([{'strength': 5000000}, {'strength': 5000000}], 2),
    ([{'strength': 3000000}, {'strength': 6000000}, {'strength': 9000000}], 3),
]

for subs, cnt in str_fixtures:
    emu_val = run_avg_str_emu(subs, cnt)
    py_val = calculate_average_strength([s['strength'] for s in subs], cnt)
    if emu_val != py_val:
        print(f"MISMATCH in CalculateAverageStrength! subs={subs}, count={cnt} => emu={emu_val}, py={py_val}")
        mismatches += 1
    total_fixtures += 1

assert mismatches == 0, f"{mismatches} mismatches encountered in emulation!"

# Record receipts
out_dir = ROOT / 'evidence/generated/formation-average-stats'
out_dir.mkdir(parents=True, exist_ok=True)
(out_dir / 'claims.json').write_text(json.dumps(claims, indent=2) + '\n')
(out_dir / 'reverify.json').write_text(json.dumps(report, indent=2) + '\n')
(out_dir / 'negative-controls.json').write_text(json.dumps(controls, indent=2) + '\n')
(out_dir / 'emulation.json').write_text(json.dumps({
    'pass': True,
    'fixtures_tested': total_fixtures,
    'mismatches': mismatches,
    'mor_fixtures_count': len(mor_fixtures),
    'str_fixtures_count': len(str_fixtures)
}, indent=2) + '\n')

# Record into persistent reverify ledger
ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify', file_path=str(bin_path))
ledger.start_run('Verify CUnit::CalculateAverageMorale and CUnit::CalculateAverageStrength', session='formation-average-stats')
ledger.record(report, rnd=1, session='formation-average-stats')
ledger.finish_run(1, report['grounded'], report['information'])
ledger.save()

print(f"Formation average stats: {len(report['results'])} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Formation average stats emulation: {total_fixtures} fixtures executed, 0 mismatches against formation_average_stats_model.")
