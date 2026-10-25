#!/usr/bin/env python3
"""Suite 84: Verificación estática y dinámica de la evaluación de cohesión y ratios
promedio de fuerza y moral en formaciones militares.

Verifica formalmente en el binario PE32 `base-game/v2game.exe`:
- CUnit::CalculateAverageSubunitStrengthRatio (0x005CFE90..0x005CFF85, 96 instrucciones)
- CUnit::CalculateAverageSubunitMoraleRatio (0x005CFF90..0x005D0099, 103 instrucciones)
- Vtables polimórficas de CArmy, CNavy, CRegiment y CShip
- Constantes flotantes y de punto fijo IEEE 754
- Control negativo y cascada dependiente
- Emulación en Unicorn Engine contrastada contra formation_cohesion_model.py
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
from formation_cohesion_model import (
    calculate_average_subunit_strength_ratio,
    calculate_average_subunit_morale_ratio,
)

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

# 1. Instrucciones de CUnit::CalculateAverageSubunitStrengthRatio (0x005CFE90..0x005CFF85)
code1 = get_bytes(0x005CFE90, 0x005CFF85 - 0x005CFE90)
for insn in md.disasm(code1, 0x005CFE90):
    claims.append({
        'id': f'strength_ratio_insn_0x{insn.address:08X}',
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

# 2. Instrucciones de CUnit::CalculateAverageSubunitMoraleRatio (0x005CFF90..0x005D0099)
code2 = get_bytes(0x005CFF90, 0x005D0099 - 0x005CFF90)
for insn in md.disasm(code2, 0x005CFF90):
    claims.append({
        'id': f'morale_ratio_insn_0x{insn.address:08X}',
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
# CArmy slot 21 (+0x54) en 0x00DF8920 -> 0x005CFE90
claims.append({
    'id': 'vtable_slot21_CArmy_strength_ratio',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00DF8920 - base),
    'base': hex(0x00DF8920),
    'expected': (0x005CFE90).to_bytes(4, 'little').hex()
})

# CArmy slot 22 (+0x58) en 0x00DF8924 -> 0x005CFF90
claims.append({
    'id': 'vtable_slot22_CArmy_morale_ratio',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00DF8924 - base),
    'base': hex(0x00DF8924),
    'expected': (0x005CFF90).to_bytes(4, 'little').hex()
})

# CNavy slot 21 (+0x54) en 0x00E03020 -> 0x005CFE90
claims.append({
    'id': 'vtable_slot21_CNavy_strength_ratio',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E03020 - base),
    'base': hex(0x00E03020),
    'expected': (0x005CFE90).to_bytes(4, 'little').hex()
})

# CNavy slot 22 (+0x58) en 0x00E03024 -> 0x005CFF90
claims.append({
    'id': 'vtable_slot22_CNavy_morale_ratio',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E03024 - base),
    'base': hex(0x00E03024),
    'expected': (0x005CFF90).to_bytes(4, 'little').hex()
})

# CRegiment slot 12 (+0x30) en 0x00DF88B4 -> 0x005BFF80 (GetMaxStrength)
claims.append({
    'id': 'vtable_slot12_CRegiment_max_strength',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00DF88B4 - base),
    'base': hex(0x00DF88B4),
    'expected': (0x005BFF80).to_bytes(4, 'little').hex()
})

# CRegiment slot 13 (+0x34) en 0x00DF88B8 -> 0x005BFFA0 (GetMaxMorale)
claims.append({
    'id': 'vtable_slot13_CRegiment_max_morale',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00DF88B8 - base),
    'base': hex(0x00DF88B8),
    'expected': (0x005BFFA0).to_bytes(4, 'little').hex()
})

# CShip slot 12 (+0x30) en 0x00E02A94 -> 0x005BFF80 (GetMaxStrength)
claims.append({
    'id': 'vtable_slot12_CShip_max_strength',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E02A94 - base),
    'base': hex(0x00E02A94),
    'expected': (0x005BFF80).to_bytes(4, 'little').hex()
})

# CShip slot 13 (+0x34) en 0x00E02A98 -> 0x005BFFA0 (GetMaxMorale)
claims.append({
    'id': 'vtable_slot13_CShip_max_morale',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E02A98 - base),
    'base': hex(0x00E02A98),
    'expected': (0x005BFFA0).to_bytes(4, 'little').hex()
})

# 4. Constantes flotantes y de punto fijo:
# Constante float 0.0005 en 0x00E45840
claims.append({
    'id': 'const_float_half_millesimal',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E45840 - base),
    'base': hex(0x00E45840),
    'expected': struct.pack('<d', 0.0005000000237487257).hex()
})

# Constante float 1000.0 en 0x00E45660
claims.append({
    'id': 'const_float_1000_scale',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E45660 - base),
    'base': hex(0x00E45660),
    'expected': struct.pack('<d', 1000.0).hex()
})

# Constante 0x189373 (1610611) de cota inferior segura en 0x005CFF02
claims.append({
    'id': 'strength_const_overflow_bias',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x005CFF02 - base),
    'base': hex(0x005CFF02),
    'expected': (0x189373).to_bytes(4, 'little').hex()
})

# Constante 0x39580d (3758093) de cota superior segura en 0x005CFF0A
claims.append({
    'id': 'strength_const_overflow_limit',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x005CFF0A - base),
    'base': hex(0x005CFF0A),
    'expected': (0x39580D).to_bytes(4, 'little').hex()
})

# Padding de alineación entre rutinas (11 bytes CC en 0x005CFF85..0x005CFF90)
claims.append({
    'id': 'formation_cohesion_padding_mid',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x005CFF85 - base),
    'base': hex(0x005CFF85),
    'expected': (b'\xcc' * 11).hex()
})

# Padding de alineación tras 0x005D0096 (7 bytes CC en 0x005D0099..0x005D00A0)
claims.append({
    'id': 'formation_cohesion_padding_end',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x005D0099 - base),
    'base': hex(0x005D0099),
    'expected': (b'\xcc' * 7).hex()
})

# Verificación estática Reverify
verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]

# Negative controls and dependent invalidation
wrong = dict(claims[0], id='negative_control_formation_cohesion', mnemonics=['sub'])
dependent = dict(claims[1], id='negative_dependent_formation_cohesion', depends_on=['negative_control_formation_cohesion'])
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

# CRT floor y ftol2 hooks
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

# Subunit mock virtual methods
MOCK_GET_MAX_STR = SCRATCH_BASE + 0x1000
# mov eax, [esp+4]; mov edx, [ecx+0x38]; mov edx, [edx+0xb0]; mov [eax], edx; ret 8
MOCK_STR_CODE = bytes([0x8B, 0x44, 0x24, 0x04, 0x8B, 0x51, 0x38, 0x8B, 0x92, 0xB0, 0x00, 0x00, 0x00, 0x89, 0x10, 0xC2, 0x08, 0x00])
uc.mem_write(MOCK_GET_MAX_STR, MOCK_STR_CODE)

MOCK_GET_MAX_MOR = SCRATCH_BASE + 0x1040
# mov eax, [esp+4]; mov edx, [ecx+0x38]; mov edx, [edx+0xb4]; mov [eax], edx; ret 8
MOCK_MOR_CODE = bytes([0x8B, 0x44, 0x24, 0x04, 0x8B, 0x51, 0x38, 0x8B, 0x92, 0xB4, 0x00, 0x00, 0x00, 0x89, 0x10, 0xC2, 0x08, 0x00])
uc.mem_write(MOCK_GET_MAX_MOR, MOCK_MOR_CODE)

SUBUNIT_VT = SCRATCH_BASE + 0x2000
uc.mem_write(SUBUNIT_VT + 0x30, struct.pack('<I', MOCK_GET_MAX_STR))
uc.mem_write(SUBUNIT_VT + 0x34, struct.pack('<I', MOCK_GET_MAX_MOR))

UNIT_ADDR = SCRATCH_BASE + 0x10000
OUT_RATIO_ADDR = SCRATCH_BASE + 0x10100
STACK = SCRATCH_BASE + 0x380000
RET_STUB = SCRATCH_BASE + 0x500
uc.mem_write(RET_STUB, b'\x90')

NODE_BASE = SCRATCH_BASE + 0x20000
SUBUNIT_BASE = SCRATCH_BASE + 0x40000
TYPE_BASE = SCRATCH_BASE + 0x60000
POP_BASE = SCRATCH_BASE + 0x80000

def run_strength_ratio_emu(subunits: list, count: int) -> int:
    if not subunits:
        uc.mem_write(UNIT_ADDR + 0x38, struct.pack('<I', 0))
    else:
        uc.mem_write(UNIT_ADDR + 0x38, struct.pack('<I', NODE_BASE))

    uc.mem_write(UNIT_ADDR + 0x40, struct.pack('<i', count))

    for idx, (curr_str, max_str) in enumerate(subunits):
        n_addr = NODE_BASE + idx * 16
        s_addr = SUBUNIT_BASE + idx * 0x100
        t_addr = TYPE_BASE + idx * 0x100
        next_n = (NODE_BASE + (idx + 1) * 16) if (idx + 1 < len(subunits)) else 0

        uc.mem_write(n_addr + 0x00, struct.pack('<I', s_addr))
        uc.mem_write(n_addr + 0x08, struct.pack('<I', next_n))

        uc.mem_write(s_addr + 0x00, struct.pack('<I', SUBUNIT_VT))
        uc.mem_write(s_addr + 0x38, struct.pack('<I', t_addr))
        uc.mem_write(s_addr + 0x3C, struct.pack('<i', curr_str))

        uc.mem_write(t_addr + 0xB0, struct.pack('<i', max_str))

    uc.reg_write(UC_X86_REG_ECX, UNIT_ADDR)
    uc.reg_write(UC_X86_REG_ESP, STACK)
    uc.mem_write(STACK, struct.pack('<II', RET_STUB, OUT_RATIO_ADDR))

    uc.emu_start(0x005CFE90, RET_STUB, timeout=2000000)
    return struct.unpack('<i', uc.mem_read(OUT_RATIO_ADDR, 4))[0]

def run_morale_ratio_emu(subunits: list, count: int) -> int:
    if not subunits:
        uc.mem_write(UNIT_ADDR + 0x38, struct.pack('<I', 0))
    else:
        uc.mem_write(UNIT_ADDR + 0x38, struct.pack('<I', NODE_BASE))

    uc.mem_write(UNIT_ADDR + 0x40, struct.pack('<i', count))

    for idx, (curr_mor, max_mor, is_rebel) in enumerate(subunits):
        n_addr = NODE_BASE + idx * 16
        s_addr = SUBUNIT_BASE + idx * 0x100
        t_addr = TYPE_BASE + idx * 0x100
        p_addr = POP_BASE + idx * 0x200
        next_n = (NODE_BASE + (idx + 1) * 16) if (idx + 1 < len(subunits)) else 0

        uc.mem_write(n_addr + 0x00, struct.pack('<I', s_addr))
        uc.mem_write(n_addr + 0x08, struct.pack('<I', next_n))

        uc.mem_write(s_addr + 0x00, struct.pack('<I', SUBUNIT_VT))
        uc.mem_write(s_addr + 0x38, struct.pack('<I', t_addr))
        uc.mem_write(s_addr + 0x40, struct.pack('<i', curr_mor))

        if is_rebel is not None:
            uc.mem_write(s_addr + 0x74, struct.pack('<I', p_addr))
            uc.mem_write(p_addr + 0x164, bytes([1 if is_rebel else 0]))
        else:
            uc.mem_write(s_addr + 0x74, struct.pack('<I', 0))

        uc.mem_write(t_addr + 0xB4, struct.pack('<i', max_mor))

    uc.reg_write(UC_X86_REG_ECX, UNIT_ADDR)
    uc.reg_write(UC_X86_REG_ESP, STACK)
    uc.mem_write(STACK, struct.pack('<II', RET_STUB, OUT_RATIO_ADDR))

    uc.emu_start(0x005CFF90, RET_STUB, timeout=2000000)
    return struct.unpack('<i', uc.mem_read(OUT_RATIO_ADDR, 4))[0]

# Fixtures de prueba dinámica
strength_fixtures = [
    # (subunits, count)
    ([], 0),
    ([], 5),
    ([(3000, 3000)], 1),
    ([(1500, 3000)], 1),
    ([(0, 3000)], 1),
    ([(1000, 1000), (500, 1000)], 2),
    ([(1000, 1000), (500, 1000), (250, 1000)], 3),
    ([(3000, 3000), (2000, 3000), (1000, 3000), (500, 3000)], 4),
    ([(100, 3000), (200, 3000), (300, 3000), (400, 3000), (500, 3000)], 5),
    ([(3000, 0)], 1),  # max = 0 -> ratio = -1
    ([(3000, 0), (1000, 1000)], 2),
    ([(10000, 10000)], 1),
    ([(5000000, 10000000)], 1),  # Rango 64 bits
    ([(3000, 3000)], 0),  # count = 0
    ([(1500, 3000), (1500, 3000)], 1),  # count != len
    ([(777, 1000), (888, 1000), (999, 1000)], 3),
    ([(1, 1000)], 1),
    ([(999, 1000)], 1),
    ([(1234, 4000), (2345, 4000), (3456, 4000)], 3),
    ([(3000, 3000)] * 8, 8),
    ([(1500, 3000)] * 8, 8),
    ([(0, 3000)] * 8, 8),
    ([(3000, 3000), (0, 3000)], 2),
    ([(2500000, 5000000)], 1),
    ([(3000000, 4000000)], 1),
    ([(1000, 2000), (2000, 4000), (3000, 6000)], 3),
    ([(500, 1000), (500, 1000), (500, 1000), (500, 1000)], 4),
    ([(250, 1000), (500, 1000), (750, 1000), (1000, 1000)], 4),
    ([(3000, 3000), (3000, 3000), (0, 0)], 3),
    ([(100, 100)], 2),
]

morale_fixtures = [
    # (subunits: [(curr, max, is_rebel)], count)
    ([], 0),
    ([], 4),
    ([(3000, 3000, False)], 1),
    ([(1500, 3000, False)], 1),
    ([(3000, 3000, True)], 1),  # Rebelde -> 0
    ([(1500, 3000, True)], 1),  # Rebelde -> 0
    ([(3000, 3000, None)], 1),  # Pop nulo -> normal
    ([(3000, 3000, False), (3000, 3000, True)], 2),  # (1000 + 0) / 2 = 500
    ([(3000, 3000, False), (1500, 3000, False), (0, 3000, False)], 3),
    ([(1000, 1000, False), (500, 1000, True), (250, 1000, False)], 3),
    ([(3000, 0, False)], 1),  # max = 0 -> -1
    ([(3000, 0, True)], 1),   # max = 0, rebelde -> 0 / 0 -> -1
    ([(5000000, 10000000, False)], 1),  # Rango 64 bits
    ([(3000, 3000, False)], 0),  # count = 0
    ([(1500, 3000, False), (1500, 3000, False)], 1),
    ([(777, 1000, False), (888, 1000, True), (999, 1000, False)], 3),
    ([(1, 1000, False)], 1),
    ([(999, 1000, False)], 1),
    ([(1234, 4000, False), (2345, 4000, False), (3456, 4000, True)], 3),
    ([(3000, 3000, False)] * 6, 6),
    ([(3000, 3000, True)] * 6, 6),
    ([(0, 3000, False)] * 6, 6),
    ([(3000, 3000, False), (0, 3000, False)], 2),
    ([(2500000, 5000000, False)], 1),
    ([(3000000, 4000000, True)], 1),
    ([(1000, 2000, False), (2000, 4000, False), (3000, 6000, False)], 3),
    ([(500, 1000, True), (500, 1000, True), (500, 1000, False), (500, 1000, False)], 4),
    ([(250, 1000, False), (500, 1000, False), (750, 1000, False), (1000, 1000, False)], 4),
    ([(3000, 3000, False), (3000, 3000, False), (0, 0, False)], 3),
    ([(100, 100, False)], 2),
]

mismatches = 0
total_fixtures = 0

for subs, cnt in strength_fixtures:
    emu_val = run_strength_ratio_emu(subs, cnt)
    py_val = calculate_average_subunit_strength_ratio(subs, cnt)
    if emu_val != py_val:
        print(f"MISMATCH in strength_ratio! subs={subs}, cnt={cnt} => emu={emu_val}, py={py_val}")
        mismatches += 1
    total_fixtures += 1

for subs, cnt in morale_fixtures:
    emu_val = run_morale_ratio_emu(subs, cnt)
    py_subs = [(m, mx, bool(reb)) for m, mx, reb in subs]
    py_val = calculate_average_subunit_morale_ratio(py_subs, cnt)
    if emu_val != py_val:
        print(f"MISMATCH in morale_ratio! subs={subs}, cnt={cnt} => emu={emu_val}, py={py_val}")
        mismatches += 1
    total_fixtures += 1

assert mismatches == 0, f"{mismatches} mismatches encountered in emulation!"

# Record receipts
out_dir = ROOT / 'evidence/generated/formation-cohesion'
out_dir.mkdir(parents=True, exist_ok=True)
(out_dir / 'claims.json').write_text(json.dumps(claims, indent=2) + '\n')
(out_dir / 'reverify.json').write_text(json.dumps(report, indent=2) + '\n')
(out_dir / 'negative-controls.json').write_text(json.dumps(controls, indent=2) + '\n')
(out_dir / 'emulation.json').write_text(json.dumps({
    'pass': True,
    'fixtures_tested': total_fixtures,
    'mismatches': mismatches,
    'strength_fixtures_count': len(strength_fixtures),
    'morale_fixtures_count': len(morale_fixtures)
}, indent=2) + '\n')

# Record into persistent reverify ledger
ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify', file_path=str(bin_path))
ledger.start_run('Verify CUnit::CalculateAverageSubunitStrengthRatio and CUnit::CalculateAverageSubunitMoraleRatio', session='formation-cohesion')
ledger.record(report, rnd=1, session='formation-cohesion')
ledger.finish_run(1, report['grounded'], report['information'])
ledger.save()

print(f"Formation cohesion: {len(report['results'])} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Formation cohesion emulation: {total_fixtures} fixtures executed, 0 mismatches against formation_cohesion_model.")
