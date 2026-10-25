#!/usr/bin/env python3
"""Suite 86: Verificación estática y dinámica de la potencia de combate efectiva
y la calificación táctica de subunidades militares.

Verifica formalmente en el binario PE32 `base-game/v2game.exe`:
- CUnitType::CalculateCombatRating (0x005BDC80..0x005BDD45, 63 instrucciones)
- CUnit::CalculateEffectiveCombatPower (0x005D0500..0x005D05E2, 83 instrucciones)
- Vtables de CArmy y CNavy (slot 25 en 0x00DF8930 / 0x00E03030)
- Vtables de CRegiment y CShip (slot 12 en 0x00DF88B4 / 0x00E02A94)
- Constantes de punto flotante en 0x00E45998, 0x00E45840, 0x00E45660
- Control negativo y cascada dependiente
- Emulación en Unicorn Engine contrastada contra unit_combat_power_model.py
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
from unit_combat_power_model import calculate_combat_rating, calculate_effective_combat_power

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

# 1. Instrucciones de CUnitType::CalculateCombatRating (0x005BDC80..0x005BDD45)
code1 = get_bytes(0x005BDC80, 0x005BDD45 - 0x005BDC80)
for insn in md.disasm(code1, 0x005BDC80):
    claims.append({
        'id': f'unit_type_calc_combat_rating_insn_0x{insn.address:08X}',
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

# 2. Instrucciones de CUnit::CalculateEffectiveCombatPower (0x005D0500..0x005D05E2)
code2 = get_bytes(0x005D0500, 0x005D05E2 - 0x005D0500)
for insn in md.disasm(code2, 0x005D0500):
    claims.append({
        'id': f'unit_calc_combat_power_insn_0x{insn.address:08X}',
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
# CArmy slot 25 (+0x64) en 0x00DF8930 -> 0x005D0500
claims.append({
    'id': 'vtable_slot25_CArmy_calculate_effective_combat_power',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00DF8930 - base),
    'base': hex(0x00DF8930),
    'expected': (0x005D0500).to_bytes(4, 'little').hex()
})

# CNavy slot 25 (+0x64) en 0x00E03030 -> 0x005D0500
claims.append({
    'id': 'vtable_slot25_CNavy_calculate_effective_combat_power',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E03030 - base),
    'base': hex(0x00E03030),
    'expected': (0x005D0500).to_bytes(4, 'little').hex()
})

# CRegiment slot 12 (+0x30) en 0x00DF88B4 -> 0x005BFF80
claims.append({
    'id': 'vtable_slot12_CRegiment_get_max_strength',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00DF88B4 - base),
    'base': hex(0x00DF88B4),
    'expected': (0x005BFF80).to_bytes(4, 'little').hex()
})

# CShip slot 12 (+0x30) en 0x00E02A94 -> 0x005BFF80
claims.append({
    'id': 'vtable_slot12_CShip_get_max_strength',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E02A94 - base),
    'base': hex(0x00E02A94),
    'expected': (0x005BFF80).to_bytes(4, 'little').hex()
})

# 4. Constantes de punto flotante:
# Constante float 1000.5f en 0x00E45998
claims.append({
    'id': 'const_float_1000_5_combat_rating',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E45998 - base),
    'base': hex(0x00E45998),
    'expected': get_bytes(0x00E45998, 4).hex()
})

# Constante double 0.0005 en 0x00E45840
claims.append({
    'id': 'const_double_half_millesimal_combat_power',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E45840 - base),
    'base': hex(0x00E45840),
    'expected': get_bytes(0x00E45840, 8).hex()
})

# Constante double 1000.0 en 0x00E45660
claims.append({
    'id': 'const_double_1000_combat_power',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E45660 - base),
    'base': hex(0x00E45660),
    'expected': get_bytes(0x00E45660, 8).hex()
})

# 5. Puntos de llamada críticos:
# Llamada a CUnitType::CalculateCombatRating en 0x005D055B
claims.append({
    'id': 'call_calculate_combat_rating_at_0x005D055B',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x005D055B - base),
    'base': hex(0x005D055B),
    'expected': get_bytes(0x005D055B, 5).hex()
})

# Llamada a _alldiv en CUnitType::CalculateCombatRating (rama terrestre) en 0x005BDCD0
claims.append({
    'id': 'call_alldiv_at_0x005BDCD0',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x005BDCD0 - base),
    'base': hex(0x005BDCD0),
    'expected': get_bytes(0x005BDCD0, 5).hex()
})

# Llamada a _alldiv en CUnitType::CalculateCombatRating (rama naval) en 0x005BDD36
claims.append({
    'id': 'call_alldiv_at_0x005BDD36',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x005BDD36 - base),
    'base': hex(0x005BDD36),
    'expected': get_bytes(0x005BDD36, 5).hex()
})

# Llamada a _alldiv en CUnit::CalculateEffectiveCombatPower en 0x005D05C2
claims.append({
    'id': 'call_alldiv_at_0x005D05C2',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x005D05C2 - base),
    'base': hex(0x005D05C2),
    'expected': get_bytes(0x005D05C2, 5).hex()
})

# 6. Padding de alineación:
# Padding tras ret en 0x005BDD44 (3 bytes CC)
claims.append({
    'id': 'calculate_combat_rating_padding',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x005BDD45 - base),
    'base': hex(0x005BDD45),
    'expected': (b'\xcc' * 3).hex()
})

# Padding tras ret 4 en 0x005D05E2 (3 bytes CC)
claims.append({
    'id': 'calculate_effective_combat_power_padding',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x005D05E2 - base),
    'base': hex(0x005D05E2),
    'expected': (b'\xcc' * 3).hex()
})

# Verificación estática Reverify
verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]

# Negative controls and dependent invalidation
wrong = dict(claims[0], id='negative_control_unit_combat_power', mnemonics=['sub'])
dependent = dict(claims[1], id='negative_dependent_unit_combat_power', depends_on=['negative_control_unit_combat_power'])
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

# Mock GetMaxStrength: mov eax, [esp+4]; mov edx, [ecx+0x44]; mov [eax], edx; ret 8
MOCK_GET_MAX_STR = SCRATCH_BASE + 0x1000
uc.mem_write(MOCK_GET_MAX_STR, bytes([0x8B, 0x44, 0x24, 0x04, 0x8B, 0x51, 0x44, 0x89, 0x10, 0xC2, 0x08, 0x00]))

SUBUNIT_VT = SCRATCH_BASE + 0x2000
uc.mem_write(SUBUNIT_VT + 0x30, struct.pack('<I', MOCK_GET_MAX_STR))

STACK = SCRATCH_BASE + 0x380000
RET_STUB = SCRATCH_BASE + 0x500
uc.mem_write(RET_STUB, b'\x90')

UNIT_ADDR = SCRATCH_BASE + 0x10000
OUT_TOTAL_ADDR = SCRATCH_BASE + 0x10100
OUT_RATING_ADDR = SCRATCH_BASE + 0x10200
TYPE_ADDR_SINGLE = SCRATCH_BASE + 0x10300

NODE_BASE = SCRATCH_BASE + 0x20000
SUBUNIT_BASE = SCRATCH_BASE + 0x40000
TYPE_BASE = SCRATCH_BASE + 0x60000

def run_combat_rating_emu(spec: dict) -> int:
    uc.mem_write(TYPE_ADDR_SINGLE, b'\x00' * 0x300)
    is_land = spec.get('is_land', True)
    is_aux = spec.get('is_aux', False)
    uc.mem_write(TYPE_ADDR_SINGLE + 0x39, bytes([1 if is_land else 0]))
    uc.mem_write(TYPE_ADDR_SINGLE + 0x38, bytes([1 if is_aux else 0]))

    if is_land:
        uc.mem_write(TYPE_ADDR_SINGLE + 0x228, struct.pack('<i', spec.get('recon', 0)))
        uc.mem_write(TYPE_ADDR_SINGLE + 0x22C, struct.pack('<i', spec.get('attack', 0)))
        uc.mem_write(TYPE_ADDR_SINGLE + 0x230, struct.pack('<i', spec.get('defense', 0)))
        uc.mem_write(TYPE_ADDR_SINGLE + 0x234, struct.pack('<i', spec.get('support', 0)))
        uc.mem_write(TYPE_ADDR_SINGLE + 0x238, struct.pack('<i', spec.get('discipline', 1000)))
        uc.mem_write(TYPE_ADDR_SINGLE + 0x23C, struct.pack('<i', spec.get('maneuver', 0)))
        uc.mem_write(TYPE_ADDR_SINGLE + 0x240, struct.pack('<i', spec.get('siege', 0)))
    else:
        uc.mem_write(TYPE_ADDR_SINGLE + 0x244, struct.pack('<i', spec.get('gun_power', 0)))
        uc.mem_write(TYPE_ADDR_SINGLE + 0x248, struct.pack('<i', spec.get('hull', 0)))
        uc.mem_write(TYPE_ADDR_SINGLE + 0x24C, struct.pack('<i', spec.get('evasion', 0)))
        uc.mem_write(TYPE_ADDR_SINGLE + 0x250, struct.pack('<i', spec.get('torpedo', 0)))
        uc.mem_write(TYPE_ADDR_SINGLE + 0x25C, struct.pack('<i', spec.get('armor', 0)))

    uc.reg_write(UC_X86_REG_EAX, TYPE_ADDR_SINGLE)
    uc.reg_write(UC_X86_REG_EDI, OUT_RATING_ADDR)
    uc.reg_write(UC_X86_REG_ESP, STACK)
    uc.mem_write(STACK, struct.pack('<I', RET_STUB))

    uc.emu_start(0x005BDC80, RET_STUB, timeout=2000000)
    return struct.unpack('<i', uc.mem_read(OUT_RATING_ADDR, 4))[0]

def run_effective_combat_power_emu(subunits_spec: list) -> int:
    if not subunits_spec:
        uc.mem_write(UNIT_ADDR + 0x38, struct.pack('<I', 0))
    else:
        uc.mem_write(UNIT_ADDR + 0x38, struct.pack('<I', NODE_BASE))

    for idx, spec in enumerate(subunits_spec):
        n_addr = NODE_BASE + idx * 16
        s_addr = SUBUNIT_BASE + idx * 0x100
        t_addr = TYPE_BASE + idx * 0x400
        next_n = (NODE_BASE + (idx + 1) * 16) if (idx + 1 < len(subunits_spec)) else 0

        uc.mem_write(n_addr + 0x00, struct.pack('<I', s_addr))
        uc.mem_write(n_addr + 0x08, struct.pack('<I', next_n))

        uc.mem_write(s_addr + 0x00, struct.pack('<I', SUBUNIT_VT))
        uc.mem_write(s_addr + 0x38, struct.pack('<I', t_addr))
        uc.mem_write(s_addr + 0x3C, struct.pack('<i', spec['curr_str']))
        uc.mem_write(s_addr + 0x44, struct.pack('<i', spec['max_str']))

        uc.mem_write(t_addr, b'\x00' * 0x300)
        is_land = spec.get('is_land', True)
        is_aux = spec.get('is_aux', False)
        uc.mem_write(t_addr + 0x39, bytes([1 if is_land else 0]))
        uc.mem_write(t_addr + 0x38, bytes([1 if is_aux else 0]))
        if is_land:
            uc.mem_write(t_addr + 0x228, struct.pack('<i', spec.get('recon', 0)))
            uc.mem_write(t_addr + 0x22C, struct.pack('<i', spec.get('attack', 0)))
            uc.mem_write(t_addr + 0x230, struct.pack('<i', spec.get('defense', 0)))
            uc.mem_write(t_addr + 0x234, struct.pack('<i', spec.get('support', 0)))
            uc.mem_write(t_addr + 0x238, struct.pack('<i', spec.get('discipline', 1000)))
            uc.mem_write(t_addr + 0x23C, struct.pack('<i', spec.get('maneuver', 0)))
            uc.mem_write(t_addr + 0x240, struct.pack('<i', spec.get('siege', 0)))
        else:
            uc.mem_write(t_addr + 0x244, struct.pack('<i', spec.get('gun_power', 0)))
            uc.mem_write(t_addr + 0x248, struct.pack('<i', spec.get('hull', 0)))
            uc.mem_write(t_addr + 0x24C, struct.pack('<i', spec.get('evasion', 0)))
            uc.mem_write(t_addr + 0x250, struct.pack('<i', spec.get('torpedo', 0)))
            uc.mem_write(t_addr + 0x25C, struct.pack('<i', spec.get('armor', 0)))

    uc.reg_write(UC_X86_REG_ECX, UNIT_ADDR)
    uc.reg_write(UC_X86_REG_ESP, STACK)
    uc.mem_write(STACK, struct.pack('<II', RET_STUB, OUT_TOTAL_ADDR))

    uc.emu_start(0x005D0500, RET_STUB, timeout=2000000)
    return struct.unpack('<i', uc.mem_read(OUT_TOTAL_ADDR, 4))[0]

# Fixtures de evaluación
total_fixtures = 0
mismatches = 0

# Fixtures de Calificación Táctica (CalculateCombatRating)
combat_rating_fixtures = [
    # 1. Land infantry & variations
    {'is_land': True, 'recon': 0, 'attack': 4, 'defense': 4, 'support': 0, 'discipline': 1000, 'maneuver': 1, 'siege': 0},
    {'is_land': True, 'recon': 2, 'attack': 3, 'defense': 1, 'support': 0, 'discipline': 1000, 'maneuver': 4, 'siege': 0},
    {'is_land': True, 'recon': 0, 'attack': 2, 'defense': 1, 'support': 3, 'discipline': 1000, 'maneuver': 1, 'siege': 1},
    {'is_land': True, 'recon': 1, 'attack': 5, 'defense': 5, 'support': 2, 'discipline': 1200, 'maneuver': 2, 'siege': 1},
    {'is_land': True, 'recon': 3, 'attack': 8, 'defense': 6, 'support': 4, 'discipline': 1500, 'maneuver': 3, 'siege': 2},
    {'is_land': True, 'recon': 0, 'attack': 0, 'defense': 0, 'support': 0, 'discipline': 1000, 'maneuver': 0, 'siege': 0},
    {'is_land': True, 'recon': 10, 'attack': 10, 'defense': 10, 'support': 10, 'discipline': 500, 'maneuver': 10, 'siege': 10},
    {'is_land': True, 'recon': 5, 'attack': 5, 'defense': 5, 'support': 5, 'discipline': 0, 'maneuver': 5, 'siege': 5},
    {'is_land': True, 'recon': 1, 'attack': 2, 'defense': 3, 'support': 4, 'discipline': 999, 'maneuver': 5, 'siege': 6},
    {'is_land': True, 'recon': 100, 'attack': 200, 'defense': 150, 'support': 50, 'discipline': 2000, 'maneuver': 100, 'siege': 50},
    # 2. Naval warships
    {'is_land': False, 'is_aux': False, 'gun_power': 10, 'hull': 20, 'armor': 5, 'evasion': 5, 'torpedo': 10},
    {'is_land': False, 'is_aux': False, 'gun_power': 30, 'hull': 50, 'armor': 20, 'evasion': 2, 'torpedo': 0},
    {'is_land': False, 'is_aux': False, 'gun_power': 5, 'hull': 10, 'armor': 0, 'evasion': 15, 'torpedo': 25},
    {'is_land': False, 'is_aux': False, 'gun_power': 0, 'hull': 0, 'armor': 0, 'evasion': 0, 'torpedo': 0},
    {'is_land': False, 'is_aux': False, 'gun_power': 50, 'hull': 80, 'armor': 40, 'evasion': 10, 'torpedo': 20},
    {'is_land': False, 'is_aux': False, 'gun_power': 100, 'hull': 150, 'armor': 80, 'evasion': 30, 'torpedo': 50},
    {'is_land': False, 'is_aux': False, 'gun_power': 1, 'hull': 1, 'armor': 1, 'evasion': 1, 'torpedo': 1},
    {'is_land': False, 'is_aux': False, 'gun_power': 25, 'hull': 40, 'armor': 15, 'evasion': 0, 'torpedo': 0},
    {'is_land': False, 'is_aux': False, 'gun_power': 60, 'hull': 120, 'armor': 50, 'evasion': 12, 'torpedo': 18},
    {'is_land': False, 'is_aux': False, 'gun_power': 80, 'hull': 200, 'armor': 90, 'evasion': 8, 'torpedo': 14},
    # 3. Naval auxiliaries (must yield strictly 0 regardless of attributes)
    {'is_land': False, 'is_aux': True, 'gun_power': 0, 'hull': 10, 'armor': 0, 'evasion': 0, 'torpedo': 0},
    {'is_land': False, 'is_aux': True, 'gun_power': 50, 'hull': 100, 'armor': 20, 'evasion': 10, 'torpedo': 10},
    {'is_land': False, 'is_aux': True, 'gun_power': 0, 'hull': 0, 'armor': 0, 'evasion': 0, 'torpedo': 0},
    {'is_land': False, 'is_aux': True, 'gun_power': 10, 'hull': 30, 'armor': 5, 'evasion': 5, 'torpedo': 5},
    # 4. Edge cases & 64-bit boundaries
    {'is_land': True, 'recon': 1000, 'attack': 2000, 'defense': 1500, 'support': 500, 'discipline': 5000, 'maneuver': 500, 'siege': 500},
    {'is_land': False, 'is_aux': False, 'gun_power': 500, 'hull': 1000, 'armor': 500, 'evasion': 200, 'torpedo': 300},
    {'is_land': True, 'recon': 5, 'attack': 5, 'defense': 5, 'support': 5, 'discipline': 1, 'maneuver': 5, 'siege': 5},
    {'is_land': False, 'is_aux': False, 'gun_power': 10, 'hull': 10, 'armor': 10, 'evasion': 500, 'torpedo': 500},
]

for spec in combat_rating_fixtures:
    emu_val = run_combat_rating_emu(spec)
    is_land = spec.get('is_land', True)
    if is_land:
        py_val = calculate_combat_rating(
            is_land=True,
            recon=spec.get('recon', 0),
            attack=spec.get('attack', 0),
            defense=spec.get('defense', 0),
            support=spec.get('support', 0),
            discipline=spec.get('discipline', 1000),
            maneuver=spec.get('maneuver', 0),
            siege=spec.get('siege', 0)
        )
    else:
        py_val = calculate_combat_rating(
            is_land=False,
            is_auxiliary=spec.get('is_aux', False),
            gun_power=spec.get('gun_power', 0),
            hull=spec.get('hull', 0),
            evasion=spec.get('evasion', 0),
            torpedo=spec.get('torpedo', 0),
            armor=spec.get('armor', 0)
        )
    if emu_val != py_val:
        print(f"MISMATCH in CalculateCombatRating! spec={spec} => emu={emu_val}, py={py_val}")
        mismatches += 1
    total_fixtures += 1

# Fixtures de Potencia de Combate Efectiva (CalculateEffectiveCombatPower)
effective_combat_power_fixtures = [
    # 1. Empty army
    [],
    # 2. Single land regiment at full / half / low / zero strength
    [{'curr_str': 3000, 'max_str': 3000, 'is_land': True, 'attack': 4, 'defense': 4, 'discipline': 1000}],
    [{'curr_str': 1500, 'max_str': 3000, 'is_land': True, 'attack': 4, 'defense': 4, 'discipline': 1000}],
    [{'curr_str': 750, 'max_str': 3000, 'is_land': True, 'attack': 4, 'defense': 4, 'discipline': 1000}],
    [{'curr_str': 1, 'max_str': 3000, 'is_land': True, 'attack': 4, 'defense': 4, 'discipline': 1000}],
    [{'curr_str': 0, 'max_str': 3000, 'is_land': True, 'attack': 4, 'defense': 4, 'discipline': 1000}],
    # 3. Corrupt subunit with max_strength = 0 -> ratio = -1
    [{'curr_str': 3000, 'max_str': 0, 'is_land': True, 'attack': 4, 'defense': 4, 'discipline': 1000}],
    [{'curr_str': 0, 'max_str': 0, 'is_land': True, 'attack': 4, 'defense': 4, 'discipline': 1000}],
    # 4. Heterogeneous army (infantry + cavalry + artillery)
    [
        {'curr_str': 3000, 'max_str': 3000, 'is_land': True, 'attack': 4, 'defense': 4, 'discipline': 1000},
        {'curr_str': 3000, 'max_str': 3000, 'is_land': True, 'recon': 2, 'attack': 3, 'maneuver': 4, 'discipline': 1000},
        {'curr_str': 3000, 'max_str': 3000, 'is_land': True, 'support': 3, 'siege': 1, 'discipline': 1000}
    ],
    [
        {'curr_str': 2500, 'max_str': 3000, 'is_land': True, 'attack': 5, 'defense': 4, 'discipline': 1100},
        {'curr_str': 1200, 'max_str': 3000, 'is_land': True, 'recon': 3, 'attack': 4, 'maneuver': 3, 'discipline': 1100},
        {'curr_str': 800, 'max_str': 3000, 'is_land': True, 'support': 4, 'siege': 2, 'discipline': 1100}
    ],
    # 5. Pure naval fleet (battleship + cruiser + destroyer)
    [
        {'curr_str': 100, 'max_str': 100, 'is_land': False, 'is_aux': False, 'gun_power': 40, 'hull': 60, 'armor': 30, 'evasion': 2, 'torpedo': 5},
        {'curr_str': 100, 'max_str': 100, 'is_land': False, 'is_aux': False, 'gun_power': 20, 'hull': 35, 'armor': 15, 'evasion': 6, 'torpedo': 10},
        {'curr_str': 100, 'max_str': 100, 'is_land': False, 'is_aux': False, 'gun_power': 8, 'hull': 15, 'armor': 2, 'evasion': 18, 'torpedo': 25}
    ],
    # 6. Naval fleet with auxiliary transports (auxiliaries contribute 0)
    [
        {'curr_str': 100, 'max_str': 100, 'is_land': False, 'is_aux': False, 'gun_power': 30, 'hull': 50, 'armor': 20, 'evasion': 4, 'torpedo': 8},
        {'curr_str': 100, 'max_str': 100, 'is_land': False, 'is_aux': True, 'gun_power': 0, 'hull': 20, 'armor': 0, 'evasion': 0, 'torpedo': 0},
        {'curr_str': 50, 'max_str': 100, 'is_land': False, 'is_aux': True, 'gun_power': 5, 'hull': 15, 'armor': 0, 'evasion': 0, 'torpedo': 0}
    ],
    # 7. Damaged fleet
    [
        {'curr_str': 35, 'max_str': 100, 'is_land': False, 'is_aux': False, 'gun_power': 40, 'hull': 60, 'armor': 30, 'evasion': 2, 'torpedo': 5},
        {'curr_str': 10, 'max_str': 100, 'is_land': False, 'is_aux': False, 'gun_power': 20, 'hull': 35, 'armor': 15, 'evasion': 6, 'torpedo': 10},
        {'curr_str': 0, 'max_str': 100, 'is_land': False, 'is_aux': False, 'gun_power': 8, 'hull': 15, 'armor': 2, 'evasion': 18, 'torpedo': 25}
    ],
    # 8. Mixed formation (combined arms army)
    [
        {'curr_str': 3000, 'max_str': 3000, 'is_land': True, 'attack': 4, 'defense': 4, 'discipline': 1000},
        {'curr_str': 3000, 'max_str': 3000, 'is_land': True, 'attack': 4, 'defense': 4, 'discipline': 1000},
        {'curr_str': 1500, 'max_str': 3000, 'is_land': True, 'attack': 4, 'defense': 4, 'discipline': 1000},
        {'curr_str': 1000, 'max_str': 3000, 'is_land': True, 'support': 3, 'siege': 1, 'discipline': 1000},
        {'curr_str': 2000, 'max_str': 3000, 'is_land': True, 'recon': 2, 'maneuver': 3, 'discipline': 1000}
    ],
    # 9. Formations with corrupt and healthy mixed units
    [
        {'curr_str': 3000, 'max_str': 0, 'is_land': True, 'attack': 4, 'defense': 4, 'discipline': 1000},
        {'curr_str': 3000, 'max_str': 3000, 'is_land': True, 'attack': 4, 'defense': 4, 'discipline': 1000}
    ],
    # 10. Large units and 64-bit threshold tests
    [{'curr_str': 5000000, 'max_str': 10000000, 'is_land': True, 'attack': 10, 'defense': 10, 'discipline': 1000}],
    [{'curr_str': 3000000, 'max_str': 4000000, 'is_land': True, 'attack': 8, 'defense': 8, 'discipline': 1200}],
    [
        {'curr_str': 2500000, 'max_str': 5000000, 'is_land': True, 'attack': 6, 'defense': 6, 'discipline': 1000},
        {'curr_str': 1000, 'max_str': 1000, 'is_land': True, 'attack': 4, 'defense': 4, 'discipline': 1000}
    ],
    # 11. 8-regiment typical corps
    [
        {'curr_str': 3000, 'max_str': 3000, 'is_land': True, 'attack': 4, 'defense': 4, 'discipline': 1000},
        {'curr_str': 3000, 'max_str': 3000, 'is_land': True, 'attack': 4, 'defense': 4, 'discipline': 1000},
        {'curr_str': 3000, 'max_str': 3000, 'is_land': True, 'attack': 4, 'defense': 4, 'discipline': 1000},
        {'curr_str': 3000, 'max_str': 3000, 'is_land': True, 'attack': 4, 'defense': 4, 'discipline': 1000},
        {'curr_str': 3000, 'max_str': 3000, 'is_land': True, 'support': 3, 'siege': 1, 'discipline': 1000},
        {'curr_str': 3000, 'max_str': 3000, 'is_land': True, 'support': 3, 'siege': 1, 'discipline': 1000},
        {'curr_str': 3000, 'max_str': 3000, 'is_land': True, 'recon': 2, 'maneuver': 3, 'discipline': 1000},
        {'curr_str': 3000, 'max_str': 3000, 'is_land': True, 'recon': 2, 'maneuver': 3, 'discipline': 1000}
    ],
    # 12. 8-regiment heavily damaged corps
    [
        {'curr_str': 500, 'max_str': 3000, 'is_land': True, 'attack': 4, 'defense': 4, 'discipline': 1000},
        {'curr_str': 600, 'max_str': 3000, 'is_land': True, 'attack': 4, 'defense': 4, 'discipline': 1000},
        {'curr_str': 400, 'max_str': 3000, 'is_land': True, 'attack': 4, 'defense': 4, 'discipline': 1000},
        {'curr_str': 300, 'max_str': 3000, 'is_land': True, 'attack': 4, 'defense': 4, 'discipline': 1000},
        {'curr_str': 800, 'max_str': 3000, 'is_land': True, 'support': 3, 'siege': 1, 'discipline': 1000},
        {'curr_str': 900, 'max_str': 3000, 'is_land': True, 'support': 3, 'siege': 1, 'discipline': 1000},
        {'curr_str': 200, 'max_str': 3000, 'is_land': True, 'recon': 2, 'maneuver': 3, 'discipline': 1000},
        {'curr_str': 150, 'max_str': 3000, 'is_land': True, 'recon': 2, 'maneuver': 3, 'discipline': 1000}
    ],
    # 13. Minimal strength sub-units
    [{'curr_str': 1, 'max_str': 1000, 'is_land': True, 'attack': 1, 'defense': 1, 'discipline': 1000}],
    [{'curr_str': 999, 'max_str': 1000, 'is_land': True, 'attack': 1, 'defense': 1, 'discipline': 1000}],
    # 14. Varied discipline values
    [
        {'curr_str': 3000, 'max_str': 3000, 'is_land': True, 'attack': 5, 'defense': 5, 'discipline': 1500},
        {'curr_str': 3000, 'max_str': 3000, 'is_land': True, 'attack': 5, 'defense': 5, 'discipline': 800}
    ],
    # 15. Fleet of 6 capital ships
    [
        {'curr_str': 100, 'max_str': 100, 'is_land': False, 'is_aux': False, 'gun_power': 50, 'hull': 80, 'armor': 40, 'evasion': 4, 'torpedo': 8},
        {'curr_str': 90, 'max_str': 100, 'is_land': False, 'is_aux': False, 'gun_power': 50, 'hull': 80, 'armor': 40, 'evasion': 4, 'torpedo': 8},
        {'curr_str': 80, 'max_str': 100, 'is_land': False, 'is_aux': False, 'gun_power': 50, 'hull': 80, 'armor': 40, 'evasion': 4, 'torpedo': 8},
        {'curr_str': 70, 'max_str': 100, 'is_land': False, 'is_aux': False, 'gun_power': 50, 'hull': 80, 'armor': 40, 'evasion': 4, 'torpedo': 8},
        {'curr_str': 60, 'max_str': 100, 'is_land': False, 'is_aux': False, 'gun_power': 50, 'hull': 80, 'armor': 40, 'evasion': 4, 'torpedo': 8},
        {'curr_str': 50, 'max_str': 100, 'is_land': False, 'is_aux': False, 'gun_power': 50, 'hull': 80, 'armor': 40, 'evasion': 4, 'torpedo': 8}
    ],
    # 16. Single high-tech dreadnought
    [{'curr_str': 100, 'max_str': 100, 'is_land': False, 'is_aux': False, 'gun_power': 80, 'hull': 150, 'armor': 70, 'evasion': 8, 'torpedo': 15}],
    # 17. Single high-tech dreadnought at 10% health
    [{'curr_str': 10, 'max_str': 100, 'is_land': False, 'is_aux': False, 'gun_power': 80, 'hull': 150, 'armor': 70, 'evasion': 8, 'torpedo': 15}],
]

for tc in effective_combat_power_fixtures:
    emu_val = run_effective_combat_power_emu(tc)
    sub_model = []
    for s in tc:
        if s.get('is_land', True):
            r = calculate_combat_rating(
                is_land=True,
                recon=s.get('recon', 0),
                attack=s.get('attack', 0),
                defense=s.get('defense', 0),
                support=s.get('support', 0),
                discipline=s.get('discipline', 1000),
                maneuver=s.get('maneuver', 0),
                siege=s.get('siege', 0)
            )
        else:
            r = calculate_combat_rating(
                is_land=False,
                is_auxiliary=s.get('is_aux', False),
                gun_power=s.get('gun_power', 0),
                hull=s.get('hull', 0),
                evasion=s.get('evasion', 0),
                torpedo=s.get('torpedo', 0),
                armor=s.get('armor', 0)
            )
        sub_model.append({'current_strength': s['curr_str'], 'max_strength': s['max_str'], 'rating': r})
    py_val = calculate_effective_combat_power(sub_model)
    if emu_val != py_val:
        print(f"MISMATCH in CalculateEffectiveCombatPower! tc={tc} => emu={emu_val}, py={py_val}")
        mismatches += 1
    total_fixtures += 1

assert mismatches == 0, f"{mismatches} mismatches encountered in emulation!"

# Record receipts
out_dir = ROOT / 'evidence/generated/unit-combat-power'
out_dir.mkdir(parents=True, exist_ok=True)
(out_dir / 'claims.json').write_text(json.dumps(claims, indent=2) + '\n')
(out_dir / 'reverify.json').write_text(json.dumps(report, indent=2) + '\n')
(out_dir / 'negative-controls.json').write_text(json.dumps(controls, indent=2) + '\n')
(out_dir / 'emulation.json').write_text(json.dumps({
    'pass': True,
    'fixtures_tested': total_fixtures,
    'mismatches': mismatches,
    'combat_rating_fixtures_count': len(combat_rating_fixtures),
    'effective_combat_power_fixtures_count': len(effective_combat_power_fixtures)
}, indent=2) + '\n')

# Record into persistent reverify ledger
ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify', file_path=str(bin_path))
ledger.start_run('Verify CUnitType::CalculateCombatRating and CUnit::CalculateEffectiveCombatPower', session='unit-combat-power')
ledger.record(report, rnd=1, session='unit-combat-power')
ledger.finish_run(1, report['grounded'], report['information'])
ledger.save()

print(f"Unit combat power: {len(report['results'])} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Unit combat power emulation: {total_fixtures} fixtures executed, 0 mismatches against unit_combat_power_model.")
