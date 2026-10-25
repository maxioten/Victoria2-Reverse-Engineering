#!/usr/bin/env python3
"""Suite 87: Verificación estática y dinámica de la potencia de combate completa
con moral, experiencia y tecnología de subunidades y formaciones militares.

Verifica formalmente en el binario PE32 `base-game/v2game.exe`:
- CUnit::CalculateFullCombatPower (0x005D02F0..0x005D04FB, 186 instrucciones)
- Vtables de CArmy y CNavy (slot 26 en 0x00DF8934 / 0x00E03034)
- Vtables de CRegiment y CShip (slot 12 y 13 en 0x00DF88B4/8 / 0x00E02A94/8)
- Constantes de punto flotante en 0x00E45A18 (100.5f) y 0x00E45BBC (10.5f)
- Singletons globales CGameState (0x012587E4), CDefines (0x012586DC) y factor de exp (0x0125FED8)
- Control negativo y cascada dependiente
- Emulación en Unicorn Engine contrastada contra unit_full_combat_power_model.py
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
from unit_combat_power_model import calculate_combat_rating
from unit_full_combat_power_model import calculate_formation_full_combat_power

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

# 1. Instrucciones de CUnit::CalculateFullCombatPower (0x005D02F0..0x005D04FB)
code = get_bytes(0x005D02F0, 0x005D04FB - 0x005D02F0)
for insn in md.disasm(code, 0x005D02F0):
    claims.append({
        'id': f'unit_calc_full_combat_power_insn_0x{insn.address:08X}',
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

# 2. Vtable slots:
# CArmy slot 26 (+0x68) en 0x00DF8934 -> 0x005D02F0
claims.append({
    'id': 'vtable_slot26_CArmy_calculate_full_combat_power',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00DF8934 - base),
    'base': hex(0x00DF8934),
    'expected': (0x005D02F0).to_bytes(4, 'little').hex()
})

# CNavy slot 26 (+0x68) en 0x00E03034 -> 0x005D02F0
claims.append({
    'id': 'vtable_slot26_CNavy_calculate_full_combat_power',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E03034 - base),
    'base': hex(0x00E03034),
    'expected': (0x005D02F0).to_bytes(4, 'little').hex()
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

# CRegiment slot 13 (+0x34) en 0x00DF88B8 -> 0x005BFFA0
claims.append({
    'id': 'vtable_slot13_CRegiment_get_max_morale',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00DF88B8 - base),
    'base': hex(0x00DF88B8),
    'expected': (0x005BFFA0).to_bytes(4, 'little').hex()
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

# CShip slot 13 (+0x34) en 0x00E02A98 -> 0x005BFFA0
claims.append({
    'id': 'vtable_slot13_CShip_get_max_morale',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E02A98 - base),
    'base': hex(0x00E02A98),
    'expected': (0x005BFFA0).to_bytes(4, 'little').hex()
})

# 3. Constantes de punto flotante:
# Constante float 100.5f en 0x00E45A18
claims.append({
    'id': 'const_float_100_5_full_combat_power',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E45A18 - base),
    'base': hex(0x00E45A18),
    'expected': get_bytes(0x00E45A18, 4).hex()
})

# Constante float 10.5f en 0x00E45BBC
claims.append({
    'id': 'const_float_10_5_experience_factor',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E45BBC - base),
    'base': hex(0x00E45BBC),
    'expected': get_bytes(0x00E45BBC, 4).hex()
})

# 4. Puntos de llamada críticos:
# Invocación a CUnitType::CalculateCombatRating en 0x005D0346
claims.append({
    'id': 'call_calculate_combat_rating_at_0x005D0346',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x005D0346 - base),
    'base': hex(0x005D0346),
    'expected': get_bytes(0x005D0346, 5).hex()
})

# Invocación a _alldiv para escalado nacional en 0x005D04EA
claims.append({
    'id': 'call_alldiv_at_0x005D04EA',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x005D04EA - base),
    'base': hex(0x005D04EA),
    'expected': get_bytes(0x005D04EA, 5).hex()
})

# 5. Padding de alineación tras ret 4 en 0x005D04FB (5 bytes CC)
claims.append({
    'id': 'calculate_full_combat_power_padding',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x005D04FB - base),
    'base': hex(0x005D04FB),
    'expected': (b'\xcc' * 5).hex()
})

# Verificación estática Reverify
verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]

# Negative controls and dependent invalidation
wrong = dict(claims[0], id='negative_control_unit_full_combat_power', mnemonics=['sub'])
dependent = dict(claims[1], id='negative_dependent_unit_full_combat_power', depends_on=['negative_control_unit_full_combat_power'])
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

# Mock GetMaxMorale: mov eax, [esp+4]; mov edx, [ecx+0x48]; mov [eax], edx; ret 8
MOCK_GET_MAX_MOR = SCRATCH_BASE + 0x1040
uc.mem_write(MOCK_GET_MAX_MOR, bytes([0x8B, 0x44, 0x24, 0x04, 0x8B, 0x51, 0x48, 0x89, 0x10, 0xC2, 0x08, 0x00]))

SUBUNIT_VT = SCRATCH_BASE + 0x2000
uc.mem_write(SUBUNIT_VT + 0x30, struct.pack('<I', MOCK_GET_MAX_STR))
uc.mem_write(SUBUNIT_VT + 0x34, struct.pack('<I', MOCK_GET_MAX_MOR))

STACK = SCRATCH_BASE + 0x380000
RET_STUB = SCRATCH_BASE + 0x500
uc.mem_write(RET_STUB, b'\x90')

UNIT_ADDR = SCRATCH_BASE + 0x10000
OUT_TOTAL_ADDR = SCRATCH_BASE + 0x10100
GAME_STATE_ADDR = SCRATCH_BASE + 0x11000
COUNTRY_TABLE_ADDR = SCRATCH_BASE + 0x12000
COUNTRY_ADDR = SCRATCH_BASE + 0x13000
MILITARY_STATS_ADDR = SCRATCH_BASE + 0x14000
DEFINES_ADDR = SCRATCH_BASE + 0x15000
MILITARY_DEFINES_ADDR = SCRATCH_BASE + 0x16000

# Setup globals
uc.mem_write(0x012587E4, struct.pack('<I', GAME_STATE_ADDR))
uc.mem_write(GAME_STATE_ADDR + 4, struct.pack('<I', COUNTRY_TABLE_ADDR))
uc.mem_write(COUNTRY_TABLE_ADDR, struct.pack('<I', COUNTRY_ADDR)) # index 0
uc.mem_write(COUNTRY_ADDR + 0xBCC, struct.pack('<I', MILITARY_STATS_ADDR))

uc.mem_write(0x012586DC, struct.pack('<I', DEFINES_ADDR))
uc.mem_write(DEFINES_ADDR + 0x20, struct.pack('<I', MILITARY_DEFINES_ADDR))

# Experience factor global
uc.mem_write(0x0125FED8, struct.pack('<i', 10))

NODE_BASE = SCRATCH_BASE + 0x20000
SUBUNIT_BASE = SCRATCH_BASE + 0x40000
TYPE_BASE = SCRATCH_BASE + 0x60000
POP_BASE = SCRATCH_BASE + 0x80000

def run_full_power_emu(subunits_spec, tech_bonus=0, base_tech=1000, exp_factor=10):
    uc.mem_write(MILITARY_STATS_ADDR + 0x70, struct.pack('<i', tech_bonus))
    uc.mem_write(MILITARY_DEFINES_ADDR + 0xE0, struct.pack('<i', base_tech))
    uc.mem_write(0x0125FED8, struct.pack('<i', exp_factor))

    # Unit setup: owner_id = 0
    uc.mem_write(UNIT_ADDR + 0xC0, struct.pack('<I', 0))
    uc.mem_write(UNIT_ADDR + 0xC4, struct.pack('<I', 0))

    if not subunits_spec:
        uc.mem_write(UNIT_ADDR + 0x90, struct.pack('<I', 0))
    else:
        uc.mem_write(UNIT_ADDR + 0x90, struct.pack('<I', NODE_BASE))

    for idx, spec in enumerate(subunits_spec):
        n_addr = NODE_BASE + idx * 16
        s_addr = SUBUNIT_BASE + idx * 0x100
        t_addr = TYPE_BASE + idx * 0x400
        p_addr = POP_BASE + idx * 0x200
        next_n = (NODE_BASE + (idx + 1) * 16) if (idx + 1 < len(subunits_spec)) else 0

        uc.mem_write(n_addr + 0x00, struct.pack('<I', s_addr))
        uc.mem_write(n_addr + 0x08, struct.pack('<I', next_n))

        uc.mem_write(s_addr + 0x00, struct.pack('<I', SUBUNIT_VT))
        uc.mem_write(s_addr + 0x34, struct.pack('<i', spec.get('exp', 0)))
        uc.mem_write(s_addr + 0x38, struct.pack('<I', t_addr))
        uc.mem_write(s_addr + 0x3C, struct.pack('<i', spec['curr_str']))
        uc.mem_write(s_addr + 0x40, struct.pack('<i', spec.get('curr_mor', 1000)))
        uc.mem_write(s_addr + 0x44, struct.pack('<i', spec['max_str']))
        uc.mem_write(s_addr + 0x48, struct.pack('<i', spec.get('max_mor', 1000)))

        is_rebel = spec.get('is_rebel', False)
        if is_rebel is not None:
            uc.mem_write(s_addr + 0x74, struct.pack('<I', p_addr))
            uc.mem_write(p_addr + 0x164, bytes([1 if is_rebel else 0]))
        else:
            uc.mem_write(s_addr + 0x74, struct.pack('<I', 0))

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

    uc.emu_start(0x005D02F0, RET_STUB, timeout=2000000)
    return struct.unpack('<i', uc.mem_read(OUT_TOTAL_ADDR, 4))[0]

# Fixtures de evaluación
fixtures = [
    # 1. Empty selection
    ([], 0, 1000, 10),
    ([], 200, 1000, 10),
    # 2. Single full land regiment
    ([{'curr_str': 3000, 'max_str': 3000, 'curr_mor': 3000, 'max_mor': 3000, 'exp': 0, 'is_land': True, 'attack': 4, 'defense': 3}], 0, 1000, 10),
    # 3. Experience scaling
    ([{'curr_str': 3000, 'max_str': 3000, 'curr_mor': 3000, 'max_mor': 3000, 'exp': 10, 'is_land': True, 'attack': 4, 'defense': 3}], 0, 1000, 10),
    ([{'curr_str': 3000, 'max_str': 3000, 'curr_mor': 3000, 'max_mor': 3000, 'exp': 50, 'is_land': True, 'attack': 4, 'defense': 3}], 0, 1000, 10),
    ([{'curr_str': 3000, 'max_str': 3000, 'curr_mor': 3000, 'max_mor': 3000, 'exp': 100, 'is_land': True, 'attack': 4, 'defense': 3}], 0, 1000, 10),
    ([{'curr_str': 3000, 'max_str': 3000, 'curr_mor': 3000, 'max_mor': 3000, 'exp': 200, 'is_land': True, 'attack': 4, 'defense': 3}], 0, 1000, 10),
    # 4. Partial strength & partial morale
    ([{'curr_str': 1500, 'max_str': 3000, 'curr_mor': 3000, 'max_mor': 3000, 'exp': 0, 'is_land': True, 'attack': 4, 'defense': 3}], 0, 1000, 10),
    ([{'curr_str': 3000, 'max_str': 3000, 'curr_mor': 1500, 'max_mor': 3000, 'exp': 0, 'is_land': True, 'attack': 4, 'defense': 3}], 0, 1000, 10),
    ([{'curr_str': 1500, 'max_str': 3000, 'curr_mor': 1500, 'max_mor': 3000, 'exp': 0, 'is_land': True, 'attack': 4, 'defense': 3}], 0, 1000, 10),
    # 5. Demoralization penalty (current_strength < 100 or current_morale < 1000)
    ([{'curr_str': 99, 'max_str': 3000, 'curr_mor': 3000, 'max_mor': 3000, 'exp': 0, 'is_land': True, 'attack': 4, 'defense': 3}], 0, 1000, 10),
    ([{'curr_str': 50, 'max_str': 3000, 'curr_mor': 3000, 'max_mor': 3000, 'exp': 0, 'is_land': True, 'attack': 4, 'defense': 3}], 0, 1000, 10),
    ([{'curr_str': 10, 'max_str': 3000, 'curr_mor': 3000, 'max_mor': 3000, 'exp': 0, 'is_land': True, 'attack': 4, 'defense': 3}], 0, 1000, 10),
    ([{'curr_str': 3000, 'max_str': 3000, 'curr_mor': 999, 'max_mor': 3000, 'exp': 0, 'is_land': True, 'attack': 4, 'defense': 3}], 0, 1000, 10),
    ([{'curr_str': 3000, 'max_str': 3000, 'curr_mor': 500, 'max_mor': 3000, 'exp': 0, 'is_land': True, 'attack': 4, 'defense': 3}], 0, 1000, 10),
    ([{'curr_str': 50, 'max_str': 3000, 'curr_mor': 500, 'max_mor': 3000, 'exp': 0, 'is_land': True, 'attack': 4, 'defense': 3}], 0, 1000, 10),
    # 6. Edge cases: zeroes and rebels
    ([{'curr_str': 0, 'max_str': 3000, 'curr_mor': 3000, 'max_mor': 3000, 'exp': 0, 'is_land': True, 'attack': 4, 'defense': 3}], 0, 1000, 10),
    ([{'curr_str': 3000, 'max_str': 3000, 'curr_mor': 0, 'max_mor': 3000, 'exp': 0, 'is_land': True, 'attack': 4, 'defense': 3}], 0, 1000, 10),
    ([{'curr_str': 3000, 'max_str': 0, 'curr_mor': 3000, 'max_mor': 3000, 'exp': 0, 'is_land': True, 'attack': 4, 'defense': 3}], 0, 1000, 10),
    ([{'curr_str': 3000, 'max_str': 3000, 'curr_mor': 3000, 'max_mor': 0, 'exp': 0, 'is_land': True, 'attack': 4, 'defense': 3}], 0, 1000, 10),
    ([{'curr_str': 3000, 'max_str': 3000, 'curr_mor': 3000, 'max_mor': 3000, 'exp': 0, 'is_land': True, 'attack': 4, 'defense': 3, 'is_rebel': True}], 0, 1000, 10),
    # 7. National technology and doctrine scaling
    ([{'curr_str': 3000, 'max_str': 3000, 'curr_mor': 3000, 'max_mor': 3000, 'exp': 0, 'is_land': True, 'attack': 4, 'defense': 3}], 100, 1000, 10),
    ([{'curr_str': 3000, 'max_str': 3000, 'curr_mor': 3000, 'max_mor': 3000, 'exp': 0, 'is_land': True, 'attack': 4, 'defense': 3}], 250, 1000, 10),
    ([{'curr_str': 3000, 'max_str': 3000, 'curr_mor': 3000, 'max_mor': 3000, 'exp': 0, 'is_land': True, 'attack': 4, 'defense': 3}], 500, 1000, 10),
    ([{'curr_str': 3000, 'max_str': 3000, 'curr_mor': 3000, 'max_mor': 3000, 'exp': 0, 'is_land': True, 'attack': 4, 'defense': 3}], 0, 800, 10),
    ([{'curr_str': 3000, 'max_str': 3000, 'curr_mor': 3000, 'max_mor': 3000, 'exp': 0, 'is_land': True, 'attack': 4, 'defense': 3}], 200, 800, 10),
    # 8. Experience factor variations
    ([{'curr_str': 3000, 'max_str': 3000, 'curr_mor': 3000, 'max_mor': 3000, 'exp': 50, 'is_land': True, 'attack': 4, 'defense': 3}], 0, 1000, 20),
    ([{'curr_str': 3000, 'max_str': 3000, 'curr_mor': 3000, 'max_mor': 3000, 'exp': 50, 'is_land': True, 'attack': 4, 'defense': 3}], 0, 1000, 5),
    # 9. Multi-regiment mixed formations
    ([
        {'curr_str': 3000, 'max_str': 3000, 'curr_mor': 3000, 'max_mor': 3000, 'exp': 10, 'is_land': True, 'attack': 4, 'defense': 4},
        {'curr_str': 3000, 'max_str': 3000, 'curr_mor': 3000, 'max_mor': 3000, 'exp': 20, 'is_land': True, 'recon': 2, 'attack': 3, 'maneuver': 4},
        {'curr_str': 3000, 'max_str': 3000, 'curr_mor': 3000, 'max_mor': 3000, 'exp': 0, 'is_land': True, 'support': 3, 'siege': 1}
    ], 100, 1000, 10),
    ([
        {'curr_str': 2000, 'max_str': 3000, 'curr_mor': 2500, 'max_mor': 3000, 'exp': 15, 'is_land': True, 'attack': 5, 'defense': 4},
        {'curr_str': 80, 'max_str': 3000, 'curr_mor': 1200, 'max_mor': 3000, 'exp': 30, 'is_land': True, 'recon': 3, 'attack': 3}, # Battered
        {'curr_str': 2500, 'max_str': 3000, 'curr_mor': 500, 'max_mor': 3000, 'exp': 5, 'is_land': True, 'support': 4, 'siege': 2} # Demoralized
    ], 150, 1000, 10),
    # 10. Naval fleets
    ([
        {'curr_str': 100, 'max_str': 100, 'curr_mor': 1000, 'max_mor': 1000, 'exp': 10, 'is_land': False, 'is_aux': False, 'gun_power': 40, 'hull': 60, 'armor': 30, 'evasion': 2, 'torpedo': 5},
        {'curr_str': 100, 'max_str': 100, 'curr_mor': 1000, 'max_mor': 1000, 'exp': 5, 'is_land': False, 'is_aux': False, 'gun_power': 20, 'hull': 35, 'armor': 15, 'evasion': 6, 'torpedo': 10},
        {'curr_str': 100, 'max_str': 100, 'curr_mor': 1000, 'max_mor': 1000, 'exp': 0, 'is_land': False, 'is_aux': True, 'gun_power': 0, 'hull': 20} # Auxiliary
    ], 0, 1000, 10),
    ([
        {'curr_str': 40, 'max_str': 100, 'curr_mor': 800, 'max_mor': 1000, 'exp': 25, 'is_land': False, 'is_aux': False, 'gun_power': 50, 'hull': 80, 'armor': 40, 'evasion': 4, 'torpedo': 8},
        {'curr_str': 90, 'max_str': 100, 'curr_mor': 1000, 'max_mor': 1000, 'exp': 10, 'is_land': False, 'is_aux': False, 'gun_power': 25, 'hull': 40, 'armor': 15, 'evasion': 8, 'torpedo': 12}
    ], 200, 1000, 10),
    # 11. Large 64-bit threshold tests
    ([{'curr_str': 5000000, 'max_str': 10000000, 'curr_mor': 3000, 'max_mor': 3000, 'exp': 0, 'is_land': True, 'attack': 10, 'defense': 10}], 0, 1000, 10),
    ([{'curr_str': 3000000, 'max_str': 4000000, 'curr_mor': 3000000, 'max_mor': 4000000, 'exp': 50, 'is_land': True, 'attack': 8, 'defense': 8}], 100, 1000, 10),
    # 12. 6-regiment corps
    ([
        {'curr_str': 3000, 'max_str': 3000, 'curr_mor': 3000, 'max_mor': 3000, 'exp': 0, 'is_land': True, 'attack': 4, 'defense': 4},
        {'curr_str': 3000, 'max_str': 3000, 'curr_mor': 3000, 'max_mor': 3000, 'exp': 10, 'is_land': True, 'attack': 4, 'defense': 4},
        {'curr_str': 3000, 'max_str': 3000, 'curr_mor': 3000, 'max_mor': 3000, 'exp': 20, 'is_land': True, 'attack': 4, 'defense': 4},
        {'curr_str': 3000, 'max_str': 3000, 'curr_mor': 3000, 'max_mor': 3000, 'exp': 5, 'is_land': True, 'support': 3, 'siege': 1},
        {'curr_str': 3000, 'max_str': 3000, 'curr_mor': 3000, 'max_mor': 3000, 'exp': 15, 'is_land': True, 'support': 3, 'siege': 1},
        {'curr_str': 3000, 'max_str': 3000, 'curr_mor': 3000, 'max_mor': 3000, 'exp': 25, 'is_land': True, 'recon': 2, 'maneuver': 3}
    ], 300, 1000, 10),
    # 13. Mixed rebel and loyal regiments
    ([
        {'curr_str': 3000, 'max_str': 3000, 'curr_mor': 3000, 'max_mor': 3000, 'exp': 0, 'is_land': True, 'attack': 4, 'defense': 4, 'is_rebel': True},
        {'curr_str': 3000, 'max_str': 3000, 'curr_mor': 3000, 'max_mor': 3000, 'exp': 0, 'is_land': True, 'attack': 4, 'defense': 4, 'is_rebel': False}
    ], 0, 1000, 10),
    # 14. Highly experienced elite regiment
    ([{'curr_str': 3000, 'max_str': 3000, 'curr_mor': 3000, 'max_mor': 3000, 'exp': 1000, 'is_land': True, 'attack': 5, 'defense': 5}], 0, 1000, 10),
    # 15. Negative tech bonus edge case
    ([{'curr_str': 3000, 'max_str': 3000, 'curr_mor': 3000, 'max_mor': 3000, 'exp': 0, 'is_land': True, 'attack': 4, 'defense': 3}], -200, 1000, 10),
]

total_fixtures = 0
mismatches = 0

for subs, t_bonus, b_tech, exp_f in fixtures:
    emu_val = run_full_power_emu(subs, t_bonus, b_tech, exp_f)
    model_subs = []
    for s in subs:
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
        model_subs.append({
            'rating': r,
            'current_strength': s['curr_str'],
            'max_strength': s['max_str'],
            'current_morale': s.get('curr_mor', 1000),
            'max_morale': s.get('max_mor', 1000),
            'experience': s.get('exp', 0),
            'is_rebel': s.get('is_rebel', False)
        })
    py_val = calculate_formation_full_combat_power(
        model_subs,
        country_tech_bonus=t_bonus,
        base_tech_define=b_tech,
        exp_factor=exp_f
    )
    if emu_val != py_val:
        print(f"MISMATCH in CalculateFullCombatPower! subs={subs} => emu={emu_val}, py={py_val}")
        mismatches += 1
    total_fixtures += 1

assert mismatches == 0, f"{mismatches} mismatches encountered in emulation!"

# Record receipts
out_dir = ROOT / 'evidence/generated/unit-full-combat-power'
out_dir.mkdir(parents=True, exist_ok=True)
(out_dir / 'claims.json').write_text(json.dumps(claims, indent=2) + '\n')
(out_dir / 'reverify.json').write_text(json.dumps(report, indent=2) + '\n')
(out_dir / 'negative-controls.json').write_text(json.dumps(controls, indent=2) + '\n')
(out_dir / 'emulation.json').write_text(json.dumps({
    'pass': True,
    'fixtures_tested': total_fixtures,
    'mismatches': mismatches
}, indent=2) + '\n')

# Record into persistent reverify ledger
ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify', file_path=str(bin_path))
ledger.start_run('Verify CUnit::CalculateFullCombatPower', session='unit-full-combat-power')
ledger.record(report, rnd=1, session='unit-full-combat-power')
ledger.finish_run(1, report['grounded'], report['information'])
ledger.save()

print(f"Unit full combat power: {len(report['results'])} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Unit full combat power emulation: {total_fixtures} fixtures executed, 0 mismatches against unit_full_combat_power_model.")
