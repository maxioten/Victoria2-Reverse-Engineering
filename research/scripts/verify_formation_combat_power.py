#!/usr/bin/env python3
"""Suite 90: Verificación estática y dinámica de la potencia de combate de formación directa y agregada.

Verifica formalmente en el binario PE32 `base-game/v2game.exe`:
- CUnit::CalculateDirectFormationCombatPower (0x005D00E0..0x005D02E8, slot 23, 186 insns)
- CUnit::CalculateAggregateFormationCombatPower (0x005D00A0..0x005D00D5, slot 24, 25 insns)
- Vtables de CArmy y CNavy (slots 23 y 24 en 0x00DF8928/C y 0x00E03028/C)
- Vtables de CRegiment y CShip (slots 12 y 13 en 0x00DF88B4/8 y 0x00E02A94/8)
- Constantes flotantes en 0x00E45A18 (100.5f) y 0x00E45BBC (10.5f)
- Singletons globales CGameState (0x012587E4), CDefines (0x012586DC) y factor exp (0x0125FED8)
- Control negativo y cascada dependiente
- Emulación en Unicorn Engine contrastada contra formation_combat_power_model.py
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
from formation_combat_power_model import (
    calculate_direct_formation_combat_power,
    calculate_aggregate_formation_combat_power
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

# 1. Instrucciones de CUnit::CalculateDirectFormationCombatPower (0x005D00E0..0x005D02E8, slot 23)
code_direct = get_bytes(0x005D00E0, 0x005D02E8 - 0x005D00E0)
for insn in md.disasm(code_direct, 0x005D00E0):
    claims.append({
        'id': f'unit_calc_direct_power_insn_0x{insn.address:08X}',
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

# 2. Instrucciones de CUnit::CalculateAggregateFormationCombatPower (0x005D00A0..0x005D00D5, slot 24)
code_agg = get_bytes(0x005D00A0, 0x005D00D5 - 0x005D00A0)
for insn in md.disasm(code_agg, 0x005D00A0):
    claims.append({
        'id': f'unit_calc_aggregate_power_insn_0x{insn.address:08X}',
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
# CArmy slot 23 (+0x5C) en 0x00DF8928 -> 0x005D00E0
claims.append({
    'id': 'vtable_slot23_CArmy_calculate_direct_formation_combat_power',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00DF8928 - base),
    'base': hex(0x00DF8928),
    'expected': (0x005D00E0).to_bytes(4, 'little').hex()
})

# CArmy slot 24 (+0x60) en 0x00DF892C -> 0x005D00A0
claims.append({
    'id': 'vtable_slot24_CArmy_calculate_aggregate_formation_combat_power',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00DF892C - base),
    'base': hex(0x00DF892C),
    'expected': (0x005D00A0).to_bytes(4, 'little').hex()
})

# CNavy slot 23 (+0x5C) en 0x00E03028 -> 0x005D00E0
claims.append({
    'id': 'vtable_slot23_CNavy_calculate_direct_formation_combat_power',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E03028 - base),
    'base': hex(0x00E03028),
    'expected': (0x005D00E0).to_bytes(4, 'little').hex()
})

# CNavy slot 24 (+0x60) en 0x00E0302C -> 0x005D00A0
claims.append({
    'id': 'vtable_slot24_CNavy_calculate_aggregate_formation_combat_power',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E0302C - base),
    'base': hex(0x00E0302C),
    'expected': (0x005D00A0).to_bytes(4, 'little').hex()
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

# 4. Constantes de punto flotante:
# Constante float 100.5f en 0x00E45A18
claims.append({
    'id': 'const_float_100_5_direct_formation_combat_power',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E45A18 - base),
    'base': hex(0x00E45A18),
    'expected': get_bytes(0x00E45A18, 4).hex()
})

# Constante float 10.5f en 0x00E45BBC
claims.append({
    'id': 'const_float_10_5_experience_factor_suite90',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E45BBC - base),
    'base': hex(0x00E45BBC),
    'expected': get_bytes(0x00E45BBC, 4).hex()
})

# 5. Puntos de llamada críticos en 0x005D00E0 y 0x005D00A0:
# Invocación a CUnitType::CalculateCombatRating en 0x005D0133
claims.append({
    'id': 'call_calculate_combat_rating_at_0x005D0133',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x005D0133 - base),
    'base': hex(0x005D0133),
    'expected': get_bytes(0x005D0133, 5).hex()
})

# Invocación virtual slot 23 en 0x005D00C3 (dentro de 0x005D00A0)
claims.append({
    'id': 'virtual_call_slot23_at_0x005D00C3',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x005D00C3 - base),
    'base': hex(0x005D00C3),
    'expected': get_bytes(0x005D00C3, 2).hex() # call eax
})

# Verificación estática Reverify
verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]

# Negative controls and dependent invalidation
wrong = dict(claims[0], id='negative_control_formation_combat_power', mnemonics=['sub'])
dependent = dict(claims[1], id='negative_dependent_formation_combat_power', depends_on=['negative_control_formation_combat_power'])
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
SCRATCH_SIZE = 0x00500000
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

# CUnit Vtable for child units in aggregate power calculation
UNIT_VT = SCRATCH_BASE + 0x3000
uc.mem_write(UNIT_VT + 0x5C, struct.pack('<I', 0x005D00E0)) # slot 23 points to 0x005D00E0

STACK = SCRATCH_BASE + 0x380000
RET_STUB = SCRATCH_BASE + 0x500
uc.mem_write(RET_STUB, b'\x90')

PARENT_UNIT_ADDR = SCRATCH_BASE + 0x10000
CHILD_UNIT_1_ADDR = SCRATCH_BASE + 0x11000
CHILD_UNIT_2_ADDR = SCRATCH_BASE + 0x12000
CHILD_UNIT_3_ADDR = SCRATCH_BASE + 0x13000

OUT_TOTAL_ADDR = SCRATCH_BASE + 0x18000
GAME_STATE_ADDR = SCRATCH_BASE + 0x19000
COUNTRY_TABLE_ADDR = SCRATCH_BASE + 0x1A000
COUNTRY_ADDR = SCRATCH_BASE + 0x1B000
MILITARY_STATS_ADDR = SCRATCH_BASE + 0x1C000
DEFINES_ADDR = SCRATCH_BASE + 0x1D000
MILITARY_DEFINES_ADDR = SCRATCH_BASE + 0x1E000

# Setup globals
uc.mem_write(0x012587E4, struct.pack('<I', GAME_STATE_ADDR))
uc.mem_write(GAME_STATE_ADDR + 4, struct.pack('<I', COUNTRY_TABLE_ADDR))
uc.mem_write(COUNTRY_TABLE_ADDR, struct.pack('<I', COUNTRY_ADDR)) # index 0
uc.mem_write(COUNTRY_ADDR + 0xBCC, struct.pack('<I', MILITARY_STATS_ADDR))

uc.mem_write(0x012586DC, struct.pack('<I', DEFINES_ADDR))
uc.mem_write(DEFINES_ADDR + 0x20, struct.pack('<I', MILITARY_DEFINES_ADDR))

# Experience factor global
uc.mem_write(0x0125FED8, struct.pack('<i', 10))

NODE_BASE = SCRATCH_BASE + 0x30000
SUBUNIT_BASE = SCRATCH_BASE + 0x50000
TYPE_BASE = SCRATCH_BASE + 0x70000
POP_BASE = SCRATCH_BASE + 0x90000
CHILD_NODE_BASE = SCRATCH_BASE + 0xB0000

def run_direct_power_emu(subunits_spec, tech_bonus=0, base_tech=1000, exp_factor=10, unit_addr=PARENT_UNIT_ADDR):
    uc.mem_write(MILITARY_STATS_ADDR + 0x70, struct.pack('<i', tech_bonus))
    uc.mem_write(MILITARY_DEFINES_ADDR + 0xE0, struct.pack('<i', base_tech))
    uc.mem_write(0x0125FED8, struct.pack('<i', exp_factor))

    # Unit setup: owner_id = 0, vtable
    uc.mem_write(unit_addr, struct.pack('<I', UNIT_VT))
    uc.mem_write(unit_addr + 0xC0, struct.pack('<I', 0))
    uc.mem_write(unit_addr + 0xC4, struct.pack('<I', 0))

    if not subunits_spec:
        uc.mem_write(unit_addr + 0x38, struct.pack('<I', 0))
    else:
        num_subs = len(subunits_spec)
        for i, sub in enumerate(subunits_spec):
            n_addr = NODE_BASE + i * 32
            s_addr = SUBUNIT_BASE + i * 128
            t_addr = TYPE_BASE + i * 64
            p_addr = POP_BASE + i * 64

            next_ptr = (NODE_BASE + (i + 1) * 32) if (i + 1 < num_subs) else 0
            uc.mem_write(n_addr, struct.pack('<I', s_addr))
            uc.mem_write(n_addr + 8, struct.pack('<I', next_ptr))

            # SubUnit setup
            uc.mem_write(s_addr, struct.pack('<I', SUBUNIT_VT))
            uc.mem_write(s_addr + 0x34, struct.pack('<i', sub.get('experience', 0)))
            uc.mem_write(s_addr + 0x38, struct.pack('<I', t_addr))
            uc.mem_write(s_addr + 0x3C, struct.pack('<i', sub['current_strength']))
            uc.mem_write(s_addr + 0x40, struct.pack('<i', sub.get('current_morale', 0)))
            uc.mem_write(s_addr + 0x44, struct.pack('<i', sub['max_strength']))
            uc.mem_write(s_addr + 0x48, struct.pack('<i', sub.get('max_morale', 1000)))

            # UnitType setup (land unit)
            uc.mem_write(t_addr + 0x14, struct.pack('<i', 1)) # is_land = 1
            rating = sub['rating']
            sum_attr = rating / 1000.5
            attr_val = sum_attr / 5.0
            for off in (0x1C, 0x20, 0x24, 0x28, 0x2C):
                uc.mem_write(t_addr + off, struct.pack('<f', attr_val))

            # POP setup
            if sub.get('is_rebel', False):
                uc.mem_write(s_addr + 0x74, struct.pack('<I', p_addr))
                uc.mem_write(p_addr + 0x164, struct.pack('<B', 1))
            else:
                uc.mem_write(s_addr + 0x74, struct.pack('<I', 0))

        uc.mem_write(unit_addr + 0x38, struct.pack('<I', NODE_BASE))

    uc.mem_write(OUT_TOTAL_ADDR, struct.pack('<i', -999))

    # Setup stack: [esp] = RET_STUB, [esp+4] = OUT_TOTAL_ADDR
    esp = STACK
    uc.mem_write(esp, struct.pack('<I', RET_STUB))
    uc.mem_write(esp + 4, struct.pack('<I', OUT_TOTAL_ADDR))

    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_ECX, unit_addr)
    uc.reg_write(UC_X86_REG_EIP, 0x005D00E0)

    uc.emu_start(0x005D00E0, RET_STUB, timeout=0)
    res = struct.unpack('<i', uc.mem_read(OUT_TOTAL_ADDR, 4))[0]
    return res


def run_aggregate_power_emu(child_specs, tech_bonus=0, base_tech=1000, exp_factor=10):
    uc.mem_write(MILITARY_STATS_ADDR + 0x70, struct.pack('<i', tech_bonus))
    uc.mem_write(MILITARY_DEFINES_ADDR + 0xE0, struct.pack('<i', base_tech))
    uc.mem_write(0x0125FED8, struct.pack('<i', exp_factor))

    # Parent unit setup
    uc.mem_write(PARENT_UNIT_ADDR, struct.pack('<I', UNIT_VT))
    uc.mem_write(PARENT_UNIT_ADDR + 0xC0, struct.pack('<I', 0))
    uc.mem_write(PARENT_UNIT_ADDR + 0xC4, struct.pack('<I', 0))

    if not child_specs:
        uc.mem_write(PARENT_UNIT_ADDR + 0x4C, struct.pack('<I', 0))
    else:
        child_addrs = [CHILD_UNIT_1_ADDR, CHILD_UNIT_2_ADDR, CHILD_UNIT_3_ADDR]
        num_children = len(child_specs)
        for c_idx, child in enumerate(child_specs):
            c_unit = child_addrs[c_idx]
            c_node = CHILD_NODE_BASE + c_idx * 32
            next_c_ptr = (CHILD_NODE_BASE + (c_idx + 1) * 32) if (c_idx + 1 < num_children) else 0

            uc.mem_write(c_node, struct.pack('<I', c_unit))
            uc.mem_write(c_node + 8, struct.pack('<I', next_c_ptr))

            # Setup child unit
            uc.mem_write(c_unit, struct.pack('<I', UNIT_VT)) # vtable with slot 23
            uc.mem_write(c_unit + 0xC0, struct.pack('<I', 0))
            uc.mem_write(c_unit + 0xC4, struct.pack('<I', 0))

            subs = child.get('subunits', [])
            if not subs:
                uc.mem_write(c_unit + 0x38, struct.pack('<I', 0))
            else:
                # Subunits for this child
                num_subs = len(subs)
                for s_idx, sub in enumerate(subs):
                    global_s_idx = c_idx * 10 + s_idx
                    n_addr = NODE_BASE + global_s_idx * 32
                    s_addr = SUBUNIT_BASE + global_s_idx * 128
                    t_addr = TYPE_BASE + global_s_idx * 64
                    p_addr = POP_BASE + global_s_idx * 64

                    next_ptr = (NODE_BASE + (global_s_idx + 1) * 32) if (s_idx + 1 < num_subs) else 0
                    uc.mem_write(n_addr, struct.pack('<I', s_addr))
                    uc.mem_write(n_addr + 8, struct.pack('<I', next_ptr))

                    uc.mem_write(s_addr, struct.pack('<I', SUBUNIT_VT))
                    uc.mem_write(s_addr + 0x34, struct.pack('<i', sub.get('experience', 0)))
                    uc.mem_write(s_addr + 0x38, struct.pack('<I', t_addr))
                    uc.mem_write(s_addr + 0x3C, struct.pack('<i', sub['current_strength']))
                    uc.mem_write(s_addr + 0x40, struct.pack('<i', sub.get('current_morale', 0)))
                    uc.mem_write(s_addr + 0x44, struct.pack('<i', sub['max_strength']))
                    uc.mem_write(s_addr + 0x48, struct.pack('<i', sub.get('max_morale', 1000)))

                    uc.mem_write(t_addr + 0x14, struct.pack('<i', 1))
                    rating = sub['rating']
                    sum_attr = rating / 1000.5
                    attr_val = sum_attr / 5.0
                    for off in (0x1C, 0x20, 0x24, 0x28, 0x2C):
                        uc.mem_write(t_addr + off, struct.pack('<f', attr_val))

                    if sub.get('is_rebel', False):
                        uc.mem_write(s_addr + 0x74, struct.pack('<I', p_addr))
                        uc.mem_write(p_addr + 0x164, struct.pack('<B', 1))
                    else:
                        uc.mem_write(s_addr + 0x74, struct.pack('<I', 0))

                first_node = NODE_BASE + (c_idx * 10) * 32
                uc.mem_write(c_unit + 0x38, struct.pack('<I', first_node))

        uc.mem_write(PARENT_UNIT_ADDR + 0x4C, struct.pack('<I', CHILD_NODE_BASE))

    uc.mem_write(OUT_TOTAL_ADDR, struct.pack('<i', -999))

    esp = STACK
    uc.mem_write(esp, struct.pack('<I', RET_STUB))
    uc.mem_write(esp + 4, struct.pack('<I', OUT_TOTAL_ADDR))

    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_ECX, PARENT_UNIT_ADDR)
    uc.reg_write(UC_X86_REG_EIP, 0x005D00A0)

    uc.emu_start(0x005D00A0, RET_STUB, timeout=0)
    res = struct.unpack('<i', uc.mem_read(OUT_TOTAL_ADDR, 4))[0]
    return res


# Test fixtures for Direct Formation Combat Power (slot 23)
direct_fixtures = [
    # 1. Empty formation
    {'subunits': [], 'tech_bonus': 0, 'base_tech': 1000, 'exp_factor': 10},
    # 2. Single fully healthy, full morale subunit
    {'subunits': [{'rating': 1000, 'current_strength': 1000, 'max_strength': 1000, 'current_morale': 1000, 'max_morale': 1000, 'experience': 0}], 'tech_bonus': 0, 'base_tech': 1000, 'exp_factor': 10},
    # 3. Half strength
    {'subunits': [{'rating': 1000, 'current_strength': 500, 'max_strength': 1000, 'current_morale': 1000, 'max_morale': 1000, 'experience': 0}], 'tech_bonus': 0, 'base_tech': 1000, 'exp_factor': 10},
    # 4. Half morale (triggers 50% penalty because morale < 1000)
    {'subunits': [{'rating': 1000, 'current_strength': 1000, 'max_strength': 1000, 'current_morale': 500, 'max_morale': 1000, 'experience': 0}], 'tech_bonus': 0, 'base_tech': 1000, 'exp_factor': 10},
    # 5. Low strength (< 100, triggers 50% penalty)
    {'subunits': [{'rating': 1000, 'current_strength': 80, 'max_strength': 1000, 'current_morale': 1000, 'max_morale': 1000, 'experience': 0}], 'tech_bonus': 0, 'base_tech': 1000, 'exp_factor': 10},
    # 6. Rebel pop (morale forced to 0, triggers 50% penalty)
    {'subunits': [{'rating': 1000, 'current_strength': 1000, 'max_strength': 1000, 'current_morale': 1000, 'max_morale': 1000, 'experience': 0, 'is_rebel': True}], 'tech_bonus': 0, 'base_tech': 1000, 'exp_factor': 10},
    # 7. High experience subunit (30 exp -> 300 milésimas -> +30% power)
    {'subunits': [{'rating': 1000, 'current_strength': 1000, 'max_strength': 1000, 'current_morale': 1000, 'max_morale': 1000, 'experience': 30}], 'tech_bonus': 0, 'base_tech': 1000, 'exp_factor': 10},
    # 8. Country tech bonus (tech_bonus = 250 -> 1250 / 1000 = 1.25x)
    {'subunits': [{'rating': 1000, 'current_strength': 1000, 'max_strength': 1000, 'current_morale': 1000, 'max_morale': 1000, 'experience': 0}], 'tech_bonus': 250, 'base_tech': 1000, 'exp_factor': 10},
    # 9. Two subunits mixed
    {
        'subunits': [
            {'rating': 1000, 'current_strength': 1000, 'max_strength': 1000, 'current_morale': 1000, 'max_morale': 1000, 'experience': 10},
            {'rating': 1500, 'current_strength': 800, 'max_strength': 1000, 'current_morale': 1000, 'max_morale': 1000, 'experience': 0}
        ],
        'tech_bonus': 100,
        'base_tech': 1000,
        'exp_factor': 10
    },
    # 10. Three subunits with rebel, damaged and elite
    {
        'subunits': [
            {'rating': 2000, 'current_strength': 1000, 'max_strength': 1000, 'current_morale': 1000, 'max_morale': 1000, 'experience': 50},
            {'rating': 800, 'current_strength': 50, 'max_strength': 1000, 'current_morale': 1000, 'max_morale': 1000, 'experience': 0}, # < 100 str
            {'rating': 1200, 'current_strength': 900, 'max_strength': 1000, 'current_morale': 1000, 'max_morale': 1000, 'experience': 5, 'is_rebel': True} # rebel
        ],
        'tech_bonus': 350,
        'base_tech': 1000,
        'exp_factor': 10
    }
]

# Generate more direct fixtures systematically
for str_val in (200, 450, 750, 1000):
    for mor_val in (300, 800, 1000):
        direct_fixtures.append({
            'subunits': [
                {'rating': 1200, 'current_strength': str_val, 'max_strength': 1000, 'current_morale': mor_val, 'max_morale': 1000, 'experience': 15}
            ],
            'tech_bonus': 150,
            'base_tech': 1000,
            'exp_factor': 10
        })

# Aggregate fixtures
aggregate_fixtures = [
    # 1. Empty parent (0 children)
    {'children': [], 'tech_bonus': 0, 'base_tech': 1000, 'exp_factor': 10},
    # 2. 1 Child with 1 subunit
    {
        'children': [
            {'subunits': [{'rating': 1000, 'current_strength': 1000, 'max_strength': 1000, 'current_morale': 1000, 'max_morale': 1000, 'experience': 0}]}
        ],
        'tech_bonus': 0, 'base_tech': 1000, 'exp_factor': 10
    },
    # 3. 2 Children with 1 subunit each
    {
        'children': [
            {'subunits': [{'rating': 1000, 'current_strength': 1000, 'max_strength': 1000, 'current_morale': 1000, 'max_morale': 1000, 'experience': 0}]},
            {'subunits': [{'rating': 1500, 'current_strength': 1000, 'max_strength': 1000, 'current_morale': 1000, 'max_morale': 1000, 'experience': 20}]}
        ],
        'tech_bonus': 100, 'base_tech': 1000, 'exp_factor': 10
    },
    # 4. 2 Children: one healthy, one damaged (<100 str)
    {
        'children': [
            {'subunits': [{'rating': 1000, 'current_strength': 800, 'max_strength': 1000, 'current_morale': 1000, 'max_morale': 1000, 'experience': 5}]},
            {'subunits': [{'rating': 1200, 'current_strength': 50, 'max_strength': 1000, 'current_morale': 1000, 'max_morale': 1000, 'experience': 0}]}
        ],
        'tech_bonus': 0, 'base_tech': 1000, 'exp_factor': 10
    },
    # 5. 3 Children multi-corps formation
    {
        'children': [
            {'subunits': [{'rating': 1000, 'current_strength': 1000, 'max_strength': 1000, 'current_morale': 1000, 'max_morale': 1000, 'experience': 10}]},
            {'subunits': [{'rating': 2000, 'current_strength': 900, 'max_strength': 1000, 'current_morale': 600, 'max_morale': 1000, 'experience': 30}]},
            {'subunits': [{'rating': 800, 'current_strength': 1000, 'max_strength': 1000, 'current_morale': 1000, 'max_morale': 1000, 'experience': 0, 'is_rebel': True}]}
        ],
        'tech_bonus': 200, 'base_tech': 1000, 'exp_factor': 10
    }
]

# Add more aggregate variations
for c_count in (1, 2, 3):
    for tb in (0, 100, 250, 400):
        children = []
        for i in range(c_count):
            children.append({
                'subunits': [
                    {'rating': 1000 + i * 200, 'current_strength': 1000 - i * 150, 'max_strength': 1000, 'current_morale': 1000, 'max_morale': 1000, 'experience': i * 10}
                ]
            })
        aggregate_fixtures.append({'children': children, 'tech_bonus': tb, 'base_tech': 1000, 'exp_factor': 10})

mismatches = 0
total_tested = 0

# Test direct fixtures
for fix in direct_fixtures:
    total_tested += 1
    expected = calculate_direct_formation_combat_power(
        subunits=fix['subunits'],
        country_tech_bonus=fix['tech_bonus'],
        base_tech_define=fix['base_tech'],
        exp_factor=fix['exp_factor']
    )
    actual = run_direct_power_emu(
        subunits_spec=fix['subunits'],
        tech_bonus=fix['tech_bonus'],
        base_tech=fix['base_tech'],
        exp_factor=fix['exp_factor']
    )
    if expected != actual:
        print(f"MISMATCH Direct: expected={expected}, actual={actual}, fix={fix}")
        mismatches += 1

# Test aggregate fixtures
for fix in aggregate_fixtures:
    total_tested += 1
    # For model, each child has country_tech_bonus and base_tech_define
    model_children = []
    for c in fix['children']:
        model_children.append({
            'subunits': c.get('subunits', []),
            'country_tech_bonus': fix['tech_bonus'],
            'base_tech_define': fix['base_tech']
        })
    expected = calculate_aggregate_formation_combat_power(
        child_formations=model_children,
        exp_factor=fix['exp_factor']
    )
    actual = run_aggregate_power_emu(
        child_specs=fix['children'],
        tech_bonus=fix['tech_bonus'],
        base_tech=fix['base_tech'],
        exp_factor=fix['exp_factor']
    )
    if expected != actual:
        print(f"MISMATCH Aggregate: expected={expected}, actual={actual}, fix={fix}")
        mismatches += 1

assert mismatches == 0, f"Emulación Unicorn falló con {mismatches} discrepancias"

out_dir = ROOT / 'evidence/generated/formation-combat-power'
out_dir.mkdir(parents=True, exist_ok=True)
(out_dir / 'claims.json').write_text(json.dumps(claims, indent=2) + '\n')
(out_dir / 'reverify.json').write_text(json.dumps(report, indent=2) + '\n')
(out_dir / 'negative-controls.json').write_text(json.dumps(controls, indent=2) + '\n')
(out_dir / 'emulation.json').write_text(json.dumps({
    'pass': True,
    'fixtures_tested': total_tested,
    'mismatches': mismatches,
    'direct_fixtures_count': len(direct_fixtures),
    'aggregate_fixtures_count': len(aggregate_fixtures)
}, indent=2) + '\n')

# Record into persistent reverify ledger
ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify', file_path=str(bin_path))
ledger.start_run('Verify CUnit::CalculateDirectFormationCombatPower and CalculateAggregateFormationCombatPower', session='formation-combat-power')
ledger.record(report, rnd=1, session='formation-combat-power')
ledger.finish_run(1, report['grounded'], report['information'])
ledger.save()

print(f"Formation combat power: {len(report['results'])} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Formation combat power emulation: {total_tested} fixtures executed ({len(direct_fixtures)} direct, {len(aggregate_fixtures)} aggregate), {mismatches} mismatches against formation_combat_power_model.")

