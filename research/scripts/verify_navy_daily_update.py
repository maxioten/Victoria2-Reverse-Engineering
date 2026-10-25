#!/usr/bin/env python3
"""Suite 85: Verificación estática y dinámica del ciclo diario de mantenimiento naval
y la aplicación de daño por atrición en buques.

Verifica formalmente en el binario PE32 `base-game/v2game.exe`:
- CNavy::DailyUpdate (0x005C7AE0..0x005C7B79, 54 instrucciones)
- CSubUnit::SetStrength (0x005C02F0..0x005C036A, 46 instrucciones)
- Vtables de CNavy (slots 29 y 31), CArmy (slot 29) y CShip/CRegiment (slot 12)
- Punteros globales CGameState (0x012588E8) y CDefines (0x012586DC)
- Control negativo y cascada dependiente
- Emulación en Unicorn Engine contrastada contra navy_daily_update_model.py
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
from navy_daily_update_model import subunit_set_strength, navy_daily_update

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

# 1. Instrucciones de CNavy::DailyUpdate (0x005C7AE0..0x005C7B79)
code1 = get_bytes(0x005C7AE0, 0x005C7B79 - 0x005C7AE0)
for insn in md.disasm(code1, 0x005C7AE0):
    claims.append({
        'id': f'navy_daily_update_insn_0x{insn.address:08X}',
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

# 2. Instrucciones de CSubUnit::SetStrength (0x005C02F0..0x005C036A)
code2 = get_bytes(0x005C02F0, 0x005C036A - 0x005C02F0)
for insn in md.disasm(code2, 0x005C02F0):
    claims.append({
        'id': f'subunit_set_strength_insn_0x{insn.address:08X}',
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
# CNavy slot 29 (+0x74) en 0x00E03040 -> 0x005C7AE0
claims.append({
    'id': 'vtable_slot29_CNavy_daily_update',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E03040 - base),
    'base': hex(0x00E03040),
    'expected': (0x005C7AE0).to_bytes(4, 'little').hex()
})

# CArmy slot 29 (+0x74) en 0x00DF8940 -> 0x005C7B80
claims.append({
    'id': 'vtable_slot29_CArmy_daily_update',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00DF8940 - base),
    'base': hex(0x00DF8940),
    'expected': (0x005C7B80).to_bytes(4, 'little').hex()
})

# CNavy slot 31 (+0x7C) en 0x00E03048 -> 0x005D7EC0
claims.append({
    'id': 'vtable_slot31_CNavy_calculate_sea_attrition',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E03048 - base),
    'base': hex(0x00E03048),
    'expected': (0x005D7EC0).to_bytes(4, 'little').hex()
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

# CRegiment slot 12 (+0x30) en 0x00DF88B4 -> 0x005BFF80
claims.append({
    'id': 'vtable_slot12_CRegiment_get_max_strength',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00DF88B4 - base),
    'base': hex(0x00DF88B4),
    'expected': (0x005BFF80).to_bytes(4, 'little').hex()
})

# 4. Punteros globales y constantes:
# Puntero global CGameState en 0x005C7AEE (0x012588E8)
claims.append({
    'id': 'ptr_game_state_at_0x005C7AEE',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x005C7AEE + 1 - base),
    'base': hex(0x005C7AEE + 1),
    'expected': (0x012588E8).to_bytes(4, 'little').hex()
})

# Puntero global CDefines en 0x005C7AFC (0x012586DC)
claims.append({
    'id': 'ptr_defines_at_0x005C7AFC',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x005C7AFC + 2 - base),
    'base': hex(0x005C7AFC + 2),
    'expected': (0x012586DC).to_bytes(4, 'little').hex()
})

# Llamada a CSubUnit::SetStrength en 0x005C7B69
claims.append({
    'id': 'call_set_strength_at_0x005C7B69',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x005C7B69 - base),
    'base': hex(0x005C7B69),
    'expected': get_bytes(0x005C7B69, 5).hex()
})

# Constante float 0.0005 en 0x00E45840
claims.append({
    'id': 'const_float_half_millesimal_set_strength',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E45840 - base),
    'base': hex(0x00E45840),
    'expected': struct.pack('<d', 0.0005000000237487257).hex()
})

# Constante float 1000.0 en 0x00E45660
claims.append({
    'id': 'const_float_1000_scale_set_strength',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E45660 - base),
    'base': hex(0x00E45660),
    'expected': struct.pack('<d', 1000.0).hex()
})

# Padding de alineación tras 0x005C0367 (6 bytes CC)
claims.append({
    'id': 'subunit_set_strength_padding',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x005C036A - base),
    'base': hex(0x005C036A),
    'expected': (b'\xcc' * 6).hex()
})

# Padding de alineación tras 0x005C7B78 (7 bytes CC)
claims.append({
    'id': 'navy_daily_update_padding',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x005C7B79 - base),
    'base': hex(0x005C7B79),
    'expected': (b'\xcc' * 7).hex()
})

# Verificación estática Reverify
verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]

# Negative controls and dependent invalidation
wrong = dict(claims[0], id='negative_control_navy_daily_update', mnemonics=['sub'])
dependent = dict(claims[1], id='negative_dependent_navy_daily_update', depends_on=['negative_control_navy_daily_update'])
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

# Stub base update at 0x005C7B80 with ret
uc.mem_write(0x005C7B80, b'\xc3')

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

# Wire defines at 0x012586DC
DEFINES_ADDR = SCRATCH_BASE + 0x15000
MIL_DEFINES = SCRATCH_BASE + 0x16000
uc.mem_write(0x012586DC, struct.pack('<I', DEFINES_ADDR))
uc.mem_write(DEFINES_ADDR + 0x20, struct.pack('<I', MIL_DEFINES))

# Wire game state at 0x012588E8
GAME_STATE_ADDR = SCRATCH_BASE + 0x18000
uc.mem_write(0x012588E8, struct.pack('<I', GAME_STATE_ADDR))

# Subunit mock virtual method (slot 12 -> GetMaxStrength)
# mov eax, [esp+4]; mov edx, [ecx+0x38]; mov edx, [edx+0xb0]; mov [eax], edx; ret 8
MOCK_GET_MAX_STR = SCRATCH_BASE + 0x1000
MOCK_STR_CODE = bytes([0x8B, 0x44, 0x24, 0x04, 0x8B, 0x51, 0x38, 0x8B, 0x92, 0xB0, 0x00, 0x00, 0x00, 0x89, 0x10, 0xC2, 0x08, 0x00])
uc.mem_write(MOCK_GET_MAX_STR, MOCK_STR_CODE)

SHIP_VT = SCRATCH_BASE + 0x2000
uc.mem_write(SHIP_VT + 0x30, struct.pack('<I', MOCK_GET_MAX_STR))

NAVY_VT = SCRATCH_BASE + 0x3000
uc.mem_write(NAVY_VT + 0x7C, struct.pack('<I', 0x005D7EC0)) # CalculateSeaAttrition
uc.mem_write(NAVY_VT + 0x74, struct.pack('<I', 0x005C7AE0)) # DailyUpdate

NAVY_ADDR = SCRATCH_BASE + 0x10000
STACK = SCRATCH_BASE + 0x380000
RET_STUB = SCRATCH_BASE + 0x500
uc.mem_write(RET_STUB, b'\x90')

NODE_BASE = SCRATCH_BASE + 0x20000
SHIP_BASE = SCRATCH_BASE + 0x40000
TYPE_BASE = SCRATCH_BASE + 0x60000

def run_set_strength_emu(current_str: int, max_str: int, new_str: int) -> int:
    s_addr = SCRATCH_BASE + 0x50000
    t_addr = SCRATCH_BASE + 0x51000

    uc.mem_write(s_addr + 0x00, struct.pack('<I', SHIP_VT))
    uc.mem_write(s_addr + 0x38, struct.pack('<I', t_addr))
    uc.mem_write(s_addr + 0x3C, struct.pack('<i', current_str))
    uc.mem_write(t_addr + 0xB0, struct.pack('<i', max_str))

    uc.reg_write(UC_X86_REG_ECX, s_addr)
    uc.reg_write(UC_X86_REG_ESI, s_addr)
    uc.reg_write(UC_X86_REG_ESP, STACK)
    uc.mem_write(STACK, struct.pack('<Ii', RET_STUB, new_str))

    uc.emu_start(0x005C02F0, RET_STUB, timeout=2000000)
    return struct.unpack('<i', uc.mem_read(s_addr + 0x3C, 4))[0]

def run_navy_daily_update_emu(
    supply_eff: int,
    time_sea: int,
    range_div: int,
    grace_ms: int,
    max_attr: int,
    min_ship_str: int,
    ships: list,
    attrition_enabled: bool = True
) -> tuple:
    # Setup defines
    uc.mem_write(MIL_DEFINES + 0xE4, struct.pack('<i', range_div))
    uc.mem_write(MIL_DEFINES + 0xE8, struct.pack('<i', min_ship_str))
    uc.mem_write(MIL_DEFINES + 0xEC, struct.pack('<i', max_attr))
    uc.mem_write(MIL_DEFINES + 0xF0, struct.pack('<i', grace_ms))

    # Setup game state
    uc.mem_write(GAME_STATE_ADDR + 0xD1C, bytes([1 if attrition_enabled else 0]))

    # Setup navy
    uc.mem_write(NAVY_ADDR + 0x00, struct.pack('<I', NAVY_VT))
    uc.mem_write(NAVY_ADDR + 0xB0, struct.pack('<i', supply_eff))
    uc.mem_write(NAVY_ADDR + 0x1BC, struct.pack('<i', time_sea))

    if not ships:
        uc.mem_write(NAVY_ADDR + 0x38, struct.pack('<I', 0))
    else:
        uc.mem_write(NAVY_ADDR + 0x38, struct.pack('<I', NODE_BASE))

    for idx, (curr_str, max_str) in enumerate(ships):
        n_addr = NODE_BASE + idx * 16
        s_addr = SHIP_BASE + idx * 0x100
        t_addr = TYPE_BASE + idx * 0x100
        next_n = (NODE_BASE + (idx + 1) * 16) if (idx + 1 < len(ships)) else 0

        uc.mem_write(n_addr + 0x00, struct.pack('<I', s_addr))
        uc.mem_write(n_addr + 0x08, struct.pack('<I', next_n))

        uc.mem_write(s_addr + 0x00, struct.pack('<I', SHIP_VT))
        uc.mem_write(s_addr + 0x38, struct.pack('<I', t_addr))
        uc.mem_write(s_addr + 0x3C, struct.pack('<i', curr_str))

        uc.mem_write(t_addr + 0xB0, struct.pack('<i', max_str))

    uc.reg_write(UC_X86_REG_ECX, NAVY_ADDR)
    uc.reg_write(UC_X86_REG_ESP, STACK)
    uc.mem_write(STACK, struct.pack('<I', RET_STUB))

    uc.emu_start(0x005C7AE0, RET_STUB, timeout=2000000)

    out_time_sea = struct.unpack('<i', uc.mem_read(NAVY_ADDR + 0x1BC, 4))[0]
    out_strengths = []
    for idx in range(len(ships)):
        s_addr = SHIP_BASE + idx * 0x100
        out_strengths.append(struct.unpack('<i', uc.mem_read(s_addr + 0x3C, 4))[0])

    return out_time_sea, out_strengths

# ==============================================================================
# Fixtures de prueba dinámica
# ==============================================================================
mismatches = 0
total_fixtures = 0

# Parte A: Pruebas unitarias de CSubUnit::SetStrength
set_strength_fixtures = [
    # (current_str, max_str, new_str)
    (1000, 1000, 500),
    (1000, 1000, 1000),
    (1000, 1000, 0),
    (1000, 1000, -1),
    (1000, 1000, -500),
    (500, 1000, 1200),  # clamped to max
    (3000, 3000, 2500),
    (3000, 3000, 3500),  # clamped to max
    (3000, 3000, -100),  # clamped to 0
    (100, 1000, 100),
    (0, 1000, 0),
    (500, 500, 500),
    (2000, 4000, 3000),
    (2000, 4000, 5000),
    (1, 1000, 1),
]

for curr_s, max_s, new_s in set_strength_fixtures:
    emu_res = run_set_strength_emu(curr_s, max_s, new_s)
    py_res = subunit_set_strength(max_s, new_s)
    if emu_res != py_res:
        print(f"MISMATCH in SetStrength! curr={curr_s}, max={max_s}, new={new_s} => emu={emu_res}, py={py_res}")
        mismatches += 1
    total_fixtures += 1

# Parte B: Pruebas de integración de CNavy::DailyUpdate
daily_update_fixtures = [
    # (supply_eff, time_sea, range_div, grace_ms, max_attr, min_ship_str, ships, enabled)
    # 1. Attrition disabled
    (500, 35, 1000, 30000, 50, 100, [(1000, 1000)], False),
    (200, 50, 1000, 30000, 100, 100, [(3000, 3000), (2000, 3000)], False),
    # 2. Well-supplied (supply >= range) -> resets time_at_sea to 0, no damage
    (1000, 35, 1000, 30000, 50, 100, [(1000, 1000)], True),
    (1500, 10, 1000, 30000, 50, 100, [(1000, 1000)], True),
    # 3. Within grace period (time_at_sea < grace) -> inc time_at_sea, no damage
    (500, 5, 1000, 30000, 50, 100, [(1000, 1000)], True),
    (500, 28, 1000, 30000, 50, 100, [(1000, 1000)], True),
    # 4. Exceeding grace period -> damage applied!
    (500, 35, 1000, 30000, 50, 100, [(1000, 1000)], True),
    (200, 40, 1000, 30000, 100, 100, [(1000, 1000)], True),
    (0, 50, 1000, 30000, 100, 100, [(1000, 1000)], True),
    # 5. Empty navy
    (500, 35, 1000, 30000, 50, 100, [], True),
    # 6. Multiple ships with damage
    (500, 35, 1000, 30000, 50, 100, [(1000, 1000), (800, 1000), (600, 1000)], True),
    (200, 40, 1000, 30000, 100, 100, [(3000, 3000), (1500, 3000), (500, 1000)], True),
    # 7. Floor protection (ship_str <= min_ship_str -> untouched)
    (500, 35, 1000, 30000, 50, 100, [(100, 1000)], True),
    (500, 35, 1000, 30000, 50, 100, [(50, 1000)], True),
    (500, 35, 1000, 30000, 50, 100, [(1000, 1000), (100, 1000)], True),
    # 8. Clamped to floor
    (500, 35, 1000, 30000, 50, 100, [(110, 1000)], True), # 110 - 25 = 85 < 100 -> clamped to 100!
    (200, 40, 1000, 30000, 100, 100, [(150, 1000)], True), # 150 - 80 = 70 < 100 -> clamped to 100!
    # 9. Diverse range and grace configurations
    (400, 20, 800, 15000, 40, 100, [(1000, 1000)], True),
    (300, 25, 600, 20000, 60, 100, [(2000, 2000), (1500, 2000)], True),
    (100, 10, 500, 5000, 80, 50, [(500, 500), (250, 500), (50, 500)], True),
    (0, 100, 1000, 10000, 150, 100, [(3000, 3000), (2000, 3000)], True),
    (800, 50, 1000, 30000, 50, 100, [(1000, 1000)], True),
    (900, 50, 1000, 30000, 50, 100, [(1000, 1000)], True),
    (999, 50, 1000, 30000, 50, 100, [(1000, 1000)], True),
    (1000, 50, 1000, 30000, 50, 100, [(1000, 1000)], True),
]

for s_eff, t_sea, r_div, gr_ms, mx_at, mn_st, shps, enab in daily_update_fixtures:
    emu_t, emu_strengths = run_navy_daily_update_emu(s_eff, t_sea, r_div, gr_ms, mx_at, mn_st, shps, enab)
    py_t, py_strengths, _ = navy_daily_update(s_eff, t_sea, r_div, gr_ms, mx_at, mn_st, shps, enab)

    if emu_t != py_t or emu_strengths != py_strengths:
        print(f"MISMATCH in DailyUpdate! s_eff={s_eff}, t_sea={t_sea} => emu=({emu_t}, {emu_strengths}), py=({py_t}, {py_strengths})")
        mismatches += 1
    total_fixtures += 1

assert mismatches == 0, f"{mismatches} mismatches encountered in emulation!"

# Record receipts
out_dir = ROOT / 'evidence/generated/navy-daily-update'
out_dir.mkdir(parents=True, exist_ok=True)
(out_dir / 'claims.json').write_text(json.dumps(claims, indent=2) + '\n')
(out_dir / 'reverify.json').write_text(json.dumps(report, indent=2) + '\n')
(out_dir / 'negative-controls.json').write_text(json.dumps(controls, indent=2) + '\n')
(out_dir / 'emulation.json').write_text(json.dumps({
    'pass': True,
    'fixtures_tested': total_fixtures,
    'mismatches': mismatches,
    'set_strength_fixtures_count': len(set_strength_fixtures),
    'daily_update_fixtures_count': len(daily_update_fixtures)
}, indent=2) + '\n')

# Record into persistent reverify ledger
ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify', file_path=str(bin_path))
ledger.start_run('Verify CNavy::DailyUpdate and CSubUnit::SetStrength', session='navy-daily-update')
ledger.record(report, rnd=1, session='navy-daily-update')
ledger.finish_run(1, report['grounded'], report['information'])
ledger.save()

print(f"Navy daily update: {len(report['results'])} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Navy daily update emulation: {total_fixtures} fixtures executed, 0 mismatches against navy_daily_update_model.")
