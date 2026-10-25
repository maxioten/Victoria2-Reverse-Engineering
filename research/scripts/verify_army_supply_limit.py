#!/usr/bin/env python3
"""Verify CArmy::CalculateSupplyLimit against PE32 binary with Reverify and Unicorn.

Routine: 0x005D63E0..0x005D6574 (404 bytes, 125 instructions).
Vtable: CArmy slot 30 at 0x00DF8944.
"""
import hashlib
import json
from pathlib import Path
import struct
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
import pefile
from reverify.verifier import Claim, Verifier
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_PROT_ALL
from unicorn.x86_const import (
    UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
    UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP,
    UC_X86_REG_EIP
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT / 'scripts'))
from army_supply_limit_model import army_supply_limit

bin_path = ROOT.parent / 'base-game/v2game.exe'
data = bin_path.read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_32)

routine_va = 0x005D63E0
routine_rva = routine_va - base
routine_raw = pe.get_offset_from_rva(routine_rva)
code = data[routine_raw:routine_raw + 420]

claims = []
disasm_insns = []
for insn in md.disasm(code, routine_va):
    disasm_insns.append(insn)
    claims.append({
        'id': f'army_supply_limit_insn_{insn.address:x}',
        'kind': 'instructions',
        'space': 'rva',
        'offset': hex(insn.address - base),
        'base': hex(insn.address),
        'arch': 'x86',
        'length': len(insn.bytes),
        'mnemonics': [insn.mnemonic],
        'operands': [insn.op_str]
    })
    if insn.address >= 0x005D6571:
        break

# Vtable pointer: CArmy slot 30 in 0x00DF8944
claims.append({
    'id': 'army_supply_limit_vt_slot30',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00DF8944 - base),
    'base': hex(0x00DF8944),
    'expected': struct.pack('<I', routine_va).hex()
})

# Run Reverify
verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]

# Negative controls and dependent invalidation
wrong = dict(claims[0], id='negative_control_army_supply_limit', mnemonics=['nop'])
dependent = dict(claims[1], id='negative_dependent_army_supply_limit', depends_on=['negative_control_army_supply_limit'])
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

uc.mem_map(0, 0x1000, UC_PROT_ALL)

heap_base = 0x02000000
uc.mem_map(heap_base, 0x200000, UC_PROT_ALL)

friendly_val_addr = heap_base + 0x10
hostile_val_addr = heap_base + 0x14
infra_val_addr = heap_base + 0x18
terrain_struct_addr = heap_base + 0x20

# Stubs for external calls (stdcall / ret 8)
stub_friendly = b'\x8b\x44\x24\x08\x8b\x15' + struct.pack('<I', friendly_val_addr) + b'\x89\x10\xc2\x08\x00'
uc.mem_write(0x005DC200, stub_friendly)

stub_hostile = b'\x8b\x44\x24\x08\x8b\x15' + struct.pack('<I', hostile_val_addr) + b'\x89\x10\xc2\x08\x00'
uc.mem_write(0x005DC2A0, stub_hostile)

stub_terrain = b'\xb8' + struct.pack('<I', terrain_struct_addr) + b'\xc2\x08\x00'
uc.mem_write(0x004B3C40, stub_terrain)

stub_infra = b'\xa1' + struct.pack('<I', infra_val_addr) + b'\xc2\x08\x00'
uc.mem_write(0x004B80B0, stub_infra)

army_obj = heap_base + 0x1000
province_obj = heap_base + 0x2000
province_sub = heap_base + 0x2100
country_table = heap_base + 0x3000
country_vec = heap_base + 0x3100
country_obj = heap_base + 0x4000
country_tech = heap_base + 0x4100
leader_obj = heap_base + 0x5000
leader_vtable = heap_base + 0x5100
leader_mod = heap_base + 0x5200
defines_ptr = heap_base + 0x6000
military_defines = heap_base + 0x6100

uc.mem_write(army_obj + 0xDC, province_obj.to_bytes(4, 'little'))
uc.mem_write(province_obj + 0x9C, province_sub.to_bytes(4, 'little'))

uc.mem_write(army_obj + 0xC0, country_table.to_bytes(4, 'little'))
uc.mem_write(0x012587E4, country_table.to_bytes(4, 'little'))
uc.mem_write(country_table + 4, country_vec.to_bytes(4, 'little'))
country_id = 1
uc.mem_write(country_vec + country_id * 4, country_obj.to_bytes(4, 'little'))
uc.mem_write(army_obj + 0xC4, country_id.to_bytes(4, 'little'))
uc.mem_write(country_obj + 0xBCC, country_tech.to_bytes(4, 'little'))

uc.mem_write(leader_obj, leader_vtable.to_bytes(4, 'little'))
uc.mem_write(leader_obj + 0x48, leader_mod.to_bytes(4, 'little'))

uc.mem_write(0x012586DC, defines_ptr.to_bytes(4, 'little'))
uc.mem_write(defines_ptr + 0x20, military_defines.to_bytes(4, 'little'))

stub_leader_trait_true = heap_base + 0x7000
stub_leader_trait_false = heap_base + 0x7010
uc.mem_write(stub_leader_trait_true, b'\xb0\x01\xc3')
uc.mem_write(stub_leader_trait_false, b'\x30\xc0\xc3')

out_buf = heap_base + 0x8000
stack_base = heap_base + 0x100000

def emu_army_supply_limit(
    is_retreat: bool,
    prov_controller: int,
    army_country: int,
    is_sieged: bool,
    is_combat: bool,
    friendly_base: int,
    hostile_base: int,
    leader_trait: bool | None,
    leader_bonus: int,
    tech_bonus: int,
    terrain_mod: int,
    infra_bonus: int,
    base_buffer: int,
    cap_raw: int,
    is_stationed: bool,
    def_bonus: int
) -> int:
    uc.mem_write(army_obj + 0x164, (1 if is_retreat else 0).to_bytes(1, 'little'))
    uc.mem_write(province_obj + 0x12C, prov_controller.to_bytes(4, 'little'))
    uc.mem_write(army_obj + 0xC4, army_country.to_bytes(4, 'little'))
    uc.mem_write(army_obj + 0x74, (1 if is_sieged else 0).to_bytes(4, 'little'))
    uc.mem_write(army_obj + 0x104, (1 if is_combat else 0).to_bytes(1, 'little'))

    uc.mem_write(friendly_val_addr, (friendly_base & 0xFFFFFFFF).to_bytes(4, 'little', signed=False))
    uc.mem_write(hostile_val_addr, (hostile_base & 0xFFFFFFFF).to_bytes(4, 'little', signed=False))

    # Leader: CNullLeader pattern (leader_obj always present)
    uc.mem_write(army_obj + 0xD8, leader_obj.to_bytes(4, 'little'))
    has_trait = bool(leader_trait)
    uc.mem_write(leader_vtable + 0x20, (stub_leader_trait_true if has_trait else stub_leader_trait_false).to_bytes(4, 'little'))
    uc.mem_write(leader_mod + 0x38, (leader_bonus & 0xFFFFFFFF).to_bytes(4, 'little', signed=False))

    uc.mem_write(country_tech + 0x20, (tech_bonus & 0xFFFFFFFF).to_bytes(4, 'little', signed=False))

    uc.mem_write(terrain_struct_addr, (terrain_mod & 0xFFFFFFFF).to_bytes(4, 'little', signed=False))
    uc.mem_write(infra_val_addr, (infra_bonus & 0xFFFFFFFF).to_bytes(4, 'little', signed=False))
    uc.mem_write(province_sub + 0x18, (cap_raw & 0xFFFFFFFF).to_bytes(4, 'little', signed=False))

    uc.mem_write(army_obj + 0x70, (1 if is_stationed else 0).to_bytes(4, 'little'))
    uc.mem_write(military_defines + 0xDC, (def_bonus & 0xFFFFFFFF).to_bytes(4, 'little', signed=False))

    uc.mem_write(out_buf, (0xDEADBEEF).to_bytes(4, 'little'))

    esp = stack_base + 0x80000
    esp -= 4
    uc.mem_write(esp, (0).to_bytes(4, 'little'))
    esp -= 4
    uc.mem_write(esp, out_buf.to_bytes(4, 'little'))
    esp -= 4
    uc.mem_write(esp, (0x005D6574).to_bytes(4, 'little'))

    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_EBP, esp + 12)
    uc.reg_write(UC_X86_REG_ECX, army_obj)

    uc.emu_start(0x005D63E0, 0x005D6574)
    return struct.unpack('<i', uc.mem_read(out_buf, 4))[0]

fixtures = [
    # (is_retreat, prov_controller, army_country, is_sieged, is_combat,
    #  friendly_base, hostile_base, leader_trait, leader_bonus, tech_bonus,
    #  terrain_mod, infra_bonus, base_buffer, cap_raw, is_stationed, def_bonus)

    # 1. Retreating unit (immediate zero)
    (True, 1, 1, False, False, 30000, 10000, True, 2000, 100, 0, 5, 0, 50000000, False, 0),
    (True, 2, 1, True, True, 15000, 5000, False, 0, 0, 1000000, 0, 0, 20000000, True, 5000),

    # 2. Friendly controlled territory, no siege/combat
    (False, 1, 1, False, False, 25000, 5000, True, 3000, 150, 0, 10, 0, 60000000, False, 0),
    (False, 1, 1, False, False, 35000, 7000, None, 0, 200, 500000, 20, 0, 80000000, True, 4000),

    # 3. Hostile territory (controller mismatch)
    (False, 2, 1, False, False, 30000, 8000, True, 1000, 50, 0, 0, 0, 40000000, False, 0),

    # 4. Under siege
    (False, 1, 1, True, False, 25000, 6000, False, 0, 0, 0, 5, 0, 30000000, False, 0),

    # 5. In combat
    (False, 1, 1, False, True, 25000, 6000, True, 2000, 100, 200000, 10, 0, 40000000, False, 0),

    # 6. Stationed with defines bonus
    (False, 1, 1, False, False, 20000, 5000, True, 2000, 100, 0, 15, 0, 60000000, True, 6000),

    # 7. Heavy terrain penalty clamped to zero
    (False, 1, 1, False, False, 5000, 1000, False, 0, 0, 20000000, 0, 0, 50000000, False, 0),

    # 8. High supply clamped to province cap
    (False, 1, 1, False, False, 50000, 20000, True, 10000, 500, 0, 50, 0, 15000000, False, 0),
]

# Systematic parametric combinations to reach >140 fixtures
for f_base in [10000, 25000, 40000]:
    for t_bonus in [0, 100, 300]:
        for cap in [20000000, 50000000]:
            for stat in [False, True]:
                fixtures.append((False, 1, 1, False, False, f_base, 5000, True, 2000, t_bonus, 0, 10, 0, cap, stat, 3000))
                fixtures.append((False, 2, 1, False, False, f_base, 6000, False, 0, t_bonus, 500000, 5, 0, cap, stat, 3000))
                fixtures.append((False, 1, 1, True, False, f_base, 4000, None, 0, t_bonus, 0, 0, 0, cap, stat, 0))
                fixtures.append((False, 1, 1, False, True, f_base, 7000, True, 1500, t_bonus, 1000000, 15, 0, cap, stat, 5000))

emu_results = []
mismatches = 0
for idx, fix in enumerate(fixtures):
    (is_ret, p_ctrl, a_cnt, is_sg, is_cb, fb, hb, l_tr, l_bon, t_bon, terr, inf, buf, cap, stat, db) = fix
    emu_val = emu_army_supply_limit(is_ret, p_ctrl, a_cnt, is_sg, is_cb, fb, hb, l_tr, l_bon, t_bon, terr, inf, buf, cap, stat, db)
    expected = army_supply_limit(is_ret, p_ctrl, a_cnt, is_sg, is_cb, fb, hb, bool(l_tr), l_bon, t_bon, terr, inf, buf, cap, stat, db)
    if emu_val != expected:
        mismatches += 1
        print(f'MISMATCH fixture {idx}: fix={fix}, emu={emu_val}, exp={expected}')
    emu_results.append({
        'fixture_idx': idx,
        'friendly_base': fb,
        'hostile_base': hb,
        'tech_bonus': t_bon,
        'province_cap_raw': cap,
        'is_stationed': stat,
        'emulated': emu_val,
        'expected': expected,
        'pass': emu_val == expected
    })

assert mismatches == 0, f'{mismatches} mismatches found during emulation!'

# Save receipts
out_dir = ROOT / 'evidence/generated/army-supply-limit'
out_dir.mkdir(parents=True, exist_ok=True)
(out_dir / 'claims.json').write_text(json.dumps(claims, indent=2) + '\n')
(out_dir / 'reverify.json').write_text(json.dumps(report, indent=2) + '\n')
(out_dir / 'negative-controls.json').write_text(json.dumps(controls, indent=2) + '\n')
(out_dir / 'emulation.json').write_text(json.dumps({
    'binary_sha256': digest,
    'routine_va': hex(routine_va),
    'fixtures_count': len(fixtures),
    'mismatches': mismatches,
    'results': emu_results
}, indent=2) + '\n')

print(f'Army supply limit: {len(report["results"])} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.')
print(f'Army supply limit emulation: {len(fixtures)} fixtures executed, {mismatches} mismatches against army_supply_limit_model.')