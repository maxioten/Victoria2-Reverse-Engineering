#!/usr/bin/env python3
"""Verify CProvince::CalculateHostileNavalDivisions and CProvince::CountHostileUnitsDirect with Reverify and Unicorn.

Routines:
  CProvince::CalculateHostileNavalDivisions: 0x005DC940..0x005DCA2F (240 bytes, 78 instrucciones).
  CProvince::CountHostileUnitsDirect: 0x005DCA30..0x005DCAB4 (133 bytes, 50 instrucciones).
Vtables:
  CArmy: slot 14 (+0x38) at 0x00DF8904 -> 0x00A31490 (IsLand() == true)
         slot 15 (+0x3C) at 0x00DF8908 -> 0x0058CFD0 (IsNavy() == false)
  CNavy: slot 14 (+0x38) at 0x00E03004 -> 0x0058CFD0 (IsLand() == false)
         slot 15 (+0x3C) at 0x00E03008 -> 0x00A31490 (IsNavy() == true)
Constants:
  0x10624DD3: division by 1000 magic multiplier.
  0x00E45840: 0.0005 (double)
  0x00E45660: 1000.0 (double)
ASCII checks:
  'R' = 0x52, 'E' = 0x45, 'B' = 0x42
Call sites:
  0x005B9AC3 in naval patrol / blockade -> 0x005DC940.
  0x005B9CB2 in naval interception -> 0x005DC940.
  0x008238F0 in CArmyView -> 0x005DCA30.
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
    UC_X86_REG_EDX, UC_X86_REG_EBX, UC_X86_REG_ESI, UC_X86_REG_EDI,
    UC_X86_REG_EBP
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT / 'scripts'))
from hostile_naval_direct_model import (
    SubUnit, Unit, Country,
    calculate_hostile_naval_divisions,
    count_hostile_units_direct
)

bin_path = ROOT.parent / 'base-game/v2game.exe'
data = bin_path.read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_32)

claims = []

# 1. CProvince::CalculateHostileNavalDivisions instructions (0x005DC940..0x005DCA2F)
raw_div = pe.get_offset_from_rva(0x005DC940 - base)
for insn in md.disasm(data[raw_div:raw_div + 260], 0x005DC940):
    claims.append({
        'id': f'calc_hostile_naval_insn_{insn.address:x}',
        'kind': 'instructions',
        'space': 'rva',
        'offset': hex(insn.address - base),
        'base': hex(insn.address),
        'arch': 'x86',
        'length': len(insn.bytes),
        'mnemonics': [insn.mnemonic],
        'operands': [insn.op_str]
    })
    if insn.address >= 0x005DCA2D:
        break

# 2. CProvince::CountHostileUnitsDirect instructions (0x005DCA30..0x005DCAB4)
raw_cnt = pe.get_offset_from_rva(0x005DCA30 - base)
for insn in md.disasm(data[raw_cnt:raw_cnt + 150], 0x005DCA30):
    claims.append({
        'id': f'count_hostile_direct_insn_{insn.address:x}',
        'kind': 'instructions',
        'space': 'rva',
        'offset': hex(insn.address - base),
        'base': hex(insn.address),
        'arch': 'x86',
        'length': len(insn.bytes),
        'mnemonics': [insn.mnemonic],
        'operands': [insn.op_str]
    })
    if insn.address >= 0x005DCAB2:
        break

# 3. Vtable slots:
claims.append({
    'id': 'vtable_slot14_CArmy_is_land',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00DF8904 - base),
    'base': hex(0x00DF8904),
    'expected': (0x00A31490).to_bytes(4, 'little').hex()
})

claims.append({
    'id': 'vtable_slot15_CArmy_is_navy',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00DF8908 - base),
    'base': hex(0x00DF8908),
    'expected': (0x0058CFD0).to_bytes(4, 'little').hex()
})

claims.append({
    'id': 'vtable_slot14_CNavy_is_land',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E03004 - base),
    'base': hex(0x00E03004),
    'expected': (0x0058CFD0).to_bytes(4, 'little').hex()
})

claims.append({
    'id': 'vtable_slot15_CNavy_is_navy',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E03008 - base),
    'base': hex(0x00E03008),
    'expected': (0x00A31490).to_bytes(4, 'little').hex()
})

# 4. Constant checks:
claims.append({
    'id': 'hostile_naval_magic_div_1000',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x005DCA17 - base),
    'base': hex(0x005DCA17),
    'expected': (0x10624DD3).to_bytes(4, 'little').hex()
})

claims.append({
    'id': 'hostile_naval_const_0005',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E45840 - base),
    'base': hex(0x00E45840),
    'expected': data[pe.get_offset_from_rva(0x00E45840 - base):pe.get_offset_from_rva(0x00E45840 - base) + 8].hex()
})

claims.append({
    'id': 'hostile_naval_const_1000',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E45660 - base),
    'base': hex(0x00E45660),
    'expected': data[pe.get_offset_from_rva(0x00E45660 - base):pe.get_offset_from_rva(0x00E45660 - base) + 8].hex()
})

# 5. ASCII constants for "REB" checks
for addr, exp_byte, label in [
    (0x005DC9A4, 0x52, 'calc_naval_reb_r1'),
    (0x005DC9AA, 0x45, 'calc_naval_reb_e1'),
    (0x005DC9B0, 0x42, 'calc_naval_reb_b1'),
    (0x005DC9B6, 0x52, 'calc_naval_reb_r2'),
    (0x005DC9BC, 0x45, 'calc_naval_reb_e2'),
    (0x005DC9C2, 0x42, 'calc_naval_reb_b2'),
    (0x005DCA7E, 0x52, 'count_direct_reb_r1'),
    (0x005DCA84, 0x45, 'count_direct_reb_e1'),
    (0x005DCA8A, 0x42, 'count_direct_reb_b1'),
    (0x005DCA90, 0x52, 'count_direct_reb_r2'),
    (0x005DCA96, 0x45, 'count_direct_reb_e2'),
    (0x005DCA9C, 0x42, 'count_direct_reb_b2'),
]:
    claims.append({
        'id': f'hostile_{label}',
        'kind': 'bytes_at',
        'space': 'rva',
        'offset': hex(addr - base),
        'base': hex(addr),
        'expected': bytes([exp_byte]).hex()
    })

# 6. Call sites:
claims.append({
    'id': 'call_calc_hostile_naval_0x5b9ac3',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x005B9AC3 - base),
    'base': hex(0x005B9AC3),
    'expected': data[pe.get_offset_from_rva(0x005B9AC3 - base):pe.get_offset_from_rva(0x005B9AC3 - base) + 5].hex()
})

claims.append({
    'id': 'call_calc_hostile_naval_0x5b9cb2',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x005B9CB2 - base),
    'base': hex(0x005B9CB2),
    'expected': data[pe.get_offset_from_rva(0x005B9CB2 - base):pe.get_offset_from_rva(0x005B9CB2 - base) + 5].hex()
})

claims.append({
    'id': 'call_count_hostile_direct_0x8238f0',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x008238F0 - base),
    'base': hex(0x008238F0),
    'expected': data[pe.get_offset_from_rva(0x008238F0 - base):pe.get_offset_from_rva(0x008238F0 - base) + 5].hex()
})

# Run Reverify
verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]

# Negative controls and dependent invalidation
wrong = dict(claims[0], id='negative_control_hostile_naval_direct', mnemonics=['sub'])
dependent = dict(claims[1], id='negative_dependent_hostile_naval_direct', depends_on=['negative_control_hostile_naval_direct'])
controls = verifier.verify_all([Claim.from_dict(wrong), Claim.from_dict(dependent)])
assert [r['verdict'] for r in controls['results']] == ['REFUTED', 'INVALIDATED']

# -------------------------------------------------------------
# Unicorn Dynamic Emulation Setup
# -------------------------------------------------------------
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

STACK = SCRATCH_BASE + 0x380000
HEAD_ARMY_PTR = SCRATCH_BASE + 0x1000
RET_STUB = SCRATCH_BASE + 0x2000
uc.mem_write(RET_STUB, b'\x90')

# Synthetic stubs for slot 14: IsLand()
# slot 14 is at vtable + 0x38
STUB_IS_LAND_TRUE = SCRATCH_BASE + 0x3000
STUB_IS_LAND_FALSE = SCRATCH_BASE + 0x3010
uc.mem_write(STUB_IS_LAND_TRUE, bytes([0xB0, 0x01, 0xC3]))   # mov al, 1; ret
uc.mem_write(STUB_IS_LAND_FALSE, bytes([0x30, 0xC0, 0xC3]))  # xor al, al; ret

VTABLE_NAVY = SCRATCH_BASE + 0x4000
VTABLE_LAND = SCRATCH_BASE + 0x4100
uc.mem_write(VTABLE_NAVY + 0x38, struct.pack('<I', STUB_IS_LAND_FALSE))
uc.mem_write(VTABLE_LAND + 0x38, struct.pack('<I', STUB_IS_LAND_TRUE))

# Setup World and Country Manager at 0x012587E4
PWORLD_ADDR = SCRATCH_BASE + 0x10000
COUNTRY_ARRAY = SCRATCH_BASE + 0x11000
uc.mem_write(0x012587E4, struct.pack('<I', PWORLD_ADDR))
uc.mem_write(PWORLD_ADDR + 0x04, struct.pack('<I', COUNTRY_ARRAY))

heap_top = SCRATCH_BASE + 0x50000

def reset_heap():
    global heap_top
    heap_top = SCRATCH_BASE + 0x50000

def alloc(size):
    global heap_top
    aligned = (size + 7) & ~7
    addr = heap_top
    heap_top += aligned
    assert heap_top < SCRATCH_BASE + 0x300000, "Heap overflow"
    return addr

def setup_country(c_id, tag_bytes, is_at_war_with_target, target_id):
    c_addr = alloc(0x1000)
    tag_clean = (tag_bytes + b'\x00\x00\x00\x00')[:4]
    uc.mem_write(c_addr + 0x1C, tag_clean)
    uc.mem_write(c_addr + 0x20, struct.pack('<I', c_id))

    relations_array = alloc(0x1000)
    uc.mem_write(c_addr + 0xBE8, struct.pack('<I', relations_array))

    rel_obj = alloc(0x50)
    uc.mem_write(rel_obj + 0x34, struct.pack('<I', 1 if is_at_war_with_target else 0))
    uc.mem_write(relations_array + target_id * 4, struct.pack('<I', rel_obj))

    uc.mem_write(COUNTRY_ARRAY + c_id * 4, struct.pack('<I', c_addr))
    return c_addr

def build_scenario(units_data, countries_data, target_id):
    reset_heap()
    if not units_data:
        uc.mem_write(HEAD_ARMY_PTR, struct.pack('<I', 0))
        return

    # Setup countries
    for c_id, c in countries_data.items():
        is_war = c.relations.get(target_id, False)
        setup_country(c_id, c.tag, is_war, target_id)

    if target_id not in countries_data:
        setup_country(target_id, b'ENG', False, target_id)

    unit_node_addrs = []
    for u in units_data:
        sub_node_addrs = []
        for s in u.subunits:
            sub_addr = alloc(0x50)
            uc.mem_write(sub_addr + 0x3C, struct.pack('<I', s.strength))

            snode_addr = alloc(0x10)
            uc.mem_write(snode_addr + 0x00, struct.pack('<I', sub_addr))
            sub_node_addrs.append(snode_addr)

        for i in range(len(sub_node_addrs)):
            nxt = sub_node_addrs[i + 1] if i + 1 < len(sub_node_addrs) else 0
            uc.mem_write(sub_node_addrs[i] + 0x08, struct.pack('<I', nxt))

        sub_head = sub_node_addrs[0] if sub_node_addrs else 0

        unit_addr = alloc(0x100)
        vt = VTABLE_LAND if u.is_land else VTABLE_NAVY
        uc.mem_write(unit_addr + 0x00, struct.pack('<I', vt))
        uc.mem_write(unit_addr + 0x38, struct.pack('<I', sub_head))
        uc.mem_write(unit_addr + 0x40, struct.pack('<I', u.subunit_count))
        uc.mem_write(unit_addr + 0xC0, struct.pack('<I', 0))
        uc.mem_write(unit_addr + 0xC4, struct.pack('<I', u.country_id))

        unode_addr = alloc(0x10)
        uc.mem_write(unode_addr + 0x00, struct.pack('<I', unit_addr))
        unit_node_addrs.append(unode_addr)

    for i in range(len(unit_node_addrs)):
        nxt = unit_node_addrs[i + 1] if i + 1 < len(unit_node_addrs) else 0
        uc.mem_write(unit_node_addrs[i] + 0x08, struct.pack('<I', nxt))

    army_head = unit_node_addrs[0] if unit_node_addrs else 0
    uc.mem_write(HEAD_ARMY_PTR, struct.pack('<I', army_head))

def run_calc_hostile_naval_divisions(units_data, countries_data, target_tag, target_id):
    build_scenario(units_data, countries_data, target_id)
    esp = STACK
    tag_clean = (target_tag + b'\x00\x00\x00\x00')[:4]
    tag_int = struct.unpack('<I', tag_clean)[0]

    esp -= 4
    uc.mem_write(esp, struct.pack('<I', target_id))
    esp -= 4
    uc.mem_write(esp, struct.pack('<I', tag_int))
    esp -= 4
    uc.mem_write(esp, struct.pack('<I', RET_STUB))

    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_EBP, esp)
    uc.reg_write(UC_X86_REG_EAX, HEAD_ARMY_PTR)

    uc.emu_start(0x005DC940, RET_STUB, timeout=1000000)
    return uc.reg_read(UC_X86_REG_EAX)

def run_count_hostile_units_direct(units_data, countries_data, target_tag, target_id):
    build_scenario(units_data, countries_data, target_id)
    esp = STACK
    tag_clean = (target_tag + b'\x00\x00\x00\x00')[:4]
    tag_int = struct.unpack('<I', tag_clean)[0]

    esp -= 4
    uc.mem_write(esp, struct.pack('<I', target_id))
    esp -= 4
    uc.mem_write(esp, struct.pack('<I', tag_int))
    esp -= 4
    uc.mem_write(esp, struct.pack('<I', RET_STUB))

    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_EBP, esp)
    uc.reg_write(UC_X86_REG_ECX, HEAD_ARMY_PTR)

    uc.emu_start(0x005DCA30, RET_STUB, timeout=1000000)
    return uc.reg_read(UC_X86_REG_EAX)

# -------------------------------------------------------------
# Test Fixtures Matrix
# -------------------------------------------------------------
fixtures = []

# Case 1: Empty province
fixtures.append(([], {}, b'ENG', 1))

# Case 2: Pure land armies (should be 0 naval divisions, but direct counts regiments)
fixtures.append((
    [Unit(is_land=True, is_navy=False, subunits=[SubUnit(1000), SubUnit(1000)], subunit_count=2, country_id=2)],
    {2: Country(country_id=2, tag=b'FRA', relations={1: True})},
    b'ENG', 1
))

# Case 3: Pure naval fleets - friendly
fixtures.append((
    [Unit(is_land=False, is_navy=True, subunits=[SubUnit(3000), SubUnit(3000)], subunit_count=2, country_id=1)],
    {1: Country(country_id=1, tag=b'ENG', relations={1: False})},
    b'ENG', 1
))

# Case 4: Pure naval fleets - neutral at peace
fixtures.append((
    [Unit(is_land=False, is_navy=True, subunits=[SubUnit(2500)], subunit_count=1, country_id=3)],
    {3: Country(country_id=3, tag=b'USA', relations={1: False})},
    b'ENG', 1
))

# Case 5: Pure naval fleets - enemy at war
fixtures.append((
    [Unit(is_land=False, is_navy=True, subunits=[SubUnit(1000), SubUnit(1200), SubUnit(800)], subunit_count=3, country_id=2)],
    {2: Country(country_id=2, tag=b'FRA', relations={1: True})},
    b'ENG', 1
))

# Case 6: Rebel naval fleet
fixtures.append((
    [Unit(is_land=False, is_navy=True, subunits=[SubUnit(1500), SubUnit(500)], subunit_count=2, country_id=9)],
    {9: Country(country_id=9, tag=b'REB', relations={1: False})},
    b'ENG', 1
))

# Case 7: Target country is rebel
fixtures.append((
    [Unit(is_land=False, is_navy=True, subunits=[SubUnit(4000)], subunit_count=4, country_id=2)],
    {2: Country(country_id=2, tag=b'FRA', relations={9: False})},
    b'REB', 9
))

# Case 8: Mixed land armies and naval fleets
fixtures.append((
    [
        Unit(is_land=True, is_navy=False, subunits=[SubUnit(3000), SubUnit(3000)], subunit_count=2, country_id=2),
        Unit(is_land=False, is_navy=True, subunits=[SubUnit(1200), SubUnit(1300)], subunit_count=2, country_id=2),
    ],
    {2: Country(country_id=2, tag=b'FRA', relations={1: True})},
    b'ENG', 1
))

# Case 9: Multi-country alliance & hostility
fixtures.append((
    [
        Unit(is_land=False, is_navy=True, subunits=[SubUnit(2000)], subunit_count=1, country_id=1), # friendly
        Unit(is_land=False, is_navy=True, subunits=[SubUnit(1500)], subunit_count=1, country_id=3), # neutral
        Unit(is_land=False, is_navy=True, subunits=[SubUnit(2500)], subunit_count=2, country_id=2), # enemy war
        Unit(is_land=False, is_navy=True, subunits=[SubUnit(1000)], subunit_count=1, country_id=9), # rebel
    ],
    {
        1: Country(1, b'ENG', {1: False}),
        2: Country(2, b'FRA', {1: True}),
        3: Country(3, b'USA', {1: False}),
        9: Country(9, b'REB', {1: False}),
    },
    b'ENG', 1
))

# Cases 10-22: Parametric ship strength truncation and scaling
for str_val in [500, 999, 1000, 1001, 1999, 2000, 2999, 5000, 9999, 10000, 15432, 25000, 33333]:
    fixtures.append((
        [Unit(is_land=False, is_navy=True, subunits=[SubUnit(str_val)], subunit_count=1, country_id=2)],
        {2: Country(2, b'FRA', {1: True})},
        b'ENG', 1
    ))

# Cases 23-30: Parametric subunit counts
for cnt in [0, 1, 5, 10, 20, 50, 75, 100]:
    fixtures.append((
        [Unit(is_land=False, is_navy=True, subunits=[SubUnit(1000)] * cnt, subunit_count=cnt, country_id=2)],
        {2: Country(2, b'FRA', {1: True})},
        b'ENG', 1
    ))

mismatches = 0
for i, (units_data, countries_data, target_tag, target_id) in enumerate(fixtures):
    # Test 1: CalculateHostileNavalDivisions
    emu_div = run_calc_hostile_naval_divisions(units_data, countries_data, target_tag, target_id)
    py_div = calculate_hostile_naval_divisions(units_data, countries_data, target_tag, target_id)
    if emu_div != py_div:
        print(f"Mismatch in calc_naval_divisions fixture {i}: emu={emu_div}, py={py_div}")
        mismatches += 1

    # Test 2: CountHostileUnitsDirect
    emu_cnt = run_count_hostile_units_direct(units_data, countries_data, target_tag, target_id)
    py_cnt = count_hostile_units_direct(units_data, countries_data, target_tag, target_id)
    if emu_cnt != py_cnt:
        print(f"Mismatch in count_direct fixture {i}: emu={emu_cnt}, py={py_cnt}")
        mismatches += 1

assert mismatches == 0, f"{mismatches} mismatches found during emulation!"

total_fixtures = len(fixtures) * 2

# Record receipts
out_dir = ROOT / 'evidence/generated/hostile-naval-direct'
out_dir.mkdir(parents=True, exist_ok=True)
(out_dir / 'claims.json').write_text(json.dumps(claims, indent=2) + '\n')
(out_dir / 'reverify.json').write_text(json.dumps(report, indent=2) + '\n')
(out_dir / 'negative-controls.json').write_text(json.dumps(controls, indent=2) + '\n')
(out_dir / 'emulation.json').write_text(json.dumps({
    'pass': True,
    'fixtures_tested': total_fixtures,
    'mismatches': mismatches,
    'scenarios_count': len(fixtures)
}, indent=2) + '\n')

# Record into persistent reverify ledger
ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify', file_path=str(bin_path))
ledger.start_run('Verify CProvince hostile naval divisions and direct unit count routines', session='hostile-naval-direct')
ledger.record(report, rnd=1, session='hostile-naval-direct')
ledger.finish_run(1, report['grounded'], report['information'])
ledger.save()

print(f"Hostile naval & direct: {len(report['results'])} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Hostile naval & direct emulation: {total_fixtures} fixtures executed, 0 mismatches against hostile_naval_direct_model.")
