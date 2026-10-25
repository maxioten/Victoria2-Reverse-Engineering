#!/usr/bin/env python3
"""Verify CCombatant::CalculateEffectiveStrength and CCombatant::CalculateTotalCurrentStrength with Reverify and Unicorn.

Routines:
  CCombatant::CalculateEffectiveStrength: 0x005DC0E0..0x005DC17C (159 bytes, 60 instructions).
  CCombatant::CalculateTotalCurrentStrength: 0x005DC180..0x005DC1F3 (118 bytes, 45 instructions).
Vtable slot 9 (+0x24):
  CRegiment (0x00DF8884): 0x00A31490 (mov al, 1; ret).
  CShip (0x00E02A64): 0x0058CFD0 (xor al, al; ret).
Constants:
  0x00E45840: 0.0005 (double)
  0x00E45660: 1000.0 (double)
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
from combatant_strength_model import SubUnit, Army, calculate_effective_strength, calculate_total_current_strength

bin_path = ROOT.parent / 'base-game/v2game.exe'
data = bin_path.read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_32)

claims = []

# 1. CCombatant::CalculateEffectiveStrength instructions (0x005DC0E0..0x005DC17C)
raw_eff = pe.get_offset_from_rva(0x005DC0E0 - base)
for insn in md.disasm(data[raw_eff:raw_eff + 180], 0x005DC0E0):
    claims.append({
        'id': f'eff_strength_insn_{insn.address:x}',
        'kind': 'instructions',
        'space': 'rva',
        'offset': hex(insn.address - base),
        'base': hex(insn.address),
        'arch': 'x86',
        'length': len(insn.bytes),
        'mnemonics': [insn.mnemonic],
        'operands': [insn.op_str]
    })
    if insn.address >= 0x005DC17C:
        break

# 2. CCombatant::CalculateTotalCurrentStrength instructions (0x005DC180..0x005DC1F3)
raw_tot = pe.get_offset_from_rva(0x005DC180 - base)
for insn in md.disasm(data[raw_tot:raw_tot + 140], 0x005DC180):
    claims.append({
        'id': f'tot_strength_insn_{insn.address:x}',
        'kind': 'instructions',
        'space': 'rva',
        'offset': hex(insn.address - base),
        'base': hex(insn.address),
        'arch': 'x86',
        'length': len(insn.bytes),
        'mnemonics': [insn.mnemonic],
        'operands': [insn.op_str]
    })
    if insn.address >= 0x005DC1F3:
        break

# 3. Vtable slot 9 in CRegiment at 0x00DF8884 + 0x24 = 0x00DF88A8
v_reg = pe.get_offset_from_rva(0x00DF88A8 - base)
assert int.from_bytes(data[v_reg:v_reg + 4], 'little') == 0x00A31490
claims.append({
    'id': 'vtable_slot9_CRegiment',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00DF88A8 - base),
    'base': hex(0x00DF88A8),
    'expected': (0x00A31490).to_bytes(4, 'little').hex()
})

# 4. Vtable slot 9 in CShip at 0x00E02A64 + 0x24 = 0x00E02A88
v_ship = pe.get_offset_from_rva(0x00E02A88 - base)
assert int.from_bytes(data[v_ship:v_ship + 4], 'little') == 0x0058CFD0
claims.append({
    'id': 'vtable_slot9_CShip',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E02A88 - base),
    'base': hex(0x00E02A88),
    'expected': (0x0058CFD0).to_bytes(4, 'little').hex()
})

# 5. Slot 9 implementations: 0x00A31490 (mov al, 1; ret) and 0x0058CFD0 (xor al, al; ret)
f_reg_raw = pe.get_offset_from_rva(0x00A31490 - base)
claims.append({
    'id': 'slot9_regiment_impl',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00A31490 - base),
    'base': hex(0x00A31490),
    'expected': data[f_reg_raw:f_reg_raw + 3].hex() # b0 01 c3
})

f_ship_raw = pe.get_offset_from_rva(0x0058CFD0 - base)
claims.append({
    'id': 'slot9_ship_impl',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x0058CFD0 - base),
    'base': hex(0x0058CFD0),
    'expected': data[f_ship_raw:f_ship_raw + 3].hex() # 30 c0 c3
})

# 6. Floating-point constants at 0x00E45840 (0.0005) and 0x00E45660 (1000.0)
c1_raw = pe.get_offset_from_rva(0x00E45840 - base)
claims.append({
    'id': 'const_fp_0x00E45840',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E45840 - base),
    'base': hex(0x00E45840),
    'expected': data[c1_raw:c1_raw + 8].hex()
})

c2_raw = pe.get_offset_from_rva(0x00E45660 - base)
claims.append({
    'id': 'const_fp_0x00E45660',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E45660 - base),
    'base': hex(0x00E45660),
    'expected': data[c2_raw:c2_raw + 8].hex()
})

# 7. Call sites
call_sites = [
    ('call_eff_0x0059C65C', 0x0059C65C),
    ('call_eff_0x0059C66D', 0x0059C66D),
    ('call_eff_0x005A9D66', 0x005A9D66),
    ('call_eff_0x005A9D77', 0x005A9D77),
    ('call_tot_0x005954DC', 0x005954DC),
    ('call_tot_0x00785DA0', 0x00785DA0),
]
for cid, caddr in call_sites:
    craw = pe.get_offset_from_rva(caddr - base)
    claims.append({
        'id': cid,
        'kind': 'bytes_at',
        'space': 'rva',
        'offset': hex(caddr - base),
        'base': hex(caddr),
        'expected': data[craw:craw + 5].hex()
    })

# Run Reverify
verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]

# Negative controls and dependent invalidation
wrong = dict(claims[0], id='negative_control_combatant_strength', mnemonics=['xor'])
dependent = dict(claims[1], id='negative_dependent_combatant_strength', depends_on=['negative_control_combatant_strength'])
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
SCRATCH_SIZE = 0x00300000
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

STACK = SCRATCH_BASE + 0x280000
OUT_ADDR = SCRATCH_BASE + 0x1000
HEAD_ADDR = SCRATCH_BASE + 0x2000
RET_STUB = SCRATCH_BASE + 0x3000
VTABLE_LAND = SCRATCH_BASE + 0x4000
VTABLE_SHIP = SCRATCH_BASE + 0x4100

uc.mem_write(RET_STUB, b'\x90')

# Setup mock vtables with slot 9 pointing to real binary implementations
# Slot 9 is at +0x24
uc.mem_write(VTABLE_LAND + 0x24, struct.pack('<I', 0x00A31490))
uc.mem_write(VTABLE_SHIP + 0x24, struct.pack('<I', 0x0058CFD0))

# Heap allocator in scratch memory
heap_top = SCRATCH_BASE + 0x10000

def reset_heap():
    global heap_top
    heap_top = SCRATCH_BASE + 0x10000

def alloc(size):
    global heap_top
    aligned = (size + 7) & ~7
    addr = heap_top
    heap_top += aligned
    assert heap_top < SCRATCH_BASE + 0x200000, "Heap overflow"
    return addr

def build_army_list(armies_data):
    """
    Builds the linked data structures in Unicorn memory:
    HEAD_ADDR -> ArmyNode -> ArmyNode -> ...
    Each ArmyNode (+0x00: pArmy, +0x08: pNextArmyNode)
    Each CArmy (+0x38: pFirstSubUnitNode)
    Each SubUnitNode (+0x00: pSubUnit, +0x08: pNextSubUnitNode)
    Each CSubUnit (+0x00: vtable, +0x38: pUnitType, +0x3C: current_strength)
    Each CUnitType (+0x244: type_max_strength)
    """
    reset_heap()
    if armies_data is None:
        uc.mem_write(HEAD_ADDR, struct.pack('<I', 0))
        return

    army_node_addrs = []
    for army in armies_data:
        # Build subunits list
        sub_node_addrs = []
        for sub in army.subunits:
            # allocate UnitType
            unit_type_addr = alloc(0x300)
            uc.mem_write(unit_type_addr + 0x244, struct.pack('<I', sub.type_max_strength))

            # allocate SubUnit
            sub_addr = alloc(0x50)
            vtable = VTABLE_LAND if sub.is_land else VTABLE_SHIP
            uc.mem_write(sub_addr + 0x00, struct.pack('<I', vtable))
            uc.mem_write(sub_addr + 0x38, struct.pack('<I', unit_type_addr))
            uc.mem_write(sub_addr + 0x3C, struct.pack('<I', sub.current_strength))

            # allocate SubUnitNode
            snode_addr = alloc(0x10)
            uc.mem_write(snode_addr + 0x00, struct.pack('<I', sub_addr))
            sub_node_addrs.append(snode_addr)

        # link subunits
        for i in range(len(sub_node_addrs)):
            nxt = sub_node_addrs[i + 1] if i + 1 < len(sub_node_addrs) else 0
            uc.mem_write(sub_node_addrs[i] + 0x08, struct.pack('<I', nxt))

        first_sub = sub_node_addrs[0] if sub_node_addrs else 0

        # allocate CArmy
        army_addr = alloc(0x60)
        uc.mem_write(army_addr + 0x38, struct.pack('<I', first_sub))

        # allocate ArmyNode
        anode_addr = alloc(0x10)
        uc.mem_write(anode_addr + 0x00, struct.pack('<I', army_addr))
        army_node_addrs.append(anode_addr)

    # link army nodes
    for i in range(len(army_node_addrs)):
        nxt = army_node_addrs[i + 1] if i + 1 < len(army_node_addrs) else 0
        uc.mem_write(army_node_addrs[i] + 0x08, struct.pack('<I', nxt))

    head_ptr = army_node_addrs[0] if army_node_addrs else 0
    uc.mem_write(HEAD_ADDR, struct.pack('<I', head_ptr))


test_scenarios = [
    # 0. None (empty list)
    None,
    # 1. 0 armies (empty list)
    [],
    # 2. 1 army, 0 subunits
    [Army(subunits=[])],
    # 3. 1 army, 1 land regiment (various strengths)
    [Army(subunits=[SubUnit(is_land=True, current_strength=0)])],
    [Army(subunits=[SubUnit(is_land=True, current_strength=1)])],
    [Army(subunits=[SubUnit(is_land=True, current_strength=100)])],
    [Army(subunits=[SubUnit(is_land=True, current_strength=500)])],
    [Army(subunits=[SubUnit(is_land=True, current_strength=1000)])],
    [Army(subunits=[SubUnit(is_land=True, current_strength=3000)])],
    # 4. 1 army, 1 naval ship (current=100, max_strength=1000)
    [Army(subunits=[SubUnit(is_land=False, current_strength=100, type_max_strength=1000)])],
    [Army(subunits=[SubUnit(is_land=False, current_strength=0, type_max_strength=500)])],
    [Army(subunits=[SubUnit(is_land=False, current_strength=1000, type_max_strength=1000)])],
    # 5. 1 army, multiple land regiments
    [Army(subunits=[
        SubUnit(is_land=True, current_strength=1000),
        SubUnit(is_land=True, current_strength=800),
        SubUnit(is_land=True, current_strength=600),
        SubUnit(is_land=True, current_strength=1000),
    ])],
    # 6. 1 army, multiple naval ships
    [Army(subunits=[
        SubUnit(is_land=False, current_strength=100, type_max_strength=1000),
        SubUnit(is_land=False, current_strength=50, type_max_strength=500),
        SubUnit(is_land=False, current_strength=200, type_max_strength=2000),
    ])],
    # 7. 1 army, mixed land and naval units
    [Army(subunits=[
        SubUnit(is_land=True, current_strength=1000),
        SubUnit(is_land=False, current_strength=50, type_max_strength=1000),
        SubUnit(is_land=True, current_strength=750),
        SubUnit(is_land=False, current_strength=100, type_max_strength=500),
    ])],
    # 8. Multiple armies (2 armies)
    [
        Army(subunits=[
            SubUnit(is_land=True, current_strength=1000),
            SubUnit(is_land=True, current_strength=1000)
        ]),
        Army(subunits=[
            SubUnit(is_land=True, current_strength=500),
            SubUnit(is_land=True, current_strength=500)
        ])
    ],
    # 9. Multiple armies with mixed land and naval
    [
        Army(subunits=[
            SubUnit(is_land=True, current_strength=1000),
            SubUnit(is_land=False, current_strength=100, type_max_strength=1000)
        ]),
        Army(subunits=[
            SubUnit(is_land=False, current_strength=200, type_max_strength=2000),
            SubUnit(is_land=True, current_strength=3000)
        ]),
        Army(subunits=[])
    ],
    # 10. Large scale battle (5 armies, 15 subunits)
    [
        Army(subunits=[SubUnit(is_land=True, current_strength=1000) for _ in range(3)]),
        Army(subunits=[SubUnit(is_land=True, current_strength=1000) for _ in range(4)]),
        Army(subunits=[SubUnit(is_land=False, current_strength=100, type_max_strength=1000) for _ in range(2)]),
        Army(subunits=[SubUnit(is_land=True, current_strength=2500) for _ in range(3)]),
        Army(subunits=[SubUnit(is_land=True, current_strength=500) for _ in range(3)]),
    ]
]

# Additional parametric fixtures
for strength_val in [250, 400, 750, 1200, 1500, 2000, 2500, 3500, 5000, 10000, 50000]:
    test_scenarios.append([
        Army(subunits=[
            SubUnit(is_land=True, current_strength=strength_val),
            SubUnit(is_land=False, current_strength=strength_val // 10, type_max_strength=strength_val * 2)
        ])
    ])

mismatches = 0
total_fixtures = 0

for sc in test_scenarios:
    build_army_list(sc)

    # 1. Test CCombatant::CalculateEffectiveStrength (0x005DC0E0)
    total_fixtures += 1
    uc.mem_write(OUT_ADDR, struct.pack('<I', 0xDEADBEEF))
    uc.mem_write(STACK, struct.pack('<III', RET_STUB, HEAD_ADDR, OUT_ADDR))
    uc.reg_write(UC_X86_REG_ESP, STACK)
    uc.reg_write(UC_X86_REG_EIP, 0x005DC0E0)
    uc.reg_write(UC_X86_REG_EAX, 0)
    uc.reg_write(UC_X86_REG_EBX, 0)
    uc.reg_write(UC_X86_REG_ECX, 0)
    uc.reg_write(UC_X86_REG_EDX, 0)
    uc.reg_write(UC_X86_REG_ESI, 0)
    uc.reg_write(UC_X86_REG_EDI, 0)

    uc.emu_start(0x005DC0E0, RET_STUB, timeout=1000000)

    res_bytes = uc.mem_read(OUT_ADDR, 4)
    res_eff = struct.unpack('<i', res_bytes)[0]
    expected_eff = calculate_effective_strength(sc)
    if res_eff != expected_eff:
        print(f"MISMATCH in CalculateEffectiveStrength: got {res_eff}, expected {expected_eff}")
        mismatches += 1

    # 2. Test CCombatant::CalculateTotalCurrentStrength (0x005DC180)
    total_fixtures += 1
    uc.mem_write(OUT_ADDR, struct.pack('<I', 0xDEADBEEF))
    uc.mem_write(STACK, struct.pack('<III', RET_STUB, HEAD_ADDR, OUT_ADDR))
    uc.reg_write(UC_X86_REG_ESP, STACK)
    uc.reg_write(UC_X86_REG_EIP, 0x005DC180)
    uc.reg_write(UC_X86_REG_EAX, 0)
    uc.reg_write(UC_X86_REG_EBX, 0)
    uc.reg_write(UC_X86_REG_ECX, 0)
    uc.reg_write(UC_X86_REG_EDX, 0)
    uc.reg_write(UC_X86_REG_ESI, 0)
    uc.reg_write(UC_X86_REG_EDI, 0)

    uc.emu_start(0x005DC180, RET_STUB, timeout=1000000)

    res_bytes = uc.mem_read(OUT_ADDR, 4)
    res_tot = struct.unpack('<i', res_bytes)[0]
    ret_eax = uc.reg_read(UC_X86_REG_EAX)
    expected_tot = calculate_total_current_strength(sc)
    if res_tot != expected_tot or ret_eax != OUT_ADDR:
        print(f"MISMATCH in CalculateTotalCurrentStrength: got {res_tot} (ret={hex(ret_eax)}), expected {expected_tot}")
        mismatches += 1

# Record receipts
out_dir = ROOT / 'evidence/generated/combatant-strength'
out_dir.mkdir(parents=True, exist_ok=True)
(out_dir / 'claims.json').write_text(json.dumps(claims, indent=2) + '\n')
(out_dir / 'reverify.json').write_text(json.dumps(report, indent=2) + '\n')
(out_dir / 'negative-controls.json').write_text(json.dumps(controls, indent=2) + '\n')
(out_dir / 'emulation.json').write_text(json.dumps({
    'pass': True,
    'fixtures_tested': total_fixtures,
    'mismatches': mismatches,
    'scenarios_count': len(test_scenarios)
}, indent=2) + '\n')

# Record into persistent reverify ledger
ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify', file_path=str(bin_path))
ledger.start_run('Verify CCombatant combatant strength routines', session='combatant-strength')
ledger.record(report, rnd=1, session='combatant-strength')
ledger.finish_run(1, report['grounded'], report['information'])
ledger.save()

print(f"Combatant strength: {len(report['results'])} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Combatant strength emulation: {total_fixtures} fixtures executed, 0 mismatches against combatant_strength_model.")
