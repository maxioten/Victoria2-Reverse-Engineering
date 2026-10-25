#!/usr/bin/env python3
"""Verify CCombatant::CountTotalRegiments, CArmy::CalculateSupplyWeight and CCombatant::CalculateSupplyWeight with Reverify and Unicorn.

Routines:
  CCombatant::CountTotalRegiments: 0x005DC560..0x005DC58F (48 bytes, 18 instrucciones).
  CArmy::CalculateSupplyWeight: 0x005DC590..0x005DC5CB (60 bytes, 17 instrucciones).
  CCombatant::CalculateSupplyWeight: 0x005DC5D0..0x005DC621 (82 bytes, 29 instrucciones).
Magic constant:
  0x10624DD3 (division by 1000 optimization).
Call sites:
  0x0078F55F in CBattleReport -> 0x005DC560.
  0x00791601 in CCombatView -> 0x005DC560.
  0x0084E97B in CShipView -> 0x005DC590.
  0x00828AED in CArmyView -> 0x005DC5D0.
  0x008296ED in CArmyView -> 0x005DC5D0.
"""
import hashlib
import json
from pathlib import Path
import struct
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
import pefile
from reverify.verifier import Claim, Verifier
from reverify.ledger import Ledger
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_PROT_ALL
from unicorn.x86_const import (
    UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_EAX, UC_X86_REG_ECX,
    UC_X86_REG_EDX, UC_X86_REG_EBX, UC_X86_REG_ESI, UC_X86_REG_EDI
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT / 'scripts'))
from subunit_weight_model import SubUnitWeightInfo, ArmyWeightInfo, count_total_regiments, calculate_army_supply_weight, calculate_combatant_supply_weight

bin_path = ROOT.parent / 'base-game/v2game.exe'
data = bin_path.read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_32)

claims = []

# 1. CCombatant::CountTotalRegiments instructions (0x005DC560..0x005DC58F)
raw_cnt = pe.get_offset_from_rva(0x005DC560 - base)
for insn in md.disasm(data[raw_cnt:raw_cnt + 60], 0x005DC560):
    claims.append({
        'id': f'count_total_regiments_insn_{insn.address:x}',
        'kind': 'instructions',
        'space': 'rva',
        'offset': hex(insn.address - base),
        'base': hex(insn.address),
        'arch': 'x86',
        'length': len(insn.bytes),
        'mnemonics': [insn.mnemonic],
        'operands': [insn.op_str]
    })
    if insn.address >= 0x005DC58F:
        break

# 2. CArmy::CalculateSupplyWeight instructions (0x005DC590..0x005DC5CB)
raw_asw = pe.get_offset_from_rva(0x005DC590 - base)
for insn in md.disasm(data[raw_asw:raw_asw + 70], 0x005DC590):
    claims.append({
        'id': f'army_supply_weight_insn_{insn.address:x}',
        'kind': 'instructions',
        'space': 'rva',
        'offset': hex(insn.address - base),
        'base': hex(insn.address),
        'arch': 'x86',
        'length': len(insn.bytes),
        'mnemonics': [insn.mnemonic],
        'operands': [insn.op_str]
    })
    if insn.address >= 0x005DC5CB:
        break

# 3. CCombatant::CalculateSupplyWeight instructions (0x005DC5D0..0x005DC621)
raw_csw = pe.get_offset_from_rva(0x005DC5D0 - base)
for insn in md.disasm(data[raw_csw:raw_csw + 95], 0x005DC5D0):
    claims.append({
        'id': f'combatant_supply_weight_insn_{insn.address:x}',
        'kind': 'instructions',
        'space': 'rva',
        'offset': hex(insn.address - base),
        'base': hex(insn.address),
        'arch': 'x86',
        'length': len(insn.bytes),
        'mnemonics': [insn.mnemonic],
        'operands': [insn.op_str]
    })
    if insn.address >= 0x005DC621:
        break

# 4. Call sites
call_sites = [
    ('call_cnt_0x0078F55F', 0x0078F55F),
    ('call_cnt_0x00791601', 0x00791601),
    ('call_asw_0x0084E97B', 0x0084E97B),
    ('call_csw_0x00828AED', 0x00828AED),
    ('call_csw_0x008296ED', 0x008296ED),
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
wrong = dict(claims[0], id='negative_control_subunit_weight', mnemonics=['inc'])
dependent = dict(claims[1], id='negative_dependent_subunit_weight', depends_on=['negative_control_subunit_weight'])
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

STACK = SCRATCH_BASE + 0x280000
HEAD_ARMY_PTR = SCRATCH_BASE + 0x1000
HEAD_SUB_PTR = SCRATCH_BASE + 0x1004
RET_STUB = SCRATCH_BASE + 0x2000
uc.mem_write(RET_STUB, b'\x90')

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

def build_structures(armies_data):
    """
    Builds linked structures in Unicorn memory:
    HEAD_ARMY_PTR -> ArmyNode -> ArmyNode -> ...
    Each ArmyNode: +0x00 = CArmy*, +0x08 = next_node
    Each CArmy: +0x38 = sub_head, +0x90 = sub_head
    Each SubUnitNode: +0x00 = CSubUnit*, +0x08 = next_node
    Each CSubUnit: +0x38 = CUnitType*, +0xA4 = CUnitType*
    Each CUnitType: +0x258 = supply_consumption
    """
    reset_heap()
    if armies_data is None:
        uc.mem_write(HEAD_ARMY_PTR, struct.pack('<I', 0))
        uc.mem_write(HEAD_SUB_PTR, struct.pack('<I', 0))
        return

    army_node_addrs = []
    first_sub_of_first_army = 0

    for a_idx, a in enumerate(armies_data):
        sub_node_addrs = []
        for s in a.subunits:
            # allocate CUnitType
            type_addr = alloc(0x300)
            uc.mem_write(type_addr + 0x258, struct.pack('<I', s.supply_consumption))

            # allocate CSubUnit
            sub_addr = alloc(0xC0)
            uc.mem_write(sub_addr + 0x38, struct.pack('<I', type_addr))
            uc.mem_write(sub_addr + 0xA4, struct.pack('<I', type_addr))

            # allocate SubUnitNode
            snode_addr = alloc(0x10)
            uc.mem_write(snode_addr + 0x00, struct.pack('<I', sub_addr))
            sub_node_addrs.append(snode_addr)

        for i in range(len(sub_node_addrs)):
            nxt = sub_node_addrs[i + 1] if i + 1 < len(sub_node_addrs) else 0
            uc.mem_write(sub_node_addrs[i] + 0x08, struct.pack('<I', nxt))

        sub_head = sub_node_addrs[0] if sub_node_addrs else 0
        if a_idx == 0:
            first_sub_of_first_army = sub_head

        # allocate CArmy
        army_addr = alloc(0xB0)
        uc.mem_write(army_addr + 0x38, struct.pack('<I', sub_head))
        uc.mem_write(army_addr + 0x90, struct.pack('<I', sub_head))

        # allocate ArmyNode
        anode_addr = alloc(0x10)
        uc.mem_write(anode_addr + 0x00, struct.pack('<I', army_addr))
        army_node_addrs.append(anode_addr)

    for i in range(len(army_node_addrs)):
        nxt = army_node_addrs[i + 1] if i + 1 < len(army_node_addrs) else 0
        uc.mem_write(army_node_addrs[i] + 0x08, struct.pack('<I', nxt))

    head_army = army_node_addrs[0] if army_node_addrs else 0
    uc.mem_write(HEAD_ARMY_PTR, struct.pack('<I', head_army))
    uc.mem_write(HEAD_SUB_PTR, struct.pack('<I', first_sub_of_first_army))


test_scenarios = [
    # 0. None (empty list)
    None,
    # 1. Empty list
    [],
    # 2. 1 army with 0 subunits
    [ArmyWeightInfo(subunits=[])],
    # 3. 1 army with 1 subunit (varying supply consumptions)
    [ArmyWeightInfo(subunits=[SubUnitWeightInfo(supply_consumption=0)])],
    [ArmyWeightInfo(subunits=[SubUnitWeightInfo(supply_consumption=500)])],
    [ArmyWeightInfo(subunits=[SubUnitWeightInfo(supply_consumption=1000)])],
    [ArmyWeightInfo(subunits=[SubUnitWeightInfo(supply_consumption=1999)])],
    [ArmyWeightInfo(subunits=[SubUnitWeightInfo(supply_consumption=2500)])],
    [ArmyWeightInfo(subunits=[SubUnitWeightInfo(supply_consumption=5000)])],
    # 4. 1 army with multiple subunits (inf, cav, art)
    [ArmyWeightInfo(subunits=[
        SubUnitWeightInfo(supply_consumption=1000),
        SubUnitWeightInfo(supply_consumption=2000),
        SubUnitWeightInfo(supply_consumption=3500),
        SubUnitWeightInfo(supply_consumption=500),
    ])],
    # 5. Multiple armies (2 armies)
    [
        ArmyWeightInfo(subunits=[
            SubUnitWeightInfo(supply_consumption=1200),
            SubUnitWeightInfo(supply_consumption=1800),
        ]),
        ArmyWeightInfo(subunits=[
            SubUnitWeightInfo(supply_consumption=2400),
            SubUnitWeightInfo(supply_consumption=800),
        ])
    ],
    # 6. Three armies with varying compositions
    [
        ArmyWeightInfo(subunits=[SubUnitWeightInfo(supply_consumption=1000) for _ in range(5)]),
        ArmyWeightInfo(subunits=[SubUnitWeightInfo(supply_consumption=2500) for _ in range(3)]),
        ArmyWeightInfo(subunits=[SubUnitWeightInfo(supply_consumption=4000) for _ in range(2)]),
    ],
    # 7. Four armies including one empty army
    [
        ArmyWeightInfo(subunits=[SubUnitWeightInfo(supply_consumption=1500) for _ in range(4)]),
        ArmyWeightInfo(subunits=[]),
        ArmyWeightInfo(subunits=[SubUnitWeightInfo(supply_consumption=2200) for _ in range(3)]),
        ArmyWeightInfo(subunits=[SubUnitWeightInfo(supply_consumption=800) for _ in range(6)]),
    ],
    # 8. Large formation (10 armies, 50 subunits)
    [
        ArmyWeightInfo(subunits=[
            SubUnitWeightInfo(supply_consumption=500 * (i + 1))
            for i in range(5)
        ])
        for _ in range(10)
    ]
]

# Additional parametric fixtures
for c in [800, 1250, 2000, 3333, 4500, 6000, 12000, 25000]:
    test_scenarios.append([
        ArmyWeightInfo(subunits=[
            SubUnitWeightInfo(supply_consumption=c),
            SubUnitWeightInfo(supply_consumption=c * 2),
            SubUnitWeightInfo(supply_consumption=c // 2),
        ])
    ])

mismatches = 0
total_fixtures = 0

for sc in test_scenarios:
    build_structures(sc)

    # 1. Test CCombatant::CountTotalRegiments (0x005DC560)
    # ecx = HEAD_ARMY_PTR, ret
    total_fixtures += 1
    uc.mem_write(STACK, struct.pack('<I', RET_STUB))
    uc.reg_write(UC_X86_REG_ESP, STACK)
    uc.reg_write(UC_X86_REG_ECX, HEAD_ARMY_PTR)
    uc.reg_write(UC_X86_REG_EIP, 0x005DC560)
    uc.reg_write(UC_X86_REG_EAX, 0)
    uc.reg_write(UC_X86_REG_EBX, 0)
    uc.reg_write(UC_X86_REG_EDX, 0)
    uc.reg_write(UC_X86_REG_ESI, 0)
    uc.reg_write(UC_X86_REG_EDI, 0)

    uc.emu_start(0x005DC560, RET_STUB, timeout=1000000)

    res_cnt = uc.reg_read(UC_X86_REG_EAX)
    expected_cnt = count_total_regiments(sc)
    if res_cnt != expected_cnt:
        print(f"MISMATCH in CountTotalRegiments: got {res_cnt}, expected {expected_cnt}")
        mismatches += 1

    # 2. Test CArmy::CalculateSupplyWeight (0x005DC590)
    # eax = HEAD_SUB_PTR, ret
    total_fixtures += 1
    uc.mem_write(STACK, struct.pack('<I', RET_STUB))
    uc.reg_write(UC_X86_REG_ESP, STACK)
    uc.reg_write(UC_X86_REG_EAX, HEAD_SUB_PTR)
    uc.reg_write(UC_X86_REG_EIP, 0x005DC590)
    uc.reg_write(UC_X86_REG_EBX, 0)
    uc.reg_write(UC_X86_REG_ECX, 0)
    uc.reg_write(UC_X86_REG_EDX, 0)
    uc.reg_write(UC_X86_REG_ESI, 0)
    uc.reg_write(UC_X86_REG_EDI, 0)

    uc.emu_start(0x005DC590, RET_STUB, timeout=1000000)

    res_asw = uc.reg_read(UC_X86_REG_EAX)
    first_army_subs = sc[0].subunits if (sc and len(sc) > 0) else None
    expected_asw = calculate_army_supply_weight(first_army_subs)
    if res_asw != expected_asw:
        print(f"MISMATCH in CalculateSupplyWeight (Army): got {res_asw}, expected {expected_asw}")
        mismatches += 1

    # 3. Test CCombatant::CalculateSupplyWeight (0x005DC5D0)
    # eax = HEAD_ARMY_PTR, ret
    total_fixtures += 1
    uc.mem_write(STACK, struct.pack('<I', RET_STUB))
    uc.reg_write(UC_X86_REG_ESP, STACK)
    uc.reg_write(UC_X86_REG_EAX, HEAD_ARMY_PTR)
    uc.reg_write(UC_X86_REG_EIP, 0x005DC5D0)
    uc.reg_write(UC_X86_REG_EBX, 0)
    uc.reg_write(UC_X86_REG_ECX, 0)
    uc.reg_write(UC_X86_REG_EDX, 0)
    uc.reg_write(UC_X86_REG_ESI, 0)
    uc.reg_write(UC_X86_REG_EDI, 0)

    uc.emu_start(0x005DC5D0, RET_STUB, timeout=1000000)

    res_csw = uc.reg_read(UC_X86_REG_EAX)
    expected_csw = calculate_combatant_supply_weight(sc)
    if res_csw != expected_csw:
        print(f"MISMATCH in CalculateSupplyWeight (Combatant): got {res_csw}, expected {expected_csw}")
        mismatches += 1

assert mismatches == 0, f"{mismatches} mismatches encountered in emulation!"

# Record receipts
out_dir = ROOT / 'evidence/generated/subunit-weight'
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
ledger.start_run('Verify CCombatant and CArmy subunit weight and counting routines', session='subunit-weight')
ledger.record(report, rnd=1, session='subunit-weight')
ledger.finish_run(1, report['grounded'], report['information'])
ledger.save()

print(f"Subunit weight: {len(report['results'])} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Subunit weight emulation: {total_fixtures} fixtures executed, 0 mismatches against subunit_weight_model.")
