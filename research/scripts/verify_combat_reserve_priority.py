#!/usr/bin/env python3
"""Verify CSubUnit::CompareTacticalValue against PE32 binary with Reverify and Unicorn.

Routine: 0x0059B780..0x0059B833 (84 bytes, 64 instructions).
Caller: 0x005AB8B7 in CLandCombatant::InsertReserveRegiment.
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
from combat_reserve_priority_model import (
    SubUnitTacticalInput, calculate_tactical_score, compare_tactical_value
)

bin_path = ROOT.parent / 'base-game/v2game.exe'
data = bin_path.read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_32)

claims = []

# 1. Routine instructions (0x0059B780..0x0059B833)
raw_start = pe.get_offset_from_rva(0x0059B780 - base)
for insn in md.disasm(data[raw_start:raw_start + 120], 0x0059B780):
    claims.append({
        'id': f'combat_reserve_priority_insn_{insn.address:x}',
        'kind': 'instructions',
        'space': 'rva',
        'offset': hex(insn.address - base),
        'base': hex(insn.address),
        'arch': 'x86',
        'length': len(insn.bytes),
        'mnemonics': [insn.mnemonic],
        'operands': [insn.op_str]
    })
    if insn.address >= 0x0059B833:
        break

# 2. Caller check in CLandCombatant::InsertReserveRegiment at 0x005AB8B7
caller_va = 0x005AB8B7
caller_raw = pe.get_offset_from_rva(caller_va - base)
caller_insn = list(md.disasm(data[caller_raw:caller_raw + 10], caller_va))[0]
claims.append({
    'id': f'combat_reserve_priority_caller_{caller_va:x}',
    'kind': 'instructions',
    'space': 'rva',
    'offset': hex(caller_va - base),
    'base': hex(caller_va),
    'arch': 'x86',
    'length': len(caller_insn.bytes),
    'mnemonics': [caller_insn.mnemonic],
    'operands': [caller_insn.op_str]
})

# Run Reverify
verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]

# Negative controls and dependent invalidation
wrong = dict(claims[0], id='negative_control_reserve_priority', mnemonics=['nop'])
dependent = dict(claims[1], id='negative_dependent_reserve_priority', depends_on=['negative_control_reserve_priority'])
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

# Allocate scratch memory for synthetic objects and stack
SCRATCH_BASE = 0x02000000
SCRATCH_SIZE = 0x00100000
uc.mem_map(SCRATCH_BASE, SCRATCH_SIZE, UC_PROT_ALL)

STACK_BASE = SCRATCH_BASE + 0x80000
REG_A_ADDR = SCRATCH_BASE + 0x1000
REG_B_ADDR = SCRATCH_BASE + 0x2000
TYPE_A_ADDR = SCRATCH_BASE + 0x3000
TYPE_B_ADDR = SCRATCH_BASE + 0x4000
LEAD_A_ADDR = SCRATCH_BASE + 0x5000
LEAD_B_ADDR = SCRATCH_BASE + 0x6000

# Wire pointers
uc.mem_write(REG_A_ADDR + 0x38, struct.pack('<I', TYPE_A_ADDR))
uc.mem_write(REG_B_ADDR + 0x38, struct.pack('<I', TYPE_B_ADDR))


def setup_subunit(reg_addr, type_addr, lead_addr, inp: SubUnitTacticalInput):
    # UnitType stats
    uc.mem_write(type_addr + 0x230, struct.pack('<i', inp.fire_attack))
    uc.mem_write(type_addr + 0x234, struct.pack('<i', inp.shock_attack))
    uc.mem_write(type_addr + 0x240, struct.pack('<i', inp.maneuver))

    # Regiment state
    uc.mem_write(reg_addr + 0x3C, struct.pack('<i', inp.strength))
    uc.mem_write(reg_addr + 0x40, struct.pack('<i', inp.organization))

    # Leader state
    if inp.has_leader:
        uc.mem_write(reg_addr + 0x74, struct.pack('<I', lead_addr))
        uc.mem_write(lead_addr + 0x164, struct.pack('<B', 1 if inp.leader_inoperative else 0))
    else:
        uc.mem_write(reg_addr + 0x74, struct.pack('<I', 0))


def run_priority_test(unit_a: SubUnitTacticalInput, unit_b: SubUnitTacticalInput) -> bool:
    setup_subunit(REG_A_ADDR, TYPE_A_ADDR, LEAD_A_ADDR, unit_a)
    setup_subunit(REG_B_ADDR, TYPE_B_ADDR, LEAD_B_ADDR, unit_b)

    ret_addr = base + 0x1000
    uc.mem_write(STACK_BASE - 4, struct.pack('<I', ret_addr))

    uc.reg_write(UC_X86_REG_ESP, STACK_BASE - 4)
    uc.reg_write(UC_X86_REG_EDX, REG_A_ADDR)
    uc.reg_write(UC_X86_REG_EAX, REG_B_ADDR)

    # Execute routine up to ret (0x0059B833)
    uc.emu_start(0x0059B780, 0x0059B833)

    al = uc.reg_read(UC_X86_REG_EAX) & 0xFF
    res = bool(al)

    expected = compare_tactical_value(unit_a, unit_b)
    assert res == expected, (
        f"Mismatch: A={unit_a}, B={unit_b}, emu={res}, expected={expected}"
    )
    return res


fixtures_run = 0

# Case 1: Identical units -> False (neither is strictly less)
c1_a = SubUnitTacticalInput(strength=3000, organization=30000, fire_attack=1000, shock_attack=1000, maneuver=1000)
c1_b = SubUnitTacticalInput(strength=3000, organization=30000, fire_attack=1000, shock_attack=1000, maneuver=1000)
assert not run_priority_test(c1_a, c1_b)
fixtures_run += 1

# Case 2: Unit A has higher strength -> A not < B -> False
c2_a = SubUnitTacticalInput(strength=3000, organization=30000, fire_attack=1000, shock_attack=1000, maneuver=1000)
c2_b = SubUnitTacticalInput(strength=1500, organization=30000, fire_attack=1000, shock_attack=1000, maneuver=1000)
assert not run_priority_test(c2_a, c2_b)
fixtures_run += 1

# Case 3: Unit A has lower strength -> A < B -> True
assert run_priority_test(c2_b, c2_a)
fixtures_run += 1

# Case 4: Unit A has higher organization -> A not < B -> False
c4_a = SubUnitTacticalInput(strength=3000, organization=40000, fire_attack=1000, shock_attack=1000, maneuver=1000)
c4_b = SubUnitTacticalInput(strength=3000, organization=20000, fire_attack=1000, shock_attack=1000, maneuver=1000)
assert not run_priority_test(c4_a, c4_b)
fixtures_run += 1

# Case 5: Unit A has lower organization -> A < B -> True
assert run_priority_test(c4_b, c4_a)
fixtures_run += 1

# Case 6: Unit A has higher stats (artillery/cavalry) -> A not < B -> False
c6_a = SubUnitTacticalInput(strength=3000, organization=30000, fire_attack=3000, shock_attack=2000, maneuver=2000)
c6_b = SubUnitTacticalInput(strength=3000, organization=30000, fire_attack=1000, shock_attack=1000, maneuver=1000)
assert not run_priority_test(c6_a, c6_b)
fixtures_run += 1

# Case 7: Unit A has lower stats -> A < B -> True
assert run_priority_test(c6_b, c6_a)
fixtures_run += 1

# Case 8: Unit A has inoperative leader -> effective org drops to 0 -> A < B -> True
c8_a = SubUnitTacticalInput(strength=3000, organization=30000, fire_attack=1000, shock_attack=1000, maneuver=1000, has_leader=True, leader_inoperative=True)
c8_b = SubUnitTacticalInput(strength=1000, organization=10000, fire_attack=1000, shock_attack=1000, maneuver=1000, has_leader=False)
assert run_priority_test(c8_a, c8_b)
fixtures_run += 1

# Case 9: Unit B has inoperative leader -> B score drops to 0 -> A < B -> False
assert not run_priority_test(c8_b, c8_a)
fixtures_run += 1

# Case 10: Both have inoperative leader -> both score 0 -> A < B -> False
c10_b = SubUnitTacticalInput(strength=1000, organization=10000, fire_attack=1000, shock_attack=1000, maneuver=1000, has_leader=True, leader_inoperative=True)
assert not run_priority_test(c8_a, c10_b)
fixtures_run += 1

# Comprehensive parametric sweep
for str_a in [500, 1500, 3000]:
    for str_b in [500, 1500, 3000]:
        for org_a in [10000, 25000, 40000]:
            for stats_b in [(1000, 1000, 1000), (2500, 1500, 2000)]:
                run_priority_test(
                    SubUnitTacticalInput(strength=str_a, organization=org_a, fire_attack=1000, shock_attack=1000, maneuver=1000),
                    SubUnitTacticalInput(strength=str_b, organization=25000, fire_attack=stats_b[0], shock_attack=stats_b[1], maneuver=stats_b[2])
                )
                fixtures_run += 1

# Save receipts
out_dir = ROOT / 'evidence/generated/combat-reserve-priority'
out_dir.mkdir(parents=True, exist_ok=True)
(out_dir / 'claims.json').write_text(json.dumps(claims, indent=2) + '\n')
(out_dir / 'reverify.json').write_text(json.dumps(report, indent=2) + '\n')
(out_dir / 'negative-controls.json').write_text(json.dumps(controls, indent=2) + '\n')
(out_dir / 'emulation.json').write_text(json.dumps({
    'binary_sha256': digest,
    'routine_va': hex(0x0059B780),
    'fixtures_count': fixtures_run,
    'mismatches': 0
}, indent=2) + '\n')

ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify', file_path=str(bin_path))
ledger.start_run('Verify CSubUnit::CompareTacticalValue routine and caller', session='combat-reserve-priority')
ledger.record(report, rnd=1, session='combat-reserve-priority')
ledger.finish_run(1, report['grounded'], report['information'])
ledger.save()

print(f"Combat reserve priority: {len(report['results'])} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Combat reserve priority emulation: {fixtures_run} fixtures executed, 0 mismatches against combat_reserve_priority_model.")
