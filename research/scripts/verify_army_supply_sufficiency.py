#!/usr/bin/env python3
"""Verify CArmy::EvaluateSupplySufficiency against PE32 binary with Reverify and Unicorn.

Routine: 0x005D5E30..0x005D5EE3 (180 bytes, 69 instructions).
Vtable slot 3 (+0x0C): 0x00DF8950 in CArmy vtable (0x00DF8944).
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
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_PROT_ALL, UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_EAX, UC_X86_REG_ECX,
    UC_X86_REG_EDX, UC_X86_REG_EBX, UC_X86_REG_ESI, UC_X86_REG_EDI
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT / 'scripts'))
from army_supply_sufficiency_model import (
    ArmyStationedState, SupplySufficiencyInput, evaluate_supply_sufficiency
)

bin_path = ROOT.parent / 'base-game/v2game.exe'
data = bin_path.read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_32)

claims = []

# 1. Routine instructions (0x005D5E30..0x005D5EE3)
raw_start = pe.get_offset_from_rva(0x005D5E30 - base)
for insn in md.disasm(data[raw_start:raw_start + 220], 0x005D5E30):
    claims.append({
        'id': f'army_supply_suff_insn_{insn.address:x}',
        'kind': 'instructions',
        'space': 'rva',
        'offset': hex(insn.address - base),
        'base': hex(insn.address),
        'arch': 'x86',
        'length': len(insn.bytes),
        'mnemonics': [insn.mnemonic],
        'operands': [insn.op_str]
    })
    if insn.address >= 0x005D5EE3:
        break

# 2. Vtable slot 3 (+0x0C) in CArmy at 0x00DF8950
vtable_va = 0x00DF8950
v_raw = pe.get_offset_from_rva(vtable_va - base)
target_ptr = int.from_bytes(data[v_raw:v_raw + 4], 'little')
assert target_ptr == 0x005D5E30
claims.append({
    'id': 'army_supply_suff_vtable_CArmy',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(vtable_va - base),
    'base': hex(vtable_va),
    'expected': (0x005D5E30).to_bytes(4, 'little').hex()
})

# Run Reverify
verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]

# Negative controls and dependent invalidation
wrong = dict(claims[0], id='negative_control_army_supply_suff', mnemonics=['nop'])
dependent = dict(claims[1], id='negative_dependent_army_supply_suff', depends_on=['negative_control_army_supply_suff'])
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

# Allocate scratch memory for synthetic objects, vtables and stack
SCRATCH_BASE = 0x02000000
SCRATCH_SIZE = 0x00100000
uc.mem_map(SCRATCH_BASE, SCRATCH_SIZE, UC_PROT_ALL)

STACK_BASE = SCRATCH_BASE + 0x80000
THIS_ARMY_ADDR = SCRATCH_BASE + 0x1000
PROV_ADDR = SCRATCH_BASE + 0x2000
TERRAIN_ADDR = SCRATCH_BASE + 0x3000
VTABLE_ARMY_ADDR = SCRATCH_BASE + 0x4000
STUB_ALLIED_CODE = SCRATCH_BASE + 0x5000
STUB_SUPPLY_CODE = SCRATCH_BASE + 0x5100
LIST_NODES_BASE = SCRATCH_BASE + 0x6000
OTHER_ARMIES_BASE = SCRATCH_BASE + 0x10000

# Wire pointers
uc.mem_write(THIS_ARMY_ADDR, struct.pack('<I', VTABLE_ARMY_ADDR))
uc.mem_write(PROV_ADDR + 0x5C, struct.pack('<I', TERRAIN_ADDR))
uc.mem_write(VTABLE_ARMY_ADDR + 0x38, struct.pack('<I', STUB_ALLIED_CODE))
uc.mem_write(VTABLE_ARMY_ADDR + 0x3C, struct.pack('<I', STUB_SUPPLY_CODE))

# Synthetic stubs for IsAlliedTo and IsSupplyContributor
# mov al, [ecx + 0x160] ; ret
stub_allied_bytes = bytes([
    0x8A, 0x81, 0x60, 0x01, 0x00, 0x00,  # mov al, [ecx + 0x160]
    0xC3                                 # ret
])
# mov al, [ecx + 0x161] ; ret
stub_supply_bytes = bytes([
    0x8A, 0x81, 0x61, 0x01, 0x00, 0x00,  # mov al, [ecx + 0x161]
    0xC3                                 # ret
])
uc.mem_write(STUB_ALLIED_CODE, stub_allied_bytes)
uc.mem_write(STUB_SUPPLY_CODE, stub_supply_bytes)


def hook_army_helpers(uc_inst, address, size, user_data):
    if address == 0x005CD580:
        # GetArmyEffectiveCapacity: army in eax, read capacity from [eax + 0x48]
        army_ptr = uc_inst.reg_read(UC_X86_REG_EAX)
        cap = struct.unpack('<i', uc_inst.mem_read(army_ptr + 0x48, 4))[0]
        uc_inst.reg_write(UC_X86_REG_EAX, cap)
        esp = uc_inst.reg_read(UC_X86_REG_ESP)
        ret = struct.unpack('<I', uc_inst.mem_read(esp, 4))[0]
        uc_inst.reg_write(UC_X86_REG_ESP, esp + 4)
        uc_inst.reg_write(UC_X86_REG_EIP, ret)
    elif address == 0x005CD2F0:
        # CanTraverseSea: army in ecx, read bool from [ecx + 0x165]
        army_ptr = uc_inst.reg_read(UC_X86_REG_ECX)
        can_trav = struct.unpack('<B', uc_inst.mem_read(army_ptr + 0x165, 1))[0]
        uc_inst.reg_write(UC_X86_REG_EAX, can_trav)
        esp = uc_inst.reg_read(UC_X86_REG_ESP)
        ret = struct.unpack('<I', uc_inst.mem_read(esp, 4))[0]
        # callee pop 4 bytes: ret 4
        uc_inst.reg_write(UC_X86_REG_ESP, esp + 8)
        uc_inst.reg_write(UC_X86_REG_EIP, ret)


uc.hook_add(UC_HOOK_CODE, hook_army_helpers)


def run_supply_sufficiency_test(inp: SupplySufficiencyInput) -> bool:
    # Setup this_army
    uc.mem_write(THIS_ARMY_ADDR + 0x40, struct.pack('<i', inp.this_army_weight))
    uc.mem_write(THIS_ARMY_ADDR + 0xC4, struct.pack('<i', inp.this_army_country_id))
    uc.mem_write(THIS_ARMY_ADDR + 0x164, struct.pack('<B', 1 if inp.is_embarked else 0))
    uc.mem_write(THIS_ARMY_ADDR + 0x165, struct.pack('<B', 1 if inp.can_traverse_sea else 0))

    # Setup terrain
    uc.mem_write(TERRAIN_ADDR + 0x2A, struct.pack('<B', 1 if inp.is_water_province else 0))

    # Setup stationed armies list in province + 0xEC
    if not inp.stationed_armies:
        uc.mem_write(PROV_ADDR + 0xEC, struct.pack('<I', 0))
    else:
        # Build linked list
        for i, a in enumerate(inp.stationed_armies):
            node_addr = LIST_NODES_BASE + i * 16
            army_addr = OTHER_ARMIES_BASE + i * 0x200
            next_node = (LIST_NODES_BASE + (i + 1) * 16) if (i + 1 < len(inp.stationed_armies)) else 0

            # Write node: [node] = army_addr, [node + 8] = next_node
            uc.mem_write(node_addr, struct.pack('<I', army_addr))
            uc.mem_write(node_addr + 4, struct.pack('<I', 0))
            uc.mem_write(node_addr + 8, struct.pack('<I', next_node))

            # Write army
            uc.mem_write(army_addr, struct.pack('<I', VTABLE_ARMY_ADDR))
            uc.mem_write(army_addr + 0x40, struct.pack('<i', a.supply_weight))
            uc.mem_write(army_addr + 0x48, struct.pack('<i', a.effective_capacity))
            uc.mem_write(army_addr + 0xC4, struct.pack('<i', a.country_id))
            uc.mem_write(army_addr + 0x160, struct.pack('<B', 1 if a.is_allied else 0))
            uc.mem_write(army_addr + 0x161, struct.pack('<B', 1 if a.is_supply_source else 0))

        uc.mem_write(PROV_ADDR + 0xEC, struct.pack('<I', LIST_NODES_BASE))

    ret_addr = SCRATCH_BASE + 0x70000
    uc.mem_write(STACK_BASE - 8, struct.pack('<II', ret_addr, PROV_ADDR))
    uc.reg_write(UC_X86_REG_ESP, STACK_BASE - 8)
    uc.reg_write(UC_X86_REG_ECX, THIS_ARMY_ADDR)

    uc.emu_start(0x005D5E30, ret_addr)

    res = bool(uc.reg_read(UC_X86_REG_EAX) & 0xFF)
    expected = evaluate_supply_sufficiency(inp)
    assert res == expected, (
        f"Mismatch: inp={inp}, emu={res}, expected={expected}"
    )
    return res


fixtures_run = 0

# Case 1: Sea zone, embarked -> True
c1 = SupplySufficiencyInput(this_army_country_id=1, this_army_weight=10, is_water_province=True, is_embarked=True)
assert run_supply_sufficiency_test(c1)
fixtures_run += 1

# Case 2: Sea zone, not embarked, cannot traverse sea -> False
c2 = SupplySufficiencyInput(this_army_country_id=1, this_army_weight=10, is_water_province=True, is_embarked=False, can_traverse_sea=False)
assert not run_supply_sufficiency_test(c2)
fixtures_run += 1

# Case 3: Sea zone, not embarked, can traverse sea -> True
c3 = SupplySufficiencyInput(this_army_country_id=1, this_army_weight=10, is_water_province=True, is_embarked=False, can_traverse_sea=True)
assert run_supply_sufficiency_test(c3)
fixtures_run += 1

# Case 4: Land province, no other armies, capacity 0 < weight 10 -> False
c4 = SupplySufficiencyInput(this_army_country_id=1, this_army_weight=10)
assert not run_supply_sufficiency_test(c4)
fixtures_run += 1

# Case 5: Land province, friendly supply source provides 30 capacity, total demand 10 + 10 = 20 <= 30 -> True
c5 = SupplySufficiencyInput(
    this_army_country_id=1,
    this_army_weight=10,
    stationed_armies=[ArmyStationedState(army_id=2, country_id=1, supply_weight=10, effective_capacity=30)]
)
assert run_supply_sufficiency_test(c5)
fixtures_run += 1

# Case 6: Land province, friendly army provides 15 capacity, total demand 10 + 10 = 20 > 15 -> False (deficit)
c6 = SupplySufficiencyInput(
    this_army_country_id=1,
    this_army_weight=10,
    stationed_armies=[ArmyStationedState(army_id=2, country_id=1, supply_weight=10, effective_capacity=15)]
)
assert not run_supply_sufficiency_test(c6)
fixtures_run += 1

# Case 7: Land province, army from another country (country_id=2) ignored -> capacity 0 < 10 -> False
c7 = SupplySufficiencyInput(
    this_army_country_id=1,
    this_army_weight=10,
    stationed_armies=[ArmyStationedState(army_id=2, country_id=2, supply_weight=5, effective_capacity=100)]
)
assert not run_supply_sufficiency_test(c7)
fixtures_run += 1

# Case 8: Land province, multiple allied armies in coalition
c8 = SupplySufficiencyInput(
    this_army_country_id=1,
    this_army_weight=15,
    stationed_armies=[
        ArmyStationedState(army_id=2, country_id=1, supply_weight=10, effective_capacity=20),
        ArmyStationedState(army_id=3, country_id=1, supply_weight=10, effective_capacity=25), # total cap = 45, demand = 35 -> True
    ]
)
assert run_supply_sufficiency_test(c8)
fixtures_run += 1

# Comprehensive parametric sweep
for my_wt in [5, 15, 30]:
    for friend_wt in [5, 10, 20]:
        for cap in [10, 25, 45, 70]:
            run_supply_sufficiency_test(SupplySufficiencyInput(
                this_army_country_id=1,
                this_army_weight=my_wt,
                stationed_armies=[ArmyStationedState(army_id=2, country_id=1, supply_weight=friend_wt, effective_capacity=cap)]
            ))
            fixtures_run += 1

# Save receipts
out_dir = ROOT / 'evidence/generated/army-supply-sufficiency'
out_dir.mkdir(parents=True, exist_ok=True)
(out_dir / 'claims.json').write_text(json.dumps(claims, indent=2) + '\n')
(out_dir / 'reverify.json').write_text(json.dumps(report, indent=2) + '\n')
(out_dir / 'negative-controls.json').write_text(json.dumps(controls, indent=2) + '\n')
(out_dir / 'emulation.json').write_text(json.dumps({
    'binary_sha256': digest,
    'routine_va': hex(0x005D5E30),
    'fixtures_count': fixtures_run,
    'mismatches': 0
}, indent=2) + '\n')

ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify', file_path=str(bin_path))
ledger.start_run('Verify CArmy::EvaluateSupplySufficiency routine and vtables', session='army-supply-sufficiency')
ledger.record(report, rnd=1, session='army-supply-sufficiency')
ledger.finish_run(1, report['grounded'], report['information'])
ledger.save()

print(f"Army supply sufficiency: {len(report['results'])} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Army supply sufficiency emulation: {fixtures_run} fixtures executed, 0 mismatches against army_supply_sufficiency_model.")
