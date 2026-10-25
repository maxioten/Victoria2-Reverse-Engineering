#!/usr/bin/env python3
"""Verify CLandCombatant::PruneAndConsolidateLine against PE32 binary with Reverify and Unicorn.

Routine: 0x0059AEF0..0x0059B0D9 (490 bytes, 157 instructions).
Caller: 0x0059ACD4 in CLandCombatant::DailyCombatPhase.
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
from combat_line_consolidation_model import (
    UnitState, CombatantLineState, prune_and_consolidate_line
)

bin_path = ROOT.parent / 'base-game/v2game.exe'
data = bin_path.read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_32)

claims = []

# 1. Routine instructions (0x0059AEF0..0x0059B0D9)
raw_start = pe.get_offset_from_rva(0x0059AEF0 - base)
for insn in md.disasm(data[raw_start:raw_start + 600], 0x0059AEF0):
    claims.append({
        'id': f'combat_consolidate_insn_{insn.address:x}',
        'kind': 'instructions',
        'space': 'rva',
        'offset': hex(insn.address - base),
        'base': hex(insn.address),
        'arch': 'x86',
        'length': len(insn.bytes),
        'mnemonics': [insn.mnemonic],
        'operands': [insn.op_str]
    })
    if insn.address >= 0x0059B0D9:
        break

# 2. Caller across engine: 0x0059ACD4
caller_va = 0x0059ACD4
caller_raw = pe.get_offset_from_rva(caller_va - base)
caller_insn = list(md.disasm(data[caller_raw:caller_raw + 10], caller_va))[0]
claims.append({
    'id': f'combat_consolidate_caller_{caller_va:x}',
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
wrong = dict(claims[0], id='negative_control_combat_consolidate', mnemonics=['nop'])
dependent = dict(claims[1], id='negative_dependent_combat_consolidate', depends_on=['negative_control_combat_consolidate'])
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

uc.mem_map(0x01100000 + base, 0x01000000, UC_PROT_ALL)
heap = 0x03000000
uc.mem_map(heap, 0x500000, UC_PROT_ALL)

ret_stub = heap + 0x100
uc.mem_write(ret_stub, b'\x90')
stack_top = heap + 0x80000

# Operator new mock
node_bump = [heap + 0x20000]
def hook_new(uc_inst, address, size, user_data):
    ptr = node_bump[0]
    node_bump[0] += 16
    uc_inst.reg_write(UC_X86_REG_EAX, ptr)

uc.hook_add(UC_HOOK_CODE, hook_new, begin=0x00AAE9AF, end=0x00AAE9AF)
uc.mem_write(0x00AAE9AF, b'\xc3')

# DeployFromReserve stub
uc.mem_write(0x0059B190, b'\xc2\x04\x00') # ret 4

# CRT hooks for floor/ftol2
def hook_ftol(uc_inst, address, size, user_data):
    uc_inst.reg_write(UC_X86_REG_EAX, 100)

uc.hook_add(UC_HOOK_CODE, hook_ftol, begin=0x00B31C00, end=0x00B31C00)
uc.mem_write(0x00401000, b'\xc3')
uc.mem_write(0x00B31C00, b'\xc3')

# Combatant and Combat structs
combatant = heap + 0x1000
combat = heap + 0x2000
vtable = heap + 0x2100
uc.mem_write(combatant + 0x1C, struct.pack('<I', combat))
uc.mem_write(combat, struct.pack('<I', vtable))

retreat_func = heap + 0x2200
uc.mem_write(vtable + 0x2C, struct.pack('<I', retreat_func))

# Dynamic hook state
hook_state = {
    'retreat_allowed': True,
    'has_target': True,
}

def hook_retreat_func(uc_inst, address, size, user_data):
    val = 1 if hook_state['retreat_allowed'] else 0
    uc_inst.reg_write(UC_X86_REG_EAX, val)

uc.hook_add(UC_HOOK_CODE, hook_retreat_func, begin=retreat_func, end=retreat_func)
uc.mem_write(retreat_func, b'\xc3')

# Hook FindTargetRegiment (0x0059B610)
def hook_find_target(uc_inst, address, size, user_data):
    val = 0x1234 if hook_state['has_target'] else 0
    uc_inst.reg_write(UC_X86_REG_EAX, val)

uc.hook_add(UC_HOOK_CODE, hook_find_target, begin=0x0059B610, end=0x0059B610)
uc.mem_write(0x0059B610, b'\xc2\x08\x00') # ret 8

target_combatant = heap + 0x2500

# Pre-allocated unit pool
unit_ptrs = {}
for uid in range(1, 400):
    u_addr = heap + 0x30000 + uid * 0x100
    t_addr = heap + 0x70000 + uid * 0x100
    uc.mem_write(u_addr + 0x38, struct.pack('<I', t_addr))
    unit_ptrs[uid] = (u_addr, t_addr)


def run_consolidation_test(
    initial_front: list,
    initial_back: list,
    retreat_allowed: bool = True,
    has_target: bool = True,
):
    hook_state['retreat_allowed'] = retreat_allowed
    hook_state['has_target'] = has_target
    node_bump[0] = heap + 0x20000

    # Reset combatant arrays
    uc.mem_write(combatant + 0x6C, b'\x00' * (32 * 4)) # front_line
    uc.mem_write(combatant + 0xEC, b'\x00' * (32 * 4)) # back_line
    uc.mem_write(combatant + 0x16C, b'\x00' * 0x30) # reset lists (0x16C to 0x19C)

    model_state = CombatantLineState(
        front_line=[None] * 32,
        back_line=[None] * 32,
        retreat_list=[],
        routed_list=[]
    )

    ptr_to_uid = {}

    for i in range(30):
        if i < len(initial_front) and initial_front[i]:
            u = initial_front[i]
            u_addr, t_addr = unit_ptrs[u.uid]
            uc.mem_write(u_addr + 0x3C, struct.pack('<i', u.strength))
            uc.mem_write(u_addr + 0x40, struct.pack('<i', u.org))
            uc.mem_write(t_addr + 0x23C, struct.pack('<i', u.support))
            uc.mem_write(t_addr + 0x240, struct.pack('<i', u.maneuver))
            uc.mem_write(combatant + i * 4 + 0x6C, struct.pack('<I', u_addr))
            model_state.front_line[i] = u
            ptr_to_uid[u_addr] = u.uid

        if i < len(initial_back) and initial_back[i]:
            u = initial_back[i]
            u_addr, t_addr = unit_ptrs[u.uid]
            uc.mem_write(u_addr + 0x3C, struct.pack('<i', u.strength))
            uc.mem_write(u_addr + 0x40, struct.pack('<i', u.org))
            uc.mem_write(t_addr + 0x23C, struct.pack('<i', u.support))
            uc.mem_write(t_addr + 0x240, struct.pack('<i', u.maneuver))
            uc.mem_write(combatant + i * 4 + 0xEC, struct.pack('<I', u_addr))
            model_state.back_line[i] = u
            ptr_to_uid[u_addr] = u.uid

    # Call 0x0059AEF0
    uc.mem_write(stack_top - 8, struct.pack('<II', ret_stub, target_combatant))
    uc.reg_write(UC_X86_REG_ESP, stack_top - 8)
    uc.reg_write(UC_X86_REG_EAX, combatant)

    uc.emu_start(0x0059AEF0, ret_stub)

    # Run analytical model
    prune_and_consolidate_line(model_state, retreat_allowed, has_target)

    # Validate frontline
    for i in range(30):
        val = struct.unpack('<I', uc.mem_read(combatant + i * 4 + 0x6C, 4))[0]
        actual_uid = ptr_to_uid.get(val, None) if val != 0 else None
        expected_uid = model_state.front_line[i].uid if model_state.front_line[i] else None
        assert actual_uid == expected_uid, (
            f"Frontline col {i} mismatch: got uid {actual_uid}, expected {expected_uid}"
        )

    # Validate backline
    for i in range(30):
        val = struct.unpack('<I', uc.mem_read(combatant + i * 4 + 0xEC, 4))[0]
        actual_uid = ptr_to_uid.get(val, None) if val != 0 else None
        expected_uid = model_state.back_line[i].uid if model_state.back_line[i] else None
        assert actual_uid == expected_uid, (
            f"Backline col {i} mismatch: got uid {actual_uid}, expected {expected_uid}"
        )

    # Validate retreat/routed counts
    ret_count = struct.unpack('<I', uc.mem_read(combatant + 0x174, 4))[0]
    rout_count = struct.unpack('<I', uc.mem_read(combatant + 0x184, 4))[0]
    assert ret_count == len(model_state.retreat_list), (
        f"Retreat count mismatch: got {ret_count}, expected {len(model_state.retreat_list)}"
    )
    assert rout_count == len(model_state.routed_list), (
        f"Routed count mismatch: got {rout_count}, expected {len(model_state.routed_list)}"
    )


fixtures_run = 0

# Test Case 1: Healthy line, no changes
f1 = [None] * 30
for c in range(10, 20):
    f1[c] = UnitState(uid=c, strength=1000, org=20000)
run_consolidation_test(f1, [None]*30)
fixtures_run += 1

# Test Case 2: Broken unit at center (strength < 100), backline steps up
f2 = [None] * 30
b2 = [None] * 30
f2[15] = UnitState(uid=1, strength=50, org=20000) # collapsed
b2[15] = UnitState(uid=2, strength=1000, org=20000, support=0) # steps up
run_consolidation_test(f2, b2)
fixtures_run += 1

# Test Case 3: Broken unit at center (org < 1000), backline steps up
f3 = [None] * 30
b3 = [None] * 30
f3[14] = UnitState(uid=3, strength=2000, org=500) # low org (< 1000)
b3[14] = UnitState(uid=4, strength=1000, org=20000, support=0)
run_consolidation_test(f3, b3)
fixtures_run += 1

# Test Case 4: Backline artillery (support > 0) stays in back when front destroyed and flaked
f4 = [None] * 30
b4 = [None] * 30
f4[15] = UnitState(uid=5, strength=10, org=100) # collapses
b4[15] = UnitState(uid=6, strength=1000, org=20000, support=1000) # artillery steps up directly!
run_consolidation_test(f4, b4)
fixtures_run += 1

# Test Case 5: Left wing centripetal consolidation (single unit slides rightward)
f5 = [None] * 30
f5[3] = UnitState(uid=10, strength=1000, org=20000)
run_consolidation_test(f5, [None]*30)
fixtures_run += 1

# Test Case 6: Right wing centripetal consolidation (single unit shifts leftward)
f6 = [None] * 30
f6[25] = UnitState(uid=11, strength=1000, org=20000)
run_consolidation_test(f6, [None]*30)
fixtures_run += 1

# Test Case 7: Both wings simultaneously consolidating towards center
f7 = [None] * 30
f7[2] = UnitState(uid=12, strength=1000, org=20000)
f7[26] = UnitState(uid=13, strength=1000, org=20000)
run_consolidation_test(f7, [None]*30)
fixtures_run += 1

# Test Case 8: Tactical retreat disallowed with broken unit (retreats to 0x16C)
f8 = [None] * 30
f8[15] = UnitState(uid=14, strength=20, org=200) # broken
run_consolidation_test(f8, [None]*30, retreat_allowed=False, has_target=True)
fixtures_run += 1

# Test Case 9: Tactical retreat disallowed with no target and broken unit (retreats to 0x16C)
f9 = [None] * 30
f9[15] = UnitState(uid=15, strength=20, org=200) # broken
run_consolidation_test(f9, [None]*30, retreat_allowed=False, has_target=False)
fixtures_run += 1

# Test Case 10: Healthy unit with target when retreat disallowed (stays in line)
f10 = [None] * 30
f10[15] = UnitState(uid=16, strength=1000, org=20000) # healthy
run_consolidation_test(f10, [None]*30, retreat_allowed=False, has_target=True)
fixtures_run += 1

# Test Case 11: Healthy unit with NO target when retreat disallowed (retreats to 0x16C)
f11 = [None] * 30
f11[15] = UnitState(uid=17, strength=1000, org=20000) # healthy but no enemies
run_consolidation_test(f11, [None]*30, retreat_allowed=False, has_target=False)
fixtures_run += 1

# Comprehensive permutation sweep: varied initial setups and broken positions
for broken_col in [5, 10, 14, 15, 16, 20, 25]:
    for has_back in [False, True]:
        for supp in [0, 500]:
            f = [None] * 30
            b = [None] * 30
            # Place surrounding units
            for c in range(broken_col - 2, broken_col + 3):
                if 0 <= c < 30:
                    f[c] = UnitState(uid=100 + c, strength=1000, org=20000)
            # Break the designated column
            f[broken_col] = UnitState(uid=200 + broken_col, strength=20, org=200)
            if has_back:
                b[broken_col] = UnitState(uid=300 + broken_col, strength=1000, org=20000, support=supp)
            run_consolidation_test(f, b)
            fixtures_run += 1

# Save receipts
out_dir = ROOT / 'evidence/generated/combat-line-consolidation'
out_dir.mkdir(parents=True, exist_ok=True)
(out_dir / 'claims.json').write_text(json.dumps(claims, indent=2) + '\n')
(out_dir / 'reverify.json').write_text(json.dumps(report, indent=2) + '\n')
(out_dir / 'negative-controls.json').write_text(json.dumps(controls, indent=2) + '\n')
(out_dir / 'emulation.json').write_text(json.dumps({
    'binary_sha256': digest,
    'routine_va': hex(0x0059AEF0),
    'fixtures_count': fixtures_run,
    'mismatches': 0
}, indent=2) + '\n')

ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify', file_path=str(bin_path))
ledger.start_run('Verify CLandCombatant::PruneAndConsolidateLine routine and callers', session='combat-line-consolidation')
ledger.record(report, rnd=1, session='combat-line-consolidation')
ledger.finish_run(1, report['grounded'], report['information'])
ledger.save()

print(f"Combat line consolidation: {len(report['results'])} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Combat line consolidation emulation: {fixtures_run} fixtures executed, 0 mismatches against combat_line_consolidation_model.")
