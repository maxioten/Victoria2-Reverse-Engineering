#!/usr/bin/env python3
"""Verify CCombat::EvaluateVictoryAndStackwipe against PE32 binary with Reverify and Unicorn.

Routine: 0x0059C630..0x0059C8A7 (632 bytes, 197 instructions).
Vtable slot 11 (+0x2C):
  - 0x00E02174 in CCombat vtable.
  - 0x00E02384 in CLandCombat vtable.
  - 0x00E02464 in CNavalCombat vtable.
Callers:
  - 0x0059AF34 in CLandCombatant::PruneAndConsolidateLine.
  - 0x005954F0, 0x005990E0 in combat round drivers.
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
from combat_victory_stackwipe_model import (
    VictoryInput, VictoryResult, evaluate_victory_and_stackwipe
)

bin_path = ROOT.parent / 'base-game/v2game.exe'
data = bin_path.read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_32)

claims = []

# 1. Routine instructions (0x0059C630..0x0059C8A7)
raw_start = pe.get_offset_from_rva(0x0059C630 - base)
for insn in md.disasm(data[raw_start:raw_start + 700], 0x0059C630):
    claims.append({
        'id': f'combat_victory_insn_{insn.address:x}',
        'kind': 'instructions',
        'space': 'rva',
        'offset': hex(insn.address - base),
        'base': hex(insn.address),
        'arch': 'x86',
        'length': len(insn.bytes),
        'mnemonics': [insn.mnemonic],
        'operands': [insn.op_str]
    })
    if insn.address >= 0x0059C8A7:
        break

# 2. Vtable entries (CCombat, CLandCombat, CNavalCombat)
for vtable_va, vname in [
    (0x00E02174, 'CCombat'),
    (0x00E02384, 'CLandCombat'),
    (0x00E02464, 'CNavalCombat'),
]:
    v_raw = pe.get_offset_from_rva(vtable_va - base)
    target_ptr = int.from_bytes(data[v_raw:v_raw + 4], 'little')
    assert target_ptr == 0x0059C630
    claims.append({
        'id': f'combat_victory_vtable_{vname}',
        'kind': 'bytes_at',
        'space': 'rva',
        'offset': hex(vtable_va - base),
        'base': hex(vtable_va),
        'expected': (0x0059C630).to_bytes(4, 'little').hex()
    })


# Run Reverify
verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]

# Negative controls and dependent invalidation
wrong = dict(claims[0], id='negative_control_combat_victory', mnemonics=['nop'])
dependent = dict(claims[1], id='negative_dependent_combat_victory', depends_on=['negative_control_combat_victory'])
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

# Debug flag container at 0x12588E8
debug_ptr = heap + 0x1000
uc.mem_write(0x012588E8, struct.pack('<I', debug_ptr))
uc.mem_write(debug_ptr + 0xD11, b'\x00')

# Combat struct
combat = heap + 0x2000
attacker = heap + 0x3000
defender = heap + 0x4000
atk_vtable = heap + 0x3100
def_vtable = heap + 0x4100
uc.mem_write(combat + 0x10, struct.pack('<I', attacker))
uc.mem_write(combat + 0x14, struct.pack('<I', defender))
uc.mem_write(combat + 0x1C, struct.pack('<i', 100))

uc.mem_write(attacker, struct.pack('<I', atk_vtable))
uc.mem_write(defender, struct.pack('<I', def_vtable))

atk_has_morale = heap + 0x3200
def_has_morale = heap + 0x4200
atk_can_retreat = heap + 0x3300
def_can_retreat = heap + 0x4300

uc.mem_write(atk_vtable + 0x58, struct.pack('<I', atk_has_morale))
uc.mem_write(def_vtable + 0x58, struct.pack('<I', def_has_morale))
uc.mem_write(atk_vtable + 0x54, struct.pack('<I', atk_can_retreat))
uc.mem_write(def_vtable + 0x54, struct.pack('<I', def_can_retreat))

# Dynamic hook state
hook_state = {
    'att_str': 10000,
    'def_str': 10000,
    'att_morale': True,
    'def_morale': True,
    'att_retreat': True,
    'def_retreat': True,
    'winner': -1,
}

def hook_strength(uc_inst, address, size, user_data):
    esp = uc_inst.reg_read(UC_X86_REG_ESP)
    target_addr = struct.unpack('<I', uc_inst.mem_read(esp + 8, 4))[0]
    side_ptr = struct.unpack('<I', uc_inst.mem_read(esp + 4, 4))[0]
    if side_ptr == attacker + 0x20:
        val = hook_state['att_str']
    else:
        val = hook_state['def_str']
    uc_inst.mem_write(target_addr, struct.pack('<i', val))

uc.hook_add(UC_HOOK_CODE, hook_strength, begin=0x005DC0E0, end=0x005DC0E0)
uc.mem_write(0x005DC0E0, b'\xc2\x08\x00') # ret 8

def hook_atk_morale(uc_inst, address, size, user_data):
    uc_inst.reg_write(UC_X86_REG_EAX, 1 if hook_state['att_morale'] else 0)

def hook_def_morale(uc_inst, address, size, user_data):
    uc_inst.reg_write(UC_X86_REG_EAX, 1 if hook_state['def_morale'] else 0)

def hook_atk_ret(uc_inst, address, size, user_data):
    uc_inst.reg_write(UC_X86_REG_EAX, 1 if hook_state['att_retreat'] else 0)

def hook_def_ret(uc_inst, address, size, user_data):
    uc_inst.reg_write(UC_X86_REG_EAX, 1 if hook_state['def_retreat'] else 0)

def hook_conclude(uc_inst, address, size, user_data):
    esp = uc_inst.reg_read(UC_X86_REG_ESP)
    w = struct.unpack('<I', uc_inst.mem_read(esp + 8, 4))[0]
    hook_state['winner'] = w

uc.hook_add(UC_HOOK_CODE, hook_atk_morale, begin=atk_has_morale, end=atk_has_morale)
uc.mem_write(atk_has_morale, b'\xc3')
uc.hook_add(UC_HOOK_CODE, hook_def_morale, begin=def_has_morale, end=def_has_morale)
uc.mem_write(def_has_morale, b'\xc3')
uc.hook_add(UC_HOOK_CODE, hook_atk_ret, begin=atk_can_retreat, end=atk_can_retreat)
uc.mem_write(atk_can_retreat, b'\xc3')
uc.hook_add(UC_HOOK_CODE, hook_def_ret, begin=def_can_retreat, end=def_can_retreat)
uc.mem_write(def_can_retreat, b'\xc3')

uc.hook_add(UC_HOOK_CODE, hook_conclude, begin=0x005A0180, end=0x005A0180)
uc.mem_write(0x005A0180, b'\xc2\x08\x00') # ret 8

uc.mem_write(0x00595660, b'\xc2\x04\x00') # ret 4
uc.mem_write(0x00595760, b'\xc3') # ret 0


def run_victory_test(inp: VictoryInput):
    hook_state['att_str'] = inp.attacker_raw_strength
    hook_state['def_str'] = inp.defender_raw_strength
    hook_state['att_morale'] = inp.attacker_has_morale
    hook_state['def_morale'] = inp.defender_has_morale
    hook_state['att_retreat'] = inp.attacker_can_retreat
    hook_state['def_retreat'] = inp.defender_can_retreat
    hook_state['winner'] = -1

    uc.mem_write(debug_ptr + 0xD11, struct.pack('<B', 1 if inp.is_debug_pause else 0))
    uc.mem_write(combat + 0x1C, struct.pack('<i', inp.retreat_province_id))

    # Call 0x0059C630(ratio_threshold, check_can_retreat)
    check_flag = 1 if inp.check_can_retreat else 0
    uc.mem_write(stack_top - 12, struct.pack('<III', ret_stub, inp.ratio_threshold, check_flag))
    uc.reg_write(UC_X86_REG_ESP, stack_top - 12)
    uc.reg_write(UC_X86_REG_ECX, combat)

    uc.emu_start(0x0059C630, ret_stub)

    actual_ended = bool(uc.reg_read(UC_X86_REG_EAX) & 0xFF)
    actual_winner = hook_state['winner']

    model_res = evaluate_victory_and_stackwipe(inp)

    assert actual_ended == model_res.battle_ended, (
        f"battle_ended mismatch: got {actual_ended}, expected {model_res.battle_ended} for {inp}"
    )
    if actual_ended:
        assert actual_winner == model_res.winner_code, (
            f"winner mismatch: got {actual_winner}, expected {model_res.winner_code} for {inp}"
        )

    return model_res


fixtures_run = 0

# Test Case 1: Ongoing battle, both have morale, no conclusion
c1 = VictoryInput(attacker_raw_strength=10000, defender_raw_strength=10000)
r1 = run_victory_test(c1)
assert not r1.battle_ended
fixtures_run += 1

# Test Case 2: Defender collapsed, ratio 3:1 (> 2:1) -> 2:1 STACKWIPE!
c2 = VictoryInput(
    attacker_raw_strength=30000,
    defender_raw_strength=10000,
    defender_has_morale=False,
)
r2 = run_victory_test(c2)
assert r2.battle_ended and r2.winner == "attacker" and r2.defender_stackwiped
fixtures_run += 1

# Test Case 3: Defender collapsed, ratio 1.5:1 (< 2:1) with retreat available -> NO STACKWIPE
c3 = VictoryInput(
    attacker_raw_strength=15000,
    defender_raw_strength=10000,
    defender_has_morale=False,
    retreat_province_id=100,
)
r3 = run_victory_test(c3)
assert not r3.defender_stackwiped
fixtures_run += 1

# Test Case 4: Defender collapsed, ratio 1.5:1, but ENCIRCLED (-1) -> POCKET STACKWIPE!
c4 = VictoryInput(
    attacker_raw_strength=15000,
    defender_raw_strength=10000,
    defender_has_morale=False,
    retreat_province_id=-1,
)
r4 = run_victory_test(c4)
assert r4.battle_ended and r4.winner == "attacker" and r4.defender_stackwiped
fixtures_run += 1

# Test Case 5: Attacker collapsed, ratio 3:1 (> 2:1) -> Attacker STACKWIPED by Defender!
c5 = VictoryInput(
    attacker_raw_strength=10000,
    defender_raw_strength=30000,
    attacker_has_morale=False,
)
r5 = run_victory_test(c5)
assert r5.battle_ended and r5.winner == "defender" and r5.attacker_stackwiped
fixtures_run += 1

# Test Case 6: Attacker collapsed, encircled (-1) -> Attacker STACKWIPED!
c6 = VictoryInput(
    attacker_raw_strength=10000,
    defender_raw_strength=12000,
    attacker_has_morale=False,
    retreat_province_id=-1,
)
r6 = run_victory_test(c6)
assert r6.battle_ended and r6.winner == "defender" and r6.attacker_stackwiped
fixtures_run += 1

# Test Case 7: Instant Overrun by overwhelming ratio (10:1) with retreat gating
c7 = VictoryInput(
    attacker_raw_strength=100000,
    defender_raw_strength=5000,
    defender_has_morale=False,
    ratio_threshold=10,
    check_can_retreat=True,
    defender_can_retreat=True,
)
r7 = run_victory_test(c7)
assert r7.battle_ended and r7.winner == "attacker"
fixtures_run += 1

# Test Case 8: Retreat gated and cannot retreat -> victory delayed
c8 = VictoryInput(
    attacker_raw_strength=15000,
    defender_raw_strength=10000,
    defender_has_morale=False,
    ratio_threshold=10,
    check_can_retreat=True,
    defender_can_retreat=False,
)
r8 = run_victory_test(c8)
assert not r8.battle_ended
fixtures_run += 1

# Test Case 9: Debug pause flag active -> no resolution
c9 = VictoryInput(
    attacker_raw_strength=100000,
    defender_raw_strength=1000,
    defender_has_morale=False,
    is_debug_pause=True,
)
r9 = run_victory_test(c9)
assert not r9.battle_ended
fixtures_run += 1

# Comprehensive permutation sweep: varying strength ratios, morale states, encirclement
for att_s in [5000, 10000, 20000, 50000]:
    for def_s in [5000, 10000, 20000, 50000]:
        for def_mor in [True, False]:
            for encircled in [100, -1]:
                run_victory_test(VictoryInput(
                    attacker_raw_strength=att_s,
                    defender_raw_strength=def_s,
                    defender_has_morale=def_mor,
                    retreat_province_id=encircled,
                ))
                fixtures_run += 1

# Save receipts
out_dir = ROOT / 'evidence/generated/combat-victory-stackwipe'
out_dir.mkdir(parents=True, exist_ok=True)
(out_dir / 'claims.json').write_text(json.dumps(claims, indent=2) + '\n')
(out_dir / 'reverify.json').write_text(json.dumps(report, indent=2) + '\n')
(out_dir / 'negative-controls.json').write_text(json.dumps(controls, indent=2) + '\n')
(out_dir / 'emulation.json').write_text(json.dumps({
    'binary_sha256': digest,
    'routine_va': hex(0x0059C630),
    'fixtures_count': fixtures_run,
    'mismatches': 0
}, indent=2) + '\n')

ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify', file_path=str(bin_path))
ledger.start_run('Verify CCombat::EvaluateVictoryAndStackwipe routine and vtables', session='combat-victory-stackwipe')
ledger.record(report, rnd=1, session='combat-victory-stackwipe')
ledger.finish_run(1, report['grounded'], report['information'])
ledger.save()

print(f"Combat victory stackwipe: {len(report['results'])} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Combat victory stackwipe emulation: {fixtures_run} fixtures executed, 0 mismatches against combat_victory_stackwipe_model.")
