#!/usr/bin/env python3
"""Verify CLandCombatant::FindTargetRegiment against PE32 binary with Reverify and Unicorn.

Routine: 0x0059B610..0x0059B779 (364 bytes, 132 instructions).
Callers:
  - 0x0059A927 in CLandCombatant::ExecuteRegimentAttack.
  - 0x0059B01F, 0x0059B588 in tactical target resolution.
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
    UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_EAX, UC_X86_REG_EDI
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT / 'scripts'))
from combat_target_acquisition_model import find_target_regiment

bin_path = ROOT.parent / 'base-game/v2game.exe'
data = bin_path.read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_32)

claims = []

# 1. Routine instructions (0x0059B610..0x0059B779)
raw_start = pe.get_offset_from_rva(0x0059B610 - base)
for insn in md.disasm(data[raw_start:raw_start + 400], 0x0059B610):
    claims.append({
        'id': f'combat_target_insn_{insn.address:x}',
        'kind': 'instructions',
        'space': 'rva',
        'offset': hex(insn.address - base),
        'base': hex(insn.address),
        'arch': 'x86',
        'length': len(insn.bytes),
        'mnemonics': [insn.mnemonic],
        'operands': [insn.op_str]
    })
    if insn.address >= 0x0059B779:
        break

# 2. Callers across engine
for caller_va in [0x0059A927, 0x0059B01F, 0x0059B588]:
    caller_raw = pe.get_offset_from_rva(caller_va - base)
    caller_insn = list(md.disasm(data[caller_raw:caller_raw + 10], caller_va))[0]
    claims.append({
        'id': f'combat_target_caller_{caller_va:x}',
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
wrong = dict(claims[0], id='negative_control_combat_target', mnemonics=['nop'])
dependent = dict(claims[1], id='negative_dependent_combat_target', depends_on=['negative_control_combat_target'])
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

# CRT hooks for floor and ftol2
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
uc.mem_write(0x00401000, b"\xc3")
uc.mem_write(0x00B31C00, b"\xc3")

heap_base = 0x02000000
uc.mem_map(heap_base, 0x200000, UC_PROT_ALL)

ret_stub = heap_base + 0x500
uc.mem_write(ret_stub, b"\x90")

stack_top = heap_base + 0x100000
target_combatant = heap_base + 0x10000

# Helper to allocate unit pointers
unit_pool = {}
for uid in range(1, 100):
    u_addr = heap_base + 0x20000 + uid * 0x100
    unit_pool[uid] = u_addr

def run_target_test(front_spec, back_spec, attacker_col, maneuver):
    # front_spec / back_spec: list of dict(uid=..., strength=..., org=...) or None
    uc.mem_write(target_combatant, b"\x00" * 0x300)

    front_model = [None] * 32
    back_model = [None] * 32
    ptr_to_key = {}

    for i in range(32):
        if i < len(front_spec) and front_spec[i]:
            info = front_spec[i]
            p = unit_pool[info['uid']]
            uc.mem_write(p + 0x3C, struct.pack('<i', info['strength']))
            uc.mem_write(p + 0x40, struct.pack('<i', info['org']))
            uc.mem_write(target_combatant + i * 4 + 0x6C, struct.pack('<I', p))
            front_model[i] = info
            ptr_to_key[p] = ('front', i)

        if i < len(back_spec) and back_spec[i]:
            info = back_spec[i]
            p = unit_pool[info['uid']]
            uc.mem_write(p + 0x3C, struct.pack('<i', info['strength']))
            uc.mem_write(p + 0x40, struct.pack('<i', info['org']))
            uc.mem_write(target_combatant + i * 4 + 0xEC, struct.pack('<I', p))
            back_model[i] = info
            ptr_to_key[p] = ('back', i)

    # Call 0x0059B610
    uc.mem_write(stack_top - 12, struct.pack('<III', ret_stub, target_combatant, attacker_col))
    uc.reg_write(UC_X86_REG_ESP, stack_top - 12)
    uc.reg_write(UC_X86_REG_EAX, maneuver)

    uc.emu_start(0x0059B610, ret_stub)
    res_ptr = uc.reg_read(UC_X86_REG_EAX)

    res_key = ptr_to_key.get(res_ptr, None)
    expected_key = find_target_regiment(front_model, back_model, attacker_col, maneuver)

    assert res_key == expected_key, (
        f"Target mismatch for col={attacker_col}, man={maneuver}: got {res_key}, expected {expected_key}"
    )
    return res_key

fixtures_run = 0
emu_results = []

# Systematic test cases covering all 5 phases
# 1. Phase 1: Direct front operational
f1 = [None] * 32
f1[15] = {'uid': 1, 'strength': 3000, 'org': 30000}
r = run_target_test(f1, [None]*32, 15, 1)
assert r == ('front', 15)
fixtures_run += 1

# 2. Phase 1 rejected (strength < 100) -> falls to phase 2
f2 = [None] * 32
f2[15] = {'uid': 1, 'strength': 90, 'org': 30000} # low strength (< 100)
f2[16] = {'uid': 2, 'strength': 1000, 'org': 20000}
r = run_target_test(f2, [None]*32, 15, 1)
assert r == ('front', 16)
fixtures_run += 1

# 3. Phase 1 rejected (org < 1000) -> falls to phase 2
f3 = [None] * 32
f3[15] = {'uid': 1, 'strength': 2000, 'org': 990} # low org (< 1000)
f3[14] = {'uid': 2, 'strength': 1000, 'org': 20000}
r = run_target_test(f3, [None]*32, 15, 1)
assert r == ('front', 14)
fixtures_run += 1

# 4. Phase 2: Flanking left vs right preference
# In scan from left_bound (col-maneuver) to right_bound (col+maneuver):
# Leftmost valid target is picked first!
f4 = [None] * 32
f4[14] = {'uid': 1, 'strength': 1000, 'org': 20000} # left
f4[16] = {'uid': 2, 'strength': 1000, 'org': 20000} # right
r = run_target_test(f4, [None]*32, 15, 1)
assert r == ('front', 14) # scans col-1=14 before col+1=16!
fixtures_run += 1

# 5. Phase 2: Maneuver range limits
f5 = [None] * 32
f5[18] = {'uid': 1, 'strength': 1000, 'org': 20000} # col 18 (distance 3 from 15)
# maneuver 1 cannot reach col 18
assert run_target_test(f5, [None]*32, 15, 1) is None
fixtures_run += 1
# maneuver 2 cannot reach col 18
assert run_target_test(f5, [None]*32, 15, 2) is None
fixtures_run += 1
# maneuver 3 REACHES col 18!
assert run_target_test(f5, [None]*32, 15, 3) == ('front', 18)
fixtures_run += 1

# 6. Phase 3: Direct backline artillery
b6 = [None] * 32
b6[15] = {'uid': 10, 'strength': 3000, 'org': 30000}
r = run_target_test([None]*32, b6, 15, 1)
assert r == ('back', 15)
fixtures_run += 1

# 7. Phase 4: Flanking into backline
b7 = [None] * 32
b7[17] = {'uid': 11, 'strength': 3000, 'org': 30000}
r = run_target_test([None]*32, b7, 15, 2)
assert r == ('back', 17)
fixtures_run += 1

# 8. Phase 5: Complete miss (empty field or out of bounds)
r = run_target_test([None]*32, [None]*32, 15, 5)
assert r is None
fixtures_run += 1

# Comprehensive permutation sweep across columns and maneuver distances
for atk_c in [1, 5, 10, 15, 20, 25, 29]:
    for man in [1, 2, 3, 4, 5]:
        f_p = [None] * 32
        b_p = [None] * 32
        # Place targets at varied distances
        if atk_c + 2 < 31:
            f_p[atk_c + 2] = {'uid': 20, 'strength': 1500, 'org': 15000}
        if atk_c - 1 >= 0:
            b_p[atk_c - 1] = {'uid': 30, 'strength': 2500, 'org': 25000}
        res = run_target_test(f_p, b_p, atk_c, man)
        exp = find_target_regiment(f_p, b_p, atk_c, man)
        assert res == exp
        fixtures_run += 1

# Save receipts
out_dir = ROOT / 'evidence/generated/combat-target-acquisition'
out_dir.mkdir(parents=True, exist_ok=True)
(out_dir / 'claims.json').write_text(json.dumps(claims, indent=2) + '\n')
(out_dir / 'reverify.json').write_text(json.dumps(report, indent=2) + '\n')
(out_dir / 'negative-controls.json').write_text(json.dumps(controls, indent=2) + '\n')
(out_dir / 'emulation.json').write_text(json.dumps({
    'binary_sha256': digest,
    'routine_va': hex(0x0059B610),
    'fixtures_count': fixtures_run,
    'mismatches': 0
}, indent=2) + '\n')

ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify', file_path=str(bin_path))
ledger.start_run('Verify CLandCombatant::FindTargetRegiment routine and callers', session='combat-target-acquisition')
ledger.record(report, rnd=1, session='combat-target-acquisition')
ledger.finish_run(1, report['grounded'], report['information'])
ledger.save()

print(f"Combat target acquisition: {len(report['results'])} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Combat target acquisition emulation: {fixtures_run} fixtures executed, 0 mismatches against combat_target_acquisition_model.")
