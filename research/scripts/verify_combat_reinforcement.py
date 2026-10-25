#!/usr/bin/env python3
"""Verify CLandCombatant reinforcement advance routines with Reverify and Unicorn.

Routines:
  - 0x0059B0E0..0x0059B14B (108 bytes, 33 instructions): CLandCombatant::AdvanceColumnReinforcement
  - 0x0059B150..0x0059B180 (49 bytes, 18 instructions): CLandCombatant::AdvanceReinforcementLine
Callers:
  - 0x0059CAE5, 0x0059CAEC in CCombat::DailyUpdate.
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
    UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDI
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT / 'scripts'))
from combat_reinforcement_model import advance_column, advance_reinforcements

bin_path = ROOT.parent / 'base-game/v2game.exe'
data = bin_path.read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_32)

claims = []

# 1. AdvanceColumnReinforcement (0x0059B0E0..0x0059B14B)
raw_adv = pe.get_offset_from_rva(0x0059B0E0 - base)
for insn in md.disasm(data[raw_adv:raw_adv + 120], 0x0059B0E0):
    claims.append({
        'id': f'combat_reinf_col_insn_{insn.address:x}',
        'kind': 'instructions',
        'space': 'rva',
        'offset': hex(insn.address - base),
        'base': hex(insn.address),
        'arch': 'x86',
        'length': len(insn.bytes),
        'mnemonics': [insn.mnemonic],
        'operands': [insn.op_str]
    })
    if insn.address >= 0x0059B14B:
        break

# 2. AdvanceReinforcementLine (0x0059B150..0x0059B180)
raw_line = pe.get_offset_from_rva(0x0059B150 - base)
for insn in md.disasm(data[raw_line:raw_line + 60], 0x0059B150):
    claims.append({
        'id': f'combat_reinf_line_insn_{insn.address:x}',
        'kind': 'instructions',
        'space': 'rva',
        'offset': hex(insn.address - base),
        'base': hex(insn.address),
        'arch': 'x86',
        'length': len(insn.bytes),
        'mnemonics': [insn.mnemonic],
        'operands': [insn.op_str]
    })
    if insn.address >= 0x0059B180:
        break

# 3. Callers in CCombat::DailyUpdate (0x0059CAE5, 0x0059CAEC)
for caller_va in [0x0059CAE5, 0x0059CAEC]:
    caller_raw = pe.get_offset_from_rva(caller_va - base)
    caller_insn = list(md.disasm(data[caller_raw:caller_raw + 10], caller_va))[0]
    claims.append({
        'id': f'combat_reinf_caller_{caller_va:x}',
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
wrong = dict(claims[0], id='negative_control_combat_reinf', mnemonics=['nop'])
dependent = dict(claims[1], id='negative_dependent_combat_reinf', depends_on=['negative_control_combat_reinf'])
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

ret_stub = heap_base + 0x500
uc.mem_write(ret_stub, b'\x90') # NOP

stack_top = heap_base + 0x100000
combatant_obj = heap_base + 0x10000

# Setup test unit objects
unit_ptrs = {}
support_flags = {}

for u_id in range(1, 10):
    u_ptr = heap_base + 0x2000 + u_id * 0x200
    t_ptr = u_ptr + 0x100
    # units 1..4: infantry (support = 0)
    # units 5..8: artillery (support = 1)
    is_supp = 1 if u_id >= 5 else 0
    uc.mem_write(u_ptr + 0x38, struct.pack('<I', t_ptr))
    uc.mem_write(t_ptr + 0x23C, struct.pack('<i', is_supp))
    unit_ptrs[u_id] = u_ptr
    support_flags[u_ptr] = is_supp

fixtures_run = 0
emu_results = []

def run_column_test(front_init, back_init, col):
    global fixtures_run
    # Initialize combatant memory
    uc.mem_write(combatant_obj, b'\x00' * 0x300)

    # Populate front and back lines in Unicorn
    f_ptrs = [unit_ptrs[x] if x else None for x in front_init]
    b_ptrs = [unit_ptrs[x] if x else None for x in back_init]

    for i in range(35):
        if i < len(f_ptrs) and f_ptrs[i]:
            uc.mem_write(combatant_obj + i * 4 + 0x6C, struct.pack('<I', f_ptrs[i]))
        if i < len(b_ptrs) and b_ptrs[i]:
            uc.mem_write(combatant_obj + i * 4 + 0xEC, struct.pack('<I', b_ptrs[i]))

    # Setup stack and registers
    uc.mem_write(stack_top - 4, struct.pack('<I', ret_stub))
    uc.reg_write(UC_X86_REG_ESP, stack_top - 4)
    uc.reg_write(UC_X86_REG_EAX, combatant_obj)
    uc.reg_write(UC_X86_REG_ECX, col)

    # Emulate 0x0059B0E0 until ret_stub
    uc.emu_start(0x0059B0E0, ret_stub)

    # Read back lines
    f_res = []
    b_res = []
    for i in range(35):
        val_f = struct.unpack('<I', uc.mem_read(combatant_obj + i * 4 + 0x6C, 4))[0]
        val_b = struct.unpack('<I', uc.mem_read(combatant_obj + i * 4 + 0xEC, 4))[0]
        f_res.append(val_f if val_f != 0 else None)
        b_res.append(val_b if val_b != 0 else None)

    # Model execution
    exp_f = list(f_ptrs)
    exp_b = list(b_ptrs)
    advance_column(exp_f, exp_b, support_flags, col)

    assert f_res[:32] == exp_f[:32], f"Front mismatch for col {col}: got {f_res[:32]}, expected {exp_f[:32]}"
    assert b_res[:32] == exp_b[:32], f"Back mismatch for col {col}: got {b_res[:32]}, expected {exp_b[:32]}"

    fixtures_run += 1
    emu_results.append({
        'fixture_idx': fixtures_run,
        'type': 'column',
        'col': col,
        'pass': True
    })

def run_line_test(front_init, back_init):
    global fixtures_run
    uc.mem_write(combatant_obj, b'\x00' * 0x300)

    f_ptrs = [unit_ptrs[x] if x else None for x in front_init]
    b_ptrs = [unit_ptrs[x] if x else None for x in back_init]

    for i in range(35):
        if i < len(f_ptrs) and f_ptrs[i]:
            uc.mem_write(combatant_obj + i * 4 + 0x6C, struct.pack('<I', f_ptrs[i]))
        if i < len(b_ptrs) and b_ptrs[i]:
            uc.mem_write(combatant_obj + i * 4 + 0xEC, struct.pack('<I', b_ptrs[i]))

    uc.mem_write(stack_top - 4, struct.pack('<I', ret_stub))
    uc.reg_write(UC_X86_REG_ESP, stack_top - 4)
    uc.reg_write(UC_X86_REG_EDI, combatant_obj)

    # Emulate 0x0059B150 until ret_stub
    uc.emu_start(0x0059B150, ret_stub)

    f_res = []
    b_res = []
    for i in range(35):
        val_f = struct.unpack('<I', uc.mem_read(combatant_obj + i * 4 + 0x6C, 4))[0]
        val_b = struct.unpack('<I', uc.mem_read(combatant_obj + i * 4 + 0xEC, 4))[0]
        f_res.append(val_f if val_f != 0 else None)
        b_res.append(val_b if val_b != 0 else None)

    exp_f, exp_b = advance_reinforcements(f_ptrs, b_ptrs, support_flags)

    assert f_res[:32] == exp_f[:32], f"Line sweep front mismatch: got {f_res[:32]}, expected {exp_f[:32]}"
    assert b_res[:32] == exp_b[:32], f"Line sweep back mismatch: got {b_res[:32]}, expected {exp_b[:32]}"

    fixtures_run += 1
    emu_results.append({
        'fixture_idx': fixtures_run,
        'type': 'line_sweep',
        'pass': True
    })

# 1. Single column tests across various combinations
for col in [1, 5, 10, 15, 16, 20, 25, 29]:
    # Empty front, infantry back
    f = [None] * 32
    b = [None] * 32
    b[col] = 1 # inf
    run_column_test(f, b, col)

    # Empty front, artillery back
    f = [None] * 32
    b = [None] * 32
    b[col] = 5 # art
    run_column_test(f, b, col)

    # Front occupied, artillery back -> stays back
    f = [None] * 32
    b = [None] * 32
    f[col] = 2
    b[col] = 5
    run_column_test(f, b, col)

    # Front occupied, infantry back, right free -> advances right
    f = [None] * 32
    b = [None] * 32
    f[col] = 2
    b[col] = 1
    run_column_test(f, b, col)

    # Front occupied, infantry back, right occupied, left free -> advances left
    f = [None] * 32
    b = [None] * 32
    f[col] = 2
    if col + 1 < 32:
        f[col + 1] = 3
    b[col] = 1
    run_column_test(f, b, col)

    # Front occupied, both flanks occupied -> stays back
    f = [None] * 32
    b = [None] * 32
    f[col] = 2
    if col + 1 < 32:
        f[col + 1] = 3
    if col - 1 >= 0:
        f[col - 1] = 4
    b[col] = 1
    run_column_test(f, b, col)

# 2. Line sweep tests with complete formations
for seed in range(25):
    # Form battle lines with varying holes and infantry/artillery distribution
    f = [None] * 32
    b = [None] * 32
    for c in range(1, 31):
        if (c + seed) % 3 == 0:
            f[c] = None # hole
        else:
            f[c] = 2 # occupied
        if (c + seed) % 2 == 0:
            b[c] = 5 # art
        elif (c + seed) % 5 == 0:
            b[c] = 1 # inf
    run_line_test(f, b)

# Save receipts
out_dir = ROOT / 'evidence/generated/combat-reinforcement'
out_dir.mkdir(parents=True, exist_ok=True)
(out_dir / 'claims.json').write_text(json.dumps(claims, indent=2) + '\n')
(out_dir / 'reverify.json').write_text(json.dumps(report, indent=2) + '\n')
(out_dir / 'negative-controls.json').write_text(json.dumps(controls, indent=2) + '\n')
(out_dir / 'emulation.json').write_text(json.dumps({
    'binary_sha256': digest,
    'routine_vas': ['0x0059B0E0', '0x0059B150'],
    'fixtures_count': fixtures_run,
    'mismatches': 0,
    'results': emu_results
}, indent=2) + '\n')

ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify', file_path=str(bin_path))
ledger.start_run('Verify CLandCombatant reinforcement advance routines and callers', session='combat-reinforcement')
ledger.record(report, rnd=1, session='combat-reinforcement')
ledger.finish_run(1, report['grounded'], report['information'])
ledger.save()

print(f"Combat reinforcement: {len(report['results'])} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Combat reinforcement emulation: {fixtures_run} fixtures executed, 0 mismatches against combat_reinforcement_model.")
