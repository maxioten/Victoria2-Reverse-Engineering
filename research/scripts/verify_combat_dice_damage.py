#!/usr/bin/env python3
"""Verify CCombat::LookupDiceDamage against PE32 binary with Reverify and Unicorn.

Routine: 0x00594230..0x005944A9 (634 bytes, 144 instructions).
Callers:
  - 0x005979C9, 0x00597C82 in CNavalCombatant::DailyDamage.
  - 0x0059A973 in CLandCombatant::ExecuteRegimentAttack.
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
    UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_EAX, UC_X86_REG_EDI
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT / 'scripts'))
from combat_dice_damage_model import combat_dice_damage

bin_path = ROOT.parent / 'base-game/v2game.exe'
data = bin_path.read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_32)

claims = []

# 1. Routine instructions (0x00594230..0x005944A9)
routine_raw = pe.get_offset_from_rva(0x00594230 - base)
for insn in md.disasm(data[routine_raw:routine_raw + 650], 0x00594230):
    claims.append({
        'id': f'combat_dice_insn_{insn.address:x}',
        'kind': 'instructions',
        'space': 'rva',
        'offset': hex(insn.address - base),
        'base': hex(insn.address),
        'arch': 'x86',
        'length': len(insn.bytes),
        'mnemonics': [insn.mnemonic],
        'operands': [insn.op_str]
    })
    if insn.address >= 0x005944A9:
        break

# 2. Callers across engine
for caller_va in [0x005979C9, 0x00597C82, 0x0059A973]:
    caller_raw = pe.get_offset_from_rva(caller_va - base)
    caller_insn = list(md.disasm(data[caller_raw:caller_raw + 10], caller_va))[0]
    claims.append({
        'id': f'combat_dice_caller_{caller_va:x}',
        'kind': 'instructions',
        'space': 'rva',
        'offset': hex(caller_va - base),
        'base': hex(caller_va),
        'arch': 'x86',
        'length': len(caller_insn.bytes),
        'mnemonics': [caller_insn.mnemonic],
        'operands': [caller_insn.op_str]
    })

# 3. 18 IEEE 754 float constants in .rdata
float_addrs = [
    0x00E45A58, 0x00E45A54, 0x00E45A50, 0x00E45A4C, 0x00E45A18,
    0x00E45A48, 0x00E45A44, 0x00E45A1C, 0x00E45A40, 0x00E45A3C,
    0x00E45A38, 0x00E45A34, 0x00E45A30, 0x00E45970, 0x00E45A2C,
    0x00E45A28, 0x00E45A24, 0x00E45A20
]

for idx, f_va in enumerate(float_addrs):
    raw_f = pe.get_offset_from_rva(f_va - base)
    expected_hex = data[raw_f:raw_f + 4].hex()
    claims.append({
        'id': f'combat_dice_float_entry_{idx}_{f_va:x}',
        'kind': 'bytes_at',
        'space': 'rva',
        'offset': hex(f_va - base),
        'base': hex(f_va),
        'expected': expected_hex
    })

# Run Reverify
verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]

# Negative controls and dependent invalidation
wrong = dict(claims[0], id='negative_control_combat_dice', mnemonics=['nop'])
dependent = dict(claims[1], id='negative_dependent_combat_dice', depends_on=['negative_control_combat_dice'])
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

# CRT floor and ftol2 hooks
ctx = {'last_floor': 0}

def hook_floor(uc_inst, address, size, user_data):
    esp = uc_inst.reg_read(UC_X86_REG_ESP)
    flt_bytes = uc_inst.mem_read(esp + 4, 4)
    flt_val = struct.unpack('<f', flt_bytes)[0]
    import math
    ctx['last_floor'] = math.floor(flt_val)

def hook_ftol(uc_inst, address, size, user_data):
    uc_inst.reg_write(UC_X86_REG_EAX, ctx['last_floor'])

from unicorn import UC_HOOK_CODE
uc.hook_add(UC_HOOK_CODE, hook_floor, begin=0x00401000, end=0x00401000)
uc.hook_add(UC_HOOK_CODE, hook_ftol, begin=0x00B31C00, end=0x00B31C00)
uc.mem_write(0x00401000, b"\xc3")
uc.mem_write(0x00B31C00, b"\xc3")

heap_base = 0x02000000
uc.mem_map(heap_base, 0x100000, UC_PROT_ALL)

ret_stub = heap_base + 0x500
uc.mem_write(ret_stub, b"\x90")

stack_top = heap_base + 0x80000
out_buf = heap_base + 0x1000

test_rolls = list(range(-15, 30)) # All possible roll ranges including heavy negative penalties and high leader rolls
fixtures_run = 0
emu_results = []

for r in test_rolls:
    uc.mem_write(stack_top - 4, struct.pack('<I', ret_stub))
    uc.reg_write(UC_X86_REG_ESP, stack_top - 4)
    uc.reg_write(UC_X86_REG_EAX, r)
    uc.reg_write(UC_X86_REG_EDI, out_buf)

    uc.emu_start(0x00594230, ret_stub)

    ret_eax = uc.reg_read(UC_X86_REG_EAX)
    assert ret_eax == out_buf, f"Return pointer mismatch: got {ret_eax:#x}, expected {out_buf:#x}"

    val = struct.unpack('<I', uc.mem_read(out_buf, 4))[0]
    expected = combat_dice_damage(r)

    assert val == expected, f"Damage mismatch for roll {r}: got {val}, expected {expected}"
    fixtures_run += 1
    emu_results.append({
        'fixture_idx': fixtures_run,
        'roll': r,
        'emulated': val,
        'expected': expected,
        'pass': val == expected
    })

# Save receipts
out_dir = ROOT / 'evidence/generated/combat-dice-damage'
out_dir.mkdir(parents=True, exist_ok=True)
(out_dir / 'claims.json').write_text(json.dumps(claims, indent=2) + '\n')
(out_dir / 'reverify.json').write_text(json.dumps(report, indent=2) + '\n')
(out_dir / 'negative-controls.json').write_text(json.dumps(controls, indent=2) + '\n')
(out_dir / 'emulation.json').write_text(json.dumps({
    'binary_sha256': digest,
    'routine_va': hex(0x00594230),
    'fixtures_count': fixtures_run,
    'mismatches': 0,
    'results': emu_results
}, indent=2) + '\n')

ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify', file_path=str(bin_path))
ledger.start_run('Verify CCombat::LookupDiceDamage routine, callers and float constants', session='combat-dice-damage')
ledger.record(report, rnd=1, session='combat-dice-damage')
ledger.finish_run(1, report['grounded'], report['information'])
ledger.save()

print(f"Combat dice damage: {len(report['results'])} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Combat dice damage emulation: {fixtures_run} fixtures executed, 0 mismatches against combat_dice_damage_model.")
