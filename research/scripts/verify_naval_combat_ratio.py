#!/usr/bin/env python3
"""Verify CNavalCombat::CalculateForceRatio against PE32 binary with Reverify and Unicorn.

Routine: 0x005AB710..0x005AB75F (80 bytes, 29 instructions).
Vtable slot 6 (+0x18): 0x00E02450 in CNavalCombat vtable (0x00E02438).
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
from naval_combat_ratio_model import calculate_naval_force_ratio

bin_path = ROOT.parent / 'base-game/v2game.exe'
data = bin_path.read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_32)

claims = []

# 1. Routine instructions (0x005AB710..0x005AB75F)
raw_start = pe.get_offset_from_rva(0x005AB710 - base)
for insn in md.disasm(data[raw_start:raw_start + 100], 0x005AB710):
    claims.append({
        'id': f'naval_combat_ratio_insn_{insn.address:x}',
        'kind': 'instructions',
        'space': 'rva',
        'offset': hex(insn.address - base),
        'base': hex(insn.address),
        'arch': 'x86',
        'length': len(insn.bytes),
        'mnemonics': [insn.mnemonic],
        'operands': [insn.op_str]
    })
    if insn.address >= 0x005AB75F:
        break

# 2. Vtable slot 6 (+0x18) in CNavalCombat at 0x00E02450
vtable_va = 0x00E02450
v_raw = pe.get_offset_from_rva(vtable_va - base)
target_ptr = int.from_bytes(data[v_raw:v_raw + 4], 'little')
assert target_ptr == 0x005AB710
claims.append({
    'id': 'naval_combat_ratio_vtable_CNavalCombat',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(vtable_va - base),
    'base': hex(vtable_va),
    'expected': (0x005AB710).to_bytes(4, 'little').hex()
})

# Run Reverify
verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]

# Negative controls and dependent invalidation
wrong = dict(claims[0], id='negative_control_naval_combat_ratio', mnemonics=['nop'])
dependent = dict(claims[1], id='negative_dependent_naval_combat_ratio', depends_on=['negative_control_naval_combat_ratio'])
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
COMBAT_ADDR = SCRATCH_BASE + 0x1000
PROV_ADDR = SCRATCH_BASE + 0x2000
OUT_RATIO_ADDR = SCRATCH_BASE + 0x3000

# Wire pointers
uc.mem_write(COMBAT_ADDR + 0x18, struct.pack('<I', PROV_ADDR))


def run_naval_ratio_test(sea_penalty: int) -> int:
    uc.mem_write(PROV_ADDR + 0x114, struct.pack('<i', sea_penalty))
    uc.mem_write(OUT_RATIO_ADDR, struct.pack('<i', -999))

    ret_addr = SCRATCH_BASE + 0x70000
    # Push arguments: [esp] = ret_addr, [esp + 4] = OUT_RATIO_ADDR
    uc.mem_write(STACK_BASE - 8, struct.pack('<II', ret_addr, OUT_RATIO_ADDR))
    uc.reg_write(UC_X86_REG_ESP, STACK_BASE - 8)
    uc.reg_write(UC_X86_REG_ECX, COMBAT_ADDR)

    uc.emu_start(0x005AB710, ret_addr)

    ret_ptr = uc.reg_read(UC_X86_REG_EAX)
    assert ret_ptr == OUT_RATIO_ADDR

    res = struct.unpack('<i', uc.mem_read(OUT_RATIO_ADDR, 4))[0]
    expected = calculate_naval_force_ratio(sea_penalty)
    assert res == expected, (
        f"Mismatch: penalty={sea_penalty}, emu={res}, expected={expected}"
    )
    return res


fixtures_run = 0

# Case 1: Zero sea penalty -> 1000 (100.0%)
assert run_naval_ratio_test(0) == 1000
fixtures_run += 1

# Case 2: 20% penalty (20,000) -> 800 (80.0%)
assert run_naval_ratio_test(20000) == 800
fixtures_run += 1

# Case 3: 50% penalty (50,000) -> 500 (50.0%)
assert run_naval_ratio_test(50000) == 500
fixtures_run += 1

# Case 4: 100% penalty (100,000) -> 0 (0.0%)
assert run_naval_ratio_test(100000) == 0
fixtures_run += 1

# Case 5: 120% penalty (120,000) -> -200 (-20.0%)
assert run_naval_ratio_test(120000) == -200
fixtures_run += 1

# Case 6: Fractional penalties testing truncation (e.g. 15,450 -> truncated to 15,000)
assert run_naval_ratio_test(15450) == 850
fixtures_run += 1

# Case 7: Small fraction below 1000 (e.g. 750 -> truncated to 0) -> 1000
assert run_naval_ratio_test(750) == 1000
fixtures_run += 1

# Case 8: Negative penalty (favorable sea condition, e.g. -10,000) -> 1100 (110.0%)
assert run_naval_ratio_test(-10000) == 1100
fixtures_run += 1

# Comprehensive parametric sweep
for p in range(-20000, 120000, 5000):
    run_naval_ratio_test(p)
    fixtures_run += 1

# Save receipts
out_dir = ROOT / 'evidence/generated/naval-combat-ratio'
out_dir.mkdir(parents=True, exist_ok=True)
(out_dir / 'claims.json').write_text(json.dumps(claims, indent=2) + '\n')
(out_dir / 'reverify.json').write_text(json.dumps(report, indent=2) + '\n')
(out_dir / 'negative-controls.json').write_text(json.dumps(controls, indent=2) + '\n')
(out_dir / 'emulation.json').write_text(json.dumps({
    'binary_sha256': digest,
    'routine_va': hex(0x005AB710),
    'fixtures_count': fixtures_run,
    'mismatches': 0
}, indent=2) + '\n')

ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify', file_path=str(bin_path))
ledger.start_run('Verify CNavalCombat::CalculateForceRatio routine and vtables', session='naval-combat-ratio')
ledger.record(report, rnd=1, session='naval-combat-ratio')
ledger.finish_run(1, report['grounded'], report['information'])
ledger.save()

print(f"Naval combat ratio: {len(report['results'])} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Naval combat ratio emulation: {fixtures_run} fixtures executed, 0 mismatches against naval_combat_ratio_model.")
