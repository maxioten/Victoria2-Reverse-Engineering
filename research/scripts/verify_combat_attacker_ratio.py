#!/usr/bin/env python3
"""Verify CCombat::CalculateAttackerStrengthRatio against PE32 binary with Reverify and Unicorn.

Routine: 0x0059C460..0x0059C51B (188 bytes, 79 instructions).
Vtable slot 6 (+0x18):
  - 0x00E02160 in CCombat vtable.
  - 0x00E02370 in CLandCombat vtable.
  - 0x00E023E0 in DerivedCombat vtable.
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
from combat_attacker_ratio_model import (
    AttackerRatioInput, calculate_attacker_strength_ratio
)

bin_path = ROOT.parent / 'base-game/v2game.exe'
data = bin_path.read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_32)

claims = []

# 1. Routine instructions (0x0059C460..0x0059C51B)
raw_start = pe.get_offset_from_rva(0x0059C460 - base)
for insn in md.disasm(data[raw_start:raw_start + 250], 0x0059C460):
    claims.append({
        'id': f'combat_attacker_ratio_insn_{insn.address:x}',
        'kind': 'instructions',
        'space': 'rva',
        'offset': hex(insn.address - base),
        'base': hex(insn.address),
        'arch': 'x86',
        'length': len(insn.bytes),
        'mnemonics': [insn.mnemonic],
        'operands': [insn.op_str]
    })
    if insn.address >= 0x0059C51B:
        break

# 2. Vtable entries (CCombat, CLandCombat, DerivedCombat)
for vtable_slot_va, vname in [
    (0x00E02160, 'CCombat'),
    (0x00E02370, 'CLandCombat'),
    (0x00E023E0, 'DerivedCombat'),
]:
    v_raw = pe.get_offset_from_rva(vtable_slot_va - base)
    target_ptr = int.from_bytes(data[v_raw:v_raw + 4], 'little')
    assert target_ptr == 0x0059C460
    claims.append({
        'id': f'combat_attacker_ratio_vtable_{vname}',
        'kind': 'bytes_at',
        'space': 'rva',
        'offset': hex(vtable_slot_va - base),
        'base': hex(vtable_slot_va),
        'expected': (0x0059C460).to_bytes(4, 'little').hex()
    })

# 3. Float constant at 0x00F141C8 (1.5)
const_raw = pe.get_offset_from_rva(0x00F141C8 - base)
claims.append({
    'id': 'combat_attacker_ratio_const_1_5',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00F141C8 - base),
    'base': hex(0x00F141C8),
    'expected': struct.pack('<f', 1.5).hex()
})

# Run Reverify
verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]

# Negative controls and dependent invalidation
wrong = dict(claims[0], id='negative_control_attacker_ratio', mnemonics=['nop'])
dependent = dict(claims[1], id='negative_dependent_attacker_ratio', depends_on=['negative_control_attacker_ratio'])
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
ATTACKER_ADDR = SCRATCH_BASE + 0x2000
DEFENDER_ADDR = SCRATCH_BASE + 0x3000
VTABLE_ATT_ADDR = SCRATCH_BASE + 0x4000
VTABLE_DEF_ADDR = SCRATCH_BASE + 0x5000
STUB_ATT_CODE = SCRATCH_BASE + 0x6000
STUB_DEF_CODE = SCRATCH_BASE + 0x7000
OUT_RATIO_ADDR = SCRATCH_BASE + 0x8000

VAL_ATT_PTR = SCRATCH_BASE + 0x9000
VAL_DEF_PTR = SCRATCH_BASE + 0x9004

# Wire combat object
uc.mem_write(COMBAT_ADDR + 0x10, struct.pack('<I', ATTACKER_ADDR))
uc.mem_write(COMBAT_ADDR + 0x14, struct.pack('<I', DEFENDER_ADDR))
uc.mem_write(ATTACKER_ADDR, struct.pack('<I', VTABLE_ATT_ADDR))
uc.mem_write(DEFENDER_ADDR, struct.pack('<I', VTABLE_DEF_ADDR))
uc.mem_write(VTABLE_ATT_ADDR + 0x28, struct.pack('<I', STUB_ATT_CODE))
uc.mem_write(VTABLE_DEF_ADDR + 0x28, struct.pack('<I', STUB_DEF_CODE))

# Synthetic stubs for GetTotalRawStrength(&out_val)
# mov edx, [esp + 4]
# mov eax, [VAL_ATT_PTR]
# mov [edx], eax
# ret 4
stub_att_bytes = bytes([
    0x8B, 0x54, 0x24, 0x04,              # mov edx, [esp + 4]
    0xA1, *struct.pack('<I', VAL_ATT_PTR), # mov eax, [VAL_ATT_PTR]
    0x89, 0x02,                          # mov [edx], eax
    0xC2, 0x04, 0x00                     # ret 4
])
stub_def_bytes = bytes([
    0x8B, 0x54, 0x24, 0x04,              # mov edx, [esp + 4]
    0xA1, *struct.pack('<I', VAL_DEF_PTR), # mov eax, [VAL_DEF_PTR]
    0x89, 0x02,                          # mov [edx], eax
    0xC2, 0x04, 0x00                     # ret 4
])
uc.mem_write(STUB_ATT_CODE, stub_att_bytes)
uc.mem_write(STUB_DEF_CODE, stub_def_bytes)


def hook_crt_helpers(uc_inst, address, size, user_data):
    if address == 0x00401000:
        esp = uc_inst.reg_read(UC_X86_REG_ESP)
        ret = struct.unpack('<I', uc_inst.mem_read(esp, 4))[0]
        uc_inst.reg_write(UC_X86_REG_ESP, esp + 4)
        uc_inst.reg_write(UC_X86_REG_EIP, ret)
    elif address == 0x00B31C00:
        uc_inst.reg_write(UC_X86_REG_EAX, 1)
        esp = uc_inst.reg_read(UC_X86_REG_ESP)
        ret = struct.unpack('<I', uc_inst.mem_read(esp, 4))[0]
        uc_inst.reg_write(UC_X86_REG_ESP, esp + 4)
        uc_inst.reg_write(UC_X86_REG_EIP, ret)


uc.hook_add(UC_HOOK_CODE, hook_crt_helpers)


def run_attacker_ratio_test(raw_att: int, raw_def: int) -> int:
    uc.mem_write(VAL_ATT_PTR, struct.pack('<i', raw_att))
    uc.mem_write(VAL_DEF_PTR, struct.pack('<i', raw_def))
    uc.mem_write(OUT_RATIO_ADDR, struct.pack('<i', -999))

    ret_addr = SCRATCH_BASE + 0x50000
    # Push arguments: [esp] = ret_addr, [esp + 4] = OUT_RATIO_ADDR
    uc.mem_write(STACK_BASE - 8, struct.pack('<II', ret_addr, OUT_RATIO_ADDR))
    uc.reg_write(UC_X86_REG_ESP, STACK_BASE - 8)
    uc.reg_write(UC_X86_REG_ECX, COMBAT_ADDR)

    # Emulate from 0x0059C460 up to ret_addr
    uc.emu_start(0x0059C460, ret_addr)

    # Output pointer returned in eax
    ret_ptr = uc.reg_read(UC_X86_REG_EAX)
    assert ret_ptr == OUT_RATIO_ADDR

    # Ratio value in out_ratio
    res = struct.unpack('<i', uc.mem_read(OUT_RATIO_ADDR, 4))[0]

    expected = calculate_attacker_strength_ratio(AttackerRatioInput(raw_att, raw_def))
    assert res == expected, (
        f"Mismatch: att={raw_att}, def={raw_def}, emu={res}, expected={expected}"
    )
    return res


fixtures_run = 0

# Case 1: Equal forces -> 500 (50.0%)
assert run_attacker_ratio_test(10000, 10000) == 500
fixtures_run += 1

# Case 2: 2:1 advantage -> 666 (66.6%)
assert run_attacker_ratio_test(20000, 10000) == 666
fixtures_run += 1

# Case 3: 1:2 disadvantage -> 333 (33.3%)
assert run_attacker_ratio_test(10000, 20000) == 333
fixtures_run += 1

# Case 4: Overwhelming attacker (99:1) -> 990 (99.0%)
assert run_attacker_ratio_test(99000, 1000) == 990
fixtures_run += 1

# Case 5: Zero attacker strength (clamped to 1) -> 1 / (1 + 1000) = 0
assert run_attacker_ratio_test(0, 1000) == 0
fixtures_run += 1

# Case 6: Both 0 (both clamped to 1) -> 1 / (1 + 1) = 500
assert run_attacker_ratio_test(0, 0) == 500
fixtures_run += 1

# Case 7: Large numbers triggering 64-bit path (> 2,147,482)
assert run_attacker_ratio_test(5000000, 5000000) == 500
fixtures_run += 1

# Case 8: Extreme 64-bit asymmetric battle
assert run_attacker_ratio_test(8000000, 2000000) == 800
fixtures_run += 1

# Case 9: 3:1 in 64-bit mode
assert run_attacker_ratio_test(3000000, 1000000) == 750
fixtures_run += 1

# Comprehensive parametric sweep
for att_val in [100, 1000, 5000, 25000, 100000, 3000000]:
    for def_val in [100, 1000, 5000, 25000, 100000, 3000000]:
        run_attacker_ratio_test(att_val, def_val)
        fixtures_run += 1

# Save receipts
out_dir = ROOT / 'evidence/generated/combat-attacker-ratio'
out_dir.mkdir(parents=True, exist_ok=True)
(out_dir / 'claims.json').write_text(json.dumps(claims, indent=2) + '\n')
(out_dir / 'reverify.json').write_text(json.dumps(report, indent=2) + '\n')
(out_dir / 'negative-controls.json').write_text(json.dumps(controls, indent=2) + '\n')
(out_dir / 'emulation.json').write_text(json.dumps({
    'binary_sha256': digest,
    'routine_va': hex(0x0059C460),
    'fixtures_count': fixtures_run,
    'mismatches': 0
}, indent=2) + '\n')

ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify', file_path=str(bin_path))
ledger.start_run('Verify CCombat::CalculateAttackerStrengthRatio routine and vtables', session='combat-attacker-ratio')
ledger.record(report, rnd=1, session='combat-attacker-ratio')
ledger.finish_run(1, report['grounded'], report['information'])
ledger.save()

print(f"Combat attacker ratio: {len(report['results'])} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Combat attacker ratio emulation: {fixtures_run} fixtures executed, 0 mismatches against combat_attacker_ratio_model.")
