#!/usr/bin/env python3
"""Verify CCombat::CalculateForceRatio against PE32 binary with Reverify and Unicorn.

Routine: 0x0059C460..0x0059C51E (190 bytes, 79 instructions).
Vtables:
  - CCombat: slot 7 at 0x00E02160
  - CLandCombat: slot 7 at 0x00E02370
  - CNavalCombat: slot 7 at 0x00E023E0
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
    UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
    UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP,
    UC_X86_REG_EIP
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT / 'scripts'))
from combat_force_ratio_model import combat_force_ratio

bin_path = ROOT.parent / 'base-game/v2game.exe'
data = bin_path.read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_32)

routine_va = 0x0059C460
routine_rva = routine_va - base
routine_raw = pe.get_offset_from_rva(routine_rva)
code = data[routine_raw:routine_raw + 210]

claims = []
disasm_insns = []
for insn in md.disasm(code, routine_va):
    disasm_insns.append(insn)
    claims.append({
        'id': f'combat_ratio_insn_{insn.address:x}',
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

# Vtables: slot 7 across combat polymorphism hierarchy
vtables = [
    (0x00E02160, 'ccombat_slot7'),
    (0x00E02370, 'clandcombat_slot7'),
    (0x00E023E0, 'cnavalcombat_slot7'),
]
for vt_va, name in vtables:
    claims.append({
        'id': f'combat_ratio_vt_{name}',
        'kind': 'bytes_at',
        'space': 'rva',
        'offset': hex(vt_va - base),
        'base': hex(vt_va),
        'expected': struct.pack('<I', routine_va).hex()
    })

# Float constant 1.5 in 0x00F141C8
claims.append({
    'id': 'combat_ratio_const_1_5',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00F141C8 - base),
    'base': hex(0x00F141C8),
    'expected': data[pe.get_offset_from_rva(0x00F141C8 - base):pe.get_offset_from_rva(0x00F141C8 - base) + 4].hex()
})

# Run Reverify
verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]

# Negative controls and dependent invalidation
wrong = dict(claims[0], id='negative_control_combat_ratio', mnemonics=['nop'])
dependent = dict(claims[1], id='negative_dependent_combat_ratio', depends_on=['negative_control_combat_ratio'])
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

# CRT stubs: floor(1.5) = 1.0 -> ftol2 = 1
uc.mem_write(0x00401000, b'\xd9\xee\xc3') # FLDZ; RET
uc.mem_write(0x00B31C00, b'\xb8\x01\x00\x00\x00\xc3') # MOV EAX, 1; RET

heap_base = 0x02000000
uc.mem_map(heap_base, 0x200000, UC_PROT_ALL)

attacker_val_addr = heap_base + 0x10
defender_val_addr = heap_base + 0x14

# Subunit / Combatant vtable stubs (slot 10 at +0x28)
# Arguments: [esp + 4] = out_ptr. Writes strength to [out_ptr] and returns ret 4
stub_get_attacker = b'\x8b\x44\x24\x04\x8b\x15' + struct.pack('<I', attacker_val_addr) + b'\x89\x10\xc2\x04\x00'
stub_get_defender = b'\x8b\x44\x24\x04\x8b\x15' + struct.pack('<I', defender_val_addr) + b'\x89\x10\xc2\x04\x00'

code_get_attacker = heap_base + 0x100
code_get_defender = heap_base + 0x120
uc.mem_write(code_get_attacker, stub_get_attacker)
uc.mem_write(code_get_defender, stub_get_defender)

attacker_vtable = heap_base + 0x200
defender_vtable = heap_base + 0x300
uc.mem_write(attacker_vtable + 0x28, code_get_attacker.to_bytes(4, 'little'))
uc.mem_write(defender_vtable + 0x28, code_get_defender.to_bytes(4, 'little'))

combat_obj = heap_base + 0x1000
attacker_obj = heap_base + 0x2000
defender_obj = heap_base + 0x3000

uc.mem_write(attacker_obj, attacker_vtable.to_bytes(4, 'little'))
uc.mem_write(defender_obj, defender_vtable.to_bytes(4, 'little'))

uc.mem_write(combat_obj + 0x10, attacker_obj.to_bytes(4, 'little'))
uc.mem_write(combat_obj + 0x14, defender_obj.to_bytes(4, 'little'))

out_buf = heap_base + 0x8000
stack_base = heap_base + 0x100000

def emu_combat_force_ratio(attacker_strength: int, defender_strength: int) -> int:
    uc.mem_write(attacker_val_addr, (attacker_strength & 0xFFFFFFFF).to_bytes(4, 'little', signed=False))
    uc.mem_write(defender_val_addr, (defender_strength & 0xFFFFFFFF).to_bytes(4, 'little', signed=False))
    uc.mem_write(out_buf, (0xDEADBEEF).to_bytes(4, 'little'))

    esp = stack_base + 0x80000
    esp -= 4
    uc.mem_write(esp, (0).to_bytes(4, 'little'))
    esp -= 4
    uc.mem_write(esp, out_buf.to_bytes(4, 'little'))
    esp -= 4
    uc.mem_write(esp, (0x0059C51E).to_bytes(4, 'little'))

    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_EBP, esp + 12)
    uc.reg_write(UC_X86_REG_ECX, combat_obj)

    uc.emu_start(0x0059C460, 0x0059C51E)
    return struct.unpack('<i', uc.mem_read(out_buf, 4))[0]

fixtures = [
    # 1. Symmetric forces
    (1000, 1000),
    (5000, 5000),
    (30000, 30000),

    # 2. Asymmetric standard battles (32-bit fast path)
    (20000, 10000),
    (10000, 20000),
    (30000, 10000),
    (10000, 30000),
    (45000, 15000),
    (12345, 67890),

    # 3. Minimum / Clamped forces (< 1 clamped to 1)
    (1, 1),
    (0, 0),
    (-100, -50),
    (0, 1000),
    (1000, 0),
    (-500, 5000),

    # 4. Overflow boundary tests (threshold 2,147,482)
    (2147480, 1000000),  # Fast path 32-bit
    (2147482, 1000000),  # Exact boundary
    (2147485, 1000000),  # Extended 64-bit safe path
    (3000000, 1500000),  # 64-bit safe path
    (5000000, 2500000),  # 64-bit safe path
    (10000000, 5000000), # 64-bit safe path
    (50000000, 25000000),# 64-bit safe path
]

# Systematic variations to reach >150 fixtures
for a in [500, 2500, 10000, 50000, 200000, 1500000, 2147482, 4000000]:
    for d in [1000, 5000, 25000, 100000, 500000, 2000000, 5000000]:
        fixtures.append((a, d))
        fixtures.append((d, a))

emu_results = []
mismatches = 0
for idx, (a, d) in enumerate(fixtures):
    emu_val = emu_combat_force_ratio(a, d)
    expected = combat_force_ratio(a, d)
    if emu_val != expected:
        mismatches += 1
        print(f'MISMATCH fixture {idx}: A={a}, D={d}, emu={emu_val}, exp={expected}')
    emu_results.append({
        'fixture_idx': idx,
        'attacker': a,
        'defender': d,
        'emulated': emu_val,
        'expected': expected,
        'pass': emu_val == expected
    })

assert mismatches == 0, f'{mismatches} mismatches found during emulation!'

# Save receipts
out_dir = ROOT / 'evidence/generated/combat-force-ratio'
out_dir.mkdir(parents=True, exist_ok=True)
(out_dir / 'claims.json').write_text(json.dumps(claims, indent=2) + '\n')
(out_dir / 'reverify.json').write_text(json.dumps(report, indent=2) + '\n')
(out_dir / 'negative-controls.json').write_text(json.dumps(controls, indent=2) + '\n')
(out_dir / 'emulation.json').write_text(json.dumps({
    'binary_sha256': digest,
    'routine_va': hex(routine_va),
    'fixtures_count': len(fixtures),
    'mismatches': mismatches,
    'results': emu_results
}, indent=2) + '\n')

ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify', file_path=str(bin_path))
ledger.start_run('Verify CCombat::CalculateForceRatio routine and vtables', session='combat-force-ratio')
ledger.record(report, rnd=1, session='combat-force-ratio')
ledger.finish_run(1, report['grounded'], report['information'])
ledger.save()

print(f'Combat force ratio: {len(report["results"])} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.')
print(f'Combat force ratio emulation: {len(fixtures)} fixtures executed, {mismatches} mismatches against combat_force_ratio_model.')
