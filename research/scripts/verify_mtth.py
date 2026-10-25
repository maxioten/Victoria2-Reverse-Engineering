#!/usr/bin/env python3
"""Verify event MTTH to daily probability calculation and callers in EventManager_DailyScan."""
import hashlib
import json
from pathlib import Path
import struct
import capstone
import pefile
import unicorn
from unicorn.x86_const import (
    UC_X86_REG_EAX, UC_X86_REG_ESP,
)
from reverify.ledger import Ledger
from reverify.verifier import Claim, Verifier
from mtth_model import compute_mtth_probability

ROOT = Path(__file__).resolve().parents[1]
data = (ROOT.parent / 'base-game/v2game.exe').read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
image = pe.get_memory_mapped_image()
base = 0x400000
cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

claims = []

# 1. Double constants: 1000.0 at 0x00E45660 and 0.0005 at 0x00E45840
claims.append({
    'id': 'mtth_scale_factor_bytes', 'kind': 'bytes_at', 'space': 'rva',
    'offset': hex(0x00E45660 - base), 'expected': '0000000000408f40'
})
claims.append({
    'id': 'mtth_round_bias_bytes', 'kind': 'bytes_at', 'space': 'rva',
    'offset': hex(0x00E45840 - base), 'expected': '000000e04d62403f'
})

# 2. Call sites in EventManager_DailyScan (0x008A7CD0)
# 0x008A7E05: CALL 0x008AE380
# 0x008A7FE6: CALL 0x008AE380
for call_site in (0x008A7E05, 0x008A7FE6):
    claims.append({
        'id': f'call_mtth_{call_site:x}', 'kind': 'instructions', 'space': 'rva',
        'offset': hex(call_site - base), 'base': hex(call_site), 'arch': 'x86',
        'length': 5, 'mnemonics': ['call'], 'operands': ['0x8ae380']
    })

# 3. Core instruction checks in Event_ComputeMTTHProbability (0x008AE380)
expected_instructions = (
    (0x8ae380, 1, 'push', 'ebp'),
    (0x8ae38a, 3, 'mov', 'ebx, dword ptr [eax + 8]'),
    (0x8ae38e, 3, 'mov', 'esi, dword ptr [eax + 0x10]'),
    (0x8ae391, 3, 'sub', 'esi, dword ptr [eax + 0xc]'),
    (0x8ae395, 3, 'sar', 'esi, 2'),
    (0x8ae39f, 2, 'test', 'esi, esi'),
    (0x8ae3a1, 6, 'jle', '0x8ae433'),
    (0x8ae3b5, 3, 'mov', 'edx, dword ptr [edx + 0x18]'),
    (0x8ae3bb, 2, 'call', 'edx'),
    (0x8ae3bd, 2, 'test', 'al, al'),
    (0x8ae3bf, 2, 'je', '0x8ae421'),
    (0x8ae3c1, 5, 'movd', 'xmm0, dword ptr [edi + 0x20]'),
    (0x8ae3c9, 3, 'cvtdq2ps', 'xmm0, xmm0'),
    (0x8ae3cc, 4, 'cvtss2sd', 'xmm1, xmm0'),
    (0x8ae3d0, 8, 'divsd', 'xmm1, qword ptr [0xe45660]'),
    (0x8ae3e0, 8, 'addsd', 'xmm1, qword ptr [0xe45840]'),
    (0x8ae3f0, 8, 'mulsd', 'xmm1, qword ptr [0xe45660]'),
    (0x8ae40a, 5, 'call', '0xb31c00'),
    (0x8ae40f, 2, 'imul', 'ebx'),
    (0x8ae413, 5, 'push', '0x3e8'),
    (0x8ae41a, 5, 'call', '0xac02a0'),
    (0x8ae428, 2, 'cmp', 'eax, esi'),
    (0x8ae42d, 6, 'jl', '0x8ae3a7'),
    (0x8ae433, 2, 'test', 'ebx, ebx'),
    (0x8ae43d, 6, 'cmp', 'ebx, 0x3e8'),
    (0x8ae443, 2, 'jg', '0x8ae453'),
    (0x8ae445, 5, 'mov', 'eax, 0xf4240'),
    (0x8ae450, 3, 'ret', '0xc'),
    (0x8ae453, 3, 'mov', 'ecx, dword ptr [ebp + 0x10]'),
    (0x8ae456, 5, 'mov', 'eax, 0x10624dd3'),
    (0x8ae45b, 6, 'imul', 'ecx, ecx, 0xf4240'),
    (0x8ae461, 2, 'imul', 'ebx'),
    (0x8ae463, 3, 'sar', 'edx, 6'),
    (0x8ae470, 2, 'idiv', 'esi'),
    (0x8ae472, 5, 'cmp', 'eax, 0xf4240'),
    (0x8ae477, 2, 'jg', '0x8ae445'),
    (0x8ae479, 2, 'test', 'eax, eax'),
    (0x8ae47b, 2, 'jg', '0x8ae482'),
    (0x8ae47d, 5, 'mov', 'eax, 1'),
    (0x8ae488, 3, 'ret', '0xc'),
)

for address, length, mnemonic, operand in expected_instructions:
    claims.append({
        'id': f'mtth_ins_{address:x}', 'kind': 'instructions', 'space': 'rva',
        'offset': hex(address - base), 'base': hex(address), 'arch': 'x86',
        'length': length, 'mnemonics': [mnemonic], 'operands': [operand]
    })

verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]

# Negative controls
wrong = dict(claims[0], id='negative_control', expected='ffffffffffffffff')
dependent = dict(claims[1], id='negative_dependent', depends_on=['negative_control'])
controls = verifier.verify_all([Claim.from_dict(wrong), Claim.from_dict(dependent)])
assert [r['verdict'] for r in controls['results']] == ['REFUTED', 'INVALIDATED']

# 4. Unicorn dynamic emulation: sweep days and modes across 200+ fixtures
uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
uc.mem_map(0, 0x1000, unicorn.UC_PROT_ALL)
uc.mem_map(0x400000, 0x1100000, unicorn.UC_PROT_ALL)
uc.mem_write(0x400000, image)

stack_base = 0x200000
uc.mem_map(stack_base, 0x20000, unicorn.UC_PROT_ALL)
return_addr = 0x12345678
uc.mem_map(0x12340000, 0x10000, unicorn.UC_PROT_ALL)
uc.mem_write(0x12345678, b'\x90\x90')

def hook_code(uc, address, size, user_data):
    if address == return_addr:
        uc.emu_stop()

uc.hook_add(unicorn.UC_HOOK_CODE, hook_code)

test_days = [
    0, 1, 2, 3, 5, 7, 10, 14, 21, 30, 45, 60, 90, 120, 180, 240, 300, 365,
    500, 730, 1000, 1825, 3650, 5000, 10000, 50000, 100000, 500000, 1000000, 2000000
]
test_modes = [1, 2, 3, 5, 10, 30, 100]

fixtures = []
for d in test_days:
    for m in test_modes:
        # Also test with exact milli-days and fractional milli-day offsets
        milli = d * 1000
        fixtures.append((milli, m))
        if d > 1:
            fixtures.append((milli + 250, m))
            fixtures.append((milli + 750, m))

emulation_records = []
mismatches = 0

for mtth_milli, mode in fixtures:
    esp = stack_base + 0x10000
    this_ptr = stack_base + 0x5000
    uc.mem_write(this_ptr + 8, struct.pack('<I', mtth_milli))
    uc.mem_write(this_ptr + 0xc, struct.pack('<I', stack_base + 0x6000))
    uc.mem_write(this_ptr + 0x10, struct.pack('<I', stack_base + 0x6000))

    uc.mem_write(esp, struct.pack('<IIII', return_addr, this_ptr, 0, mode))
    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.emu_start(0x008AE380, return_addr)

    actual_prob = uc.reg_read(UC_X86_REG_EAX)
    expected_prob = compute_mtth_probability(mtth_milli, mode)

    if actual_prob != expected_prob:
        mismatches += 1
        print(f"MISMATCH for mtth={mtth_milli}, mode={mode}: actual={actual_prob} vs expected={expected_prob}")

    emulation_records.append({
        'mtth_milli': mtth_milli, 'mode': mode,
        'actual': actual_prob, 'expected': expected_prob,
        'pass': (actual_prob == expected_prob)
    })

assert mismatches == 0, f"{mismatches} mismatches in MTTH probability emulation"

out = ROOT / 'evidence/generated/mtth'
out.mkdir(parents=True, exist_ok=True)
(out / 'claims.json').write_text(json.dumps(claims, indent=2) + '\n')
(out / 'reverify.json').write_text(json.dumps(report, indent=2) + '\n')
(out / 'negative-controls.json').write_text(json.dumps(controls, indent=2) + '\n')
(out / 'emulation.json').write_text(json.dumps({
    'total_fixtures': len(fixtures),
    'mismatches': mismatches,
    'records_sample': emulation_records[:20]
}, indent=2) + '\n')

ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify')
ledger.record(report, session='event-mtth-probability')
ledger.save()

print(f"Event MTTH: {len(claims)} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Event MTTH emulation: {len(fixtures)} fixtures executed, 0 mismatches against mtth_model.")
