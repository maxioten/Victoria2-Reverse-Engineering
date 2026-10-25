#!/usr/bin/env python3
"""Verify market price elasticity and sensitivity curve (0x00482610..0x0048292B, 0x0048C080)."""
import hashlib
import json
from pathlib import Path
import random
import struct
import capstone
import pefile
import unicorn
from unicorn.x86_const import (
    UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EBX,
    UC_X86_REG_ESP, UC_X86_REG_EBP, UC_X86_REG_ESI, UC_X86_REG_EDI,
)
from reverify.ledger import Ledger
from reverify.verifier import Claim, Verifier
import sys

# Ensure src/v2re is in path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src/v2re'))
from market_sensitivity_curve_model import calculate_price_sensitivity, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13

data = (ROOT.parent / 'base-game/v2game.exe').read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
image = pe.get_memory_mapped_image()
base = 0x400000

claims = []

# 1. Double constants: thresholds and returns for first tiers
claims.append({
    'id': 'sens_double_1638_bytes', 'kind': 'bytes_at', 'space': 'rva',
    'offset': hex(0x00E45820 - base),
    'expected': struct.pack('<d', 1638.9000244140625).hex()
})
claims.append({
    'id': 'sens_double_7307_bytes', 'kind': 'bytes_at', 'space': 'rva',
    'offset': hex(0x00E45818 - base),
    'expected': struct.pack('<d', 7307.76416015625).hex()
})
claims.append({
    'id': 'sens_double_2163_bytes', 'kind': 'bytes_at', 'space': 'rva',
    'offset': hex(0x00E45810 - base),
    'expected': struct.pack('<d', 2163.18798828125).hex()
})
claims.append({
    'id': 'sens_double_8454_bytes', 'kind': 'bytes_at', 'space': 'rva',
    'offset': hex(0x00E45808 - base),
    'expected': struct.pack('<d', 8454.6435546875).hex()
})
claims.append({
    'id': 'sens_double_2720_bytes', 'kind': 'bytes_at', 'space': 'rva',
    'offset': hex(0x00E45800 - base),
    'expected': struct.pack('<d', 2720.243896484375).hex()
})
claims.append({
    'id': 'sens_double_9437_bytes', 'kind': 'bytes_at', 'space': 'rva',
    'offset': hex(0x00E457F8 - base),
    'expected': struct.pack('<d', 9437.68359375).hex()
})
claims.append({
    'id': 'sens_double_3277_bytes', 'kind': 'bytes_at', 'space': 'rva',
    'offset': hex(0x00E457F0 - base),
    'expected': struct.pack('<d', 3277.300048828125).hex()
})

# 2. Key scaling constants in helper routines
claims.append({
    'id': 'fixed_scale_32768_bytes', 'kind': 'bytes_at', 'space': 'rva',
    'offset': hex(0x00E456B0 - base),
    'expected': struct.pack('<d', 32768.0).hex()
})
claims.append({
    'id': 'fixed_inv_scale_bytes', 'kind': 'bytes_at', 'space': 'rva',
    'offset': hex(0x00E456C0 - base),
    'expected': struct.pack('<d', 3.0517578125e-05).hex()
})

# 3. Key instructions in Market Sensitivity Function (0x00482610..0x0048292B)
expected_sens_instructions = (
    (0x00482610, 1, 'push', 'ebp'),
    (0x00482611, 2, 'mov', 'ebp, esp'),
    (0x00482613, 6, 'fld', 'qword ptr [0xe45820]'),
    (0x0048261E, 5, 'call', '0xb31c36'),
    (0x00482626, 2, 'cmp', 'ebx, edx'),
    (0x00482633, 6, 'fld', 'qword ptr [0xe45818]'),
    (0x0048264E, 6, 'fld', 'qword ptr [0xe45810]'),
    (0x0048267B, 6, 'fld', 'qword ptr [0xe45800]'),
    (0x004826A8, 6, 'fld', 'qword ptr [0xe457f0]'),
    (0x004826BD, 8, 'movss', 'xmm0, dword ptr [0xe457e8]'),
    (0x004826CD, 5, 'call', '0x408d50'),
    (0x00482734, 5, 'call', '0x43a5e0'),
    (0x004828E6, 5, 'call', '0x43a5e0'),
    (0x0048291C, 5, 'call', '0x48c080'),
    (0x0048292B, 1, 'ret', ''),
)

for address, length, mnemonic, operand in expected_sens_instructions:
    claims.append({
        'id': f'sens_ins_{address:x}', 'kind': 'instructions', 'space': 'rva',
        'offset': hex(address - base), 'base': hex(address), 'arch': 'x86',
        'length': length, 'mnemonics': [mnemonic], 'operands': [operand] if operand else []
    })

# 4. Key instructions in Sqrt Fallback Routine (0x0048C080..0x0048C0C8)
expected_sqrt_instructions = (
    (0x0048C080, 1, 'push', 'ebp'),
    (0x0048C083, 3, 'fild', 'qword ptr [ebp + 8]'),
    (0x0048C086, 6, 'fmul', 'qword ptr [0xe456c0]'),
    (0x0048C08C, 5, 'call', '0xb35500'),
    (0x0048C0AD, 6, 'fmul', 'qword ptr [0xe456b0]'),
    (0x0048C0B8, 3, 'fadd', 'qword ptr [ebp + 8]'),
    (0x0048C0BB, 5, 'call', '0xb31c36'),
    (0x0048C0C8, 1, 'ret', ''),
)

for address, length, mnemonic, operand in expected_sqrt_instructions:
    claims.append({
        'id': f'sqrt_ins_{address:x}', 'kind': 'instructions', 'space': 'rva',
        'offset': hex(address - base), 'base': hex(address), 'arch': 'x86',
        'length': length, 'mnemonics': [mnemonic], 'operands': [operand] if operand else []
    })

# 5. Caller site verification in Market Daily Loop (0x00482B58..0x00482B7F)
expected_caller_instructions = (
    (0x00482B58, 5, 'call', '0xac02a0'),
    (0x00482B62, 3, 'lea', 'edi, [ebp - 0x70]'),
    (0x00482B65, 5, 'call', '0x482610'),
    (0x00482B6A, 3, 'mov', 'edx, dword ptr [eax + 4]'),
    (0x00482B6D, 2, 'mov', 'eax, dword ptr [eax]'),
    (0x00482B7F, 5, 'call', '0xac9f20'),
)

for address, length, mnemonic, operand in expected_caller_instructions:
    claims.append({
        'id': f'caller_ins_{address:x}', 'kind': 'instructions', 'space': 'rva',
        'offset': hex(address - base), 'base': hex(address), 'arch': 'x86',
        'length': length, 'mnemonics': [mnemonic], 'operands': [operand] if operand else []
    })

# Reverify evaluation
verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]
verified_count = len(claims)

# Negative controls
wrong = dict(claims[0], id='negative_control', expected='1122334455667788')
dependent = dict(claims[1], id='negative_dependent', depends_on=['negative_control'])
controls = verifier.verify_all([Claim.from_dict(wrong), Claim.from_dict(dependent)])
assert [r['verdict'] for r in controls['results']] == ['REFUTED', 'INVALIDATED']

# Unicorn emulation: hardware-level execution against market_sensitivity_curve_model
uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
image_base = pe.OPTIONAL_HEADER.ImageBase

for section in pe.sections:
    va = image_base + section.VirtualAddress
    size = (section.Misc_VirtualSize + 0xFFF) & ~0xFFF
    uc.mem_map(va, size)
    uc.mem_write(va, section.get_data())

STACK_BASE = 0x02000000
STACK_SIZE = 0x00100000
uc.mem_map(STACK_BASE, STACK_SIZE)

# Standard MSVC FPU control word initialization (0x027F = 53-bit double precision, masked exceptions)
SETUP_ADDR = STACK_BASE + 0x1000
uc.mem_write(SETUP_ADDR, b'\xdb\xe3\x68\x7f\x02\x00\x00\xd9\x2c\x24\x83\xc4\x04\xc3')
uc.reg_write(UC_X86_REG_ESP, STACK_BASE + 0x80000)
uc.emu_start(SETUP_ADDR, SETUP_ADDR + 13)

def emu_run_sensitivity(ratio_val: int) -> int:
    esp = STACK_BASE + 0x80000
    edi = STACK_BASE + 0x40000
    ratio_bytes = ratio_val.to_bytes(8, byteorder='little', signed=True)
    ret_addr = 0x00401000
    uc.mem_write(esp, ret_addr.to_bytes(4, 'little'))
    uc.mem_write(esp + 4, ratio_bytes[:4])
    uc.mem_write(esp + 8, ratio_bytes[4:])
    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_EDI, edi)
    uc.emu_start(0x00482610, ret_addr)
    res_bytes = uc.mem_read(edi, 8)
    return int.from_bytes(res_bytes, byteorder='little', signed=True)

# Generate comprehensive fixtures:
test_fixtures = []

# Critical threshold boundaries:
thresholds = [T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13]
for t in thresholds:
    test_fixtures.extend([t - 2, t - 1, t, t + 1, t + 2])

# Edge and representative market cases:
test_fixtures.extend([
    -10000, -1, 0, 1, 100, 500, 1000, 2000, 3000, 5000, 10000,
    16384, 20000, 30000, 32768, 40000, 50000, 65536, 100000, 289837, 500000
])

# Randomized fixtures
random.seed(42)
for _ in range(200):
    test_fixtures.append(random.randint(0, 500000))

mismatches = 0
for r in test_fixtures:
    expected = calculate_price_sensitivity(r)
    actual = emu_run_sensitivity(r)
    if expected != actual:
        mismatches += 1
        print(f"Discrepancy at ratio={r}: expected={expected}, actual={actual}")

assert mismatches == 0, f"{mismatches} mismatches found during Unicorn emulation"

# Record receipts in evidence/generated/market-sensitivity-curve/
out = ROOT / 'evidence/generated/market-sensitivity-curve'
out.mkdir(parents=True, exist_ok=True)
(out / 'claims.json').write_text(json.dumps(claims, indent=2) + '\n')
(out / 'reverify.json').write_text(json.dumps(report, indent=2) + '\n')
(out / 'negative-controls.json').write_text(json.dumps(controls, indent=2) + '\n')
(out / 'emulation.json').write_text(json.dumps({
    'target_digest': digest,
    'total_fixtures': len(test_fixtures),
    'mismatches': mismatches,
    'status': 'PASS'
}, indent=2) + '\n')

ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify')
ledger.record(report, session='market-sensitivity-curve')
ledger.save()

print(f"Market sensitivity curve: {verified_count} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Market sensitivity curve emulation: {len(test_fixtures)} fixtures executed, 0 mismatches against market_sensitivity_curve_model.")

