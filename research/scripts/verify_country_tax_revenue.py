#!/usr/bin/env python3
"""Verify CCountry::CalculateTotalTaxRevenue routine (0x0052B780..0x0052B859, caller at 0x008383CF)."""
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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from country_tax_revenue_model import calculate_total_tax_revenue

data = (ROOT.parent / 'base-game/v2game.exe').read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = 0x400000

claims = []

# 1. Key instructions in CCountry::CalculateTotalTaxRevenue (0x0052B780..0x0052B859)
expected_tax_revenue_instructions = (
    (0x0052B780, 1, 'push', 'ebp'),
    (0x0052B781, 2, 'mov', 'ebp, esp'),
    (0x0052B783, 3, 'and', 'esp, 0xfffffff8'),
    (0x0052B786, 3, 'sub', 'esp, 8'),
    (0x0052B789, 6, 'mov', 'ecx, dword ptr [0xf096c8]'),
    (0x0052B78F, 3, 'add', 'ecx, 0xd'),
    (0x0052B792, 1, 'push', 'ebx'),
    (0x0052B793, 3, 'mov', 'ebx, dword ptr [ebp + 8]'),
    (0x0052B796, 3, 'shl', 'ecx, 4'),
    (0x0052B799, 4, 'mov', 'edx, dword ptr [ecx + ebx + 4]'),
    (0x0052B79D, 3, 'sub', 'edx, dword ptr [ecx + ebx]'),
    (0x0052B7A0, 2, 'add', 'ecx, ebx'),
    (0x0052B7A2, 2, 'xor', 'eax, eax'),
    (0x0052B7A4, 1, 'push', 'edi'),
    (0x0052B7A5, 2, 'mov', 'dword ptr [esi], eax'),
    (0x0052B7A7, 3, 'mov', 'dword ptr [esi + 4], eax'),
    (0x0052B7B2, 6, 'test', 'edx, 0xfffffff8'),
    (0x0052B7B8, 6, 'jle', '0x52b852'),
    (0x0052B7BE, 6, 'mov', 'edi, dword ptr [0xf0973c]'),
    (0x0052B7C4, 2, 'test', 'eax, eax'),
    (0x0052B7C6, 2, 'jne', '0x52b80d'),
    (0x0052B7C8, 6, 'mov', 'eax, dword ptr [ebx + 0xa0]'),
    (0x0052B7CE, 2, 'mov', 'eax, dword ptr [eax]'),
    (0x0052B7D0, 3, 'mov', 'edx, dword ptr [eax + 0x64]'),
    (0x0052B7D3, 3, 'mov', 'ecx, dword ptr [eax + 0x60]'),
    (0x0052B7E2, 5, 'call', '0xac9f20'),
    (0x0052B7E7, 6, 'mov', 'ecx, dword ptr [0xf0aacc]'),
    (0x0052B7EE, 6, 'mov', 'ecx, dword ptr [0xf0aac8]'),
    (0x0052B7F5, 5, 'and', 'eax, 0xffff8000'),
    (0x0052B7FC, 5, 'call', '0xac02a0'),
    (0x0052B801, 2, 'add', 'dword ptr [esi], eax'),
    (0x0052B80D, 3, 'cmp', 'eax, 1'),
    (0x0052B818, 3, 'mov', 'eax, dword ptr [edx + 4]'),
    (0x0052B81D, 3, 'cmp', 'eax, 2'),
    (0x0052B828, 3, 'mov', 'eax, dword ptr [edx + 8]'),
    (0x0052B83A, 3, 'adc', 'dword ptr [esi + 4], edx'),
    (0x0052B842, 1, 'inc', 'eax'),
    (0x0052B843, 3, 'sar', 'edx, 3'),
    (0x0052B84A, 2, 'cmp', 'eax, edx'),
    (0x0052B853, 2, 'mov', 'eax, esi'),
    (0x0052B859, 3, 'ret', '4'),
)

for address, length, mnemonic, operand in expected_tax_revenue_instructions:
    claims.append({
        'id': f'tax_rev_ins_{address:x}', 'kind': 'instructions', 'space': 'rva',
        'offset': hex(address - base), 'base': hex(address), 'arch': 'x86',
        'length': length, 'mnemonics': [mnemonic], 'operands': [operand] if operand else []
    })

# 2. Caller site verification at 0x008383CF
expected_caller_instructions = (
    (0x008383CA, 1, 'push', 'ebx'),
    (0x008383CB, 4, 'lea', 'esi, [esp + 0x24]'),
    (0x008383CF, 5, 'call', '0x52b780'),
)

for address, length, mnemonic, operand in expected_caller_instructions:
    claims.append({
        'id': f'tax_rev_caller_{address:x}', 'kind': 'instructions', 'space': 'rva',
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
wrong = dict(claims[0], id='negative_control_tax_revenue', mnemonics=['nop'])
dependent = dict(claims[1], id='negative_dependent_tax_revenue', depends_on=['negative_control_tax_revenue'])
controls = verifier.verify_all([Claim.from_dict(wrong), Claim.from_dict(dependent)])
assert [r['verdict'] for r in controls['results']] == ['REFUTED', 'INVALIDATED']

# Unicorn dynamic emulation
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

HEAP_BASE = 0x03000000
uc.mem_map(HEAP_BASE, 0x100000)

COUNTRY_ADDR = HEAP_BASE + 0x1000
TAX_VEC_ADDR = HEAP_BASE + 0x2000
TS0_ADDR     = HEAP_BASE + 0x3000
TS1_ADDR     = HEAP_BASE + 0x3100
TS2_ADDR     = HEAP_BASE + 0x3200
BUCKETS_DATA = HEAP_BASE + 0x4000
OUT_PTR      = HEAP_BASE + 0x5000

uc.mem_write(COUNTRY_ADDR + 0xA0, struct.pack('<I', TAX_VEC_ADDR))
uc.mem_write(TAX_VEC_ADDR, struct.pack('<III', TS0_ADDR, TS1_ADDR, TS2_ADDR))

def emu_tax_revenue(rates: list[int], bases: list[int], buckets: list[int]) -> int:
    esp = STACK_BASE + 0x80000
    ret_addr = 0x00401000

    # Write tax settings
    for idx, ts_addr in enumerate([TS0_ADDR, TS1_ADDR, TS2_ADDR]):
        r = rates[idx] if idx < len(rates) else 0
        b = bases[idx] if idx < len(bases) else 0
        uc.mem_write(ts_addr + 0x60, struct.pack('<q', r))
        uc.mem_write(ts_addr + 0x50, struct.pack('<q', b))

    # Write buckets vector
    for idx, val in enumerate(buckets):
        uc.mem_write(BUCKETS_DATA + idx * 8, struct.pack('<q', val))

    num_b = len(buckets)
    uc.mem_write(COUNTRY_ADDR + 0x0E0, struct.pack('<I', BUCKETS_DATA))
    uc.mem_write(COUNTRY_ADDR + 0x0E4, struct.pack('<I', BUCKETS_DATA + num_b * 8))
    uc.mem_write(COUNTRY_ADDR + 0x0E8, struct.pack('<I', BUCKETS_DATA + num_b * 8))

    # Clean out buffer
    uc.mem_write(OUT_PTR, struct.pack('<qq', 0, 0))

    uc.mem_write(esp + 4, struct.pack('<I', COUNTRY_ADDR))
    uc.mem_write(esp, struct.pack('<I', ret_addr))

    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_ESI, OUT_PTR)

    uc.emu_start(0x0052B780, ret_addr)

    res_lo, res_hi = struct.unpack('<II', uc.mem_read(OUT_PTR, 8))
    res = (res_hi << 32) | res_lo
    if res >= (1 << 63):
        res -= (1 << 64)
    return res

# Generate fixtures
fixtures = []

# Case 1: Empty buckets
fixtures.append(([0, 0, 0], [0, 0, 0], []))

# Case 2: Only 1 bucket (poor tax)
fixtures.append(([32768, 0, 0], [32768000, 0, 0], [1000]))

# Case 3: 2 buckets (poor, middle)
fixtures.append(([32768, 16384, 0], [32768000, 65536000, 0], [1000, 2000]))

# Case 4: 3 buckets (poor, middle, rich)
fixtures.append(([32768, 16384, 8192], [32768000, 65536000, 98304000], [1000, 2000, 3000]))

# Case 5: 5 buckets (3 taxes + 2 fixed other revenues)
fixtures.append(([32768, 32768, 32768], [32768000, 65536000, 98304000], [1000, 2000, 3000, 4000, 5000]))

# Deterministic randomized fixtures
random.seed(424242)
for _ in range(120):
    rates = [random.randint(0, 65536) for _ in range(3)]
    bases = [random.randint(0, 100000000) for _ in range(3)]
    n_buckets = random.randint(0, 8)
    buckets = [random.randint(0, 50000) for _ in range(n_buckets)]
    fixtures.append((rates, bases, buckets))

# Negative and edge-case values
for r_scale in [-10000, 0, 32768, 65536]:
    for b_scale in [-50000000, 0, 32768000, 100000000]:
        rates = [r_scale, r_scale // 2, r_scale // 4]
        bases = [b_scale, b_scale * 2, b_scale * 3]
        buckets = [100, 200, 300, 400, 500]
        fixtures.append((rates, bases, buckets))

mismatches = 0
for rates, bases, buckets in fixtures:
    exp = calculate_total_tax_revenue(rates, bases, buckets)
    act = emu_tax_revenue(rates, bases, buckets)
    if act != exp:
        mismatches += 1
        print(f"Mismatch: rates={rates}, bases={bases}, buckets={buckets} -> act={act}, exp={exp}")

assert mismatches == 0, f"{mismatches} mismatches found during country tax revenue emulation"

# Record receipts in evidence/generated/country-tax-revenue/
out = ROOT / 'evidence/generated/country-tax-revenue'
out.mkdir(parents=True, exist_ok=True)
(out / 'claims.json').write_text(json.dumps(claims, indent=2) + '\n')
(out / 'reverify.json').write_text(json.dumps(report, indent=2) + '\n')
(out / 'negative-controls.json').write_text(json.dumps(controls, indent=2) + '\n')
(out / 'emulation.json').write_text(json.dumps({
    'target_digest': digest,
    'total_fixtures': len(fixtures),
    'mismatches': mismatches,
    'status': 'PASS'
}, indent=2) + '\n')

ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify')
ledger.record(report, session='country-tax-revenue')
ledger.save()

print(f"Country tax revenue: {verified_count} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Country tax revenue emulation: {len(fixtures)} fixtures executed, 0 mismatches against country_tax_revenue_model.")
