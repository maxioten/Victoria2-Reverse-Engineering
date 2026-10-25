#!/usr/bin/env python3
"""Verify CCountry::SetTariffRateAndClamp routine (0x00538070..0x00538147, callers at 0x00582500 and 0x00524A7B)."""
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
from country_tariff_clamp_model import set_tariff_rate_and_clamp

data = (ROOT.parent / 'base-game/v2game.exe').read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = 0x400000

claims = []

# 1. Key instructions in CCountry::SetTariffRateAndClamp (0x00538070..0x00538147)
expected_tariff_clamp_instructions = (
    (0x00538070, 1, 'push', 'ebp'),
    (0x00538071, 2, 'mov', 'ebp, esp'),
    (0x00538073, 3, 'sub', 'esp, 0x14'),
    (0x00538076, 3, 'mov', 'eax, dword ptr [ebp + 8]'),
    (0x00538079, 3, 'mov', 'ecx, dword ptr [ebp + 0xc]'),
    (0x0053807C, 6, 'mov', 'dword ptr [esi + 0x1440], eax'),
    (0x00538082, 6, 'mov', 'dword ptr [esi + 0x1444], ecx'),
    (0x00538088, 6, 'mov', 'edx, dword ptr [esi + 0xa60]'),
    (0x0053808E, 6, 'mov', 'eax, dword ptr [edx + 0xe8]'),
    (0x00538094, 1, 'push', 'edi'),
    (0x00538095, 1, 'cdq', ''),
    (0x00538096, 4, 'shld', 'edx, eax, 0x1e'),
    (0x0053809C, 5, 'push', '0x1f40000'),
    (0x005380A1, 3, 'shl', 'eax, 0x1e'),
    (0x005380A6, 5, 'call', '0xac02a0'),
    (0x005380AB, 6, 'mov', 'ecx, dword ptr [esi + 0x1444]'),
    (0x005380B1, 6, 'mov', 'edi, dword ptr [esi + 0x1440]'),
    (0x005380C3, 2, 'cmp', 'edx, ecx'),
    (0x005380C5, 2, 'jg', '0x5380d2'),
    (0x005380C7, 2, 'jl', '0x5380cd'),
    (0x005380C9, 2, 'cmp', 'eax, edi'),
    (0x005380CB, 2, 'jae', '0x5380d2'),
    (0x005380CD, 3, 'lea', 'eax, [ebp - 8]'),
    (0x005380D2, 3, 'lea', 'eax, [ebp - 0x10]'),
    (0x005380DA, 6, 'mov', 'dword ptr [esi + 0x1444], edx'),
    (0x005380E0, 6, 'mov', 'dword ptr [esi + 0x1440], ecx'),
    (0x005380E6, 6, 'mov', 'eax, dword ptr [esi + 0xa60]'),
    (0x005380EC, 6, 'mov', 'eax, dword ptr [eax + 0xf0]'),
    (0x005380F3, 4, 'shld', 'edx, eax, 0x1e'),
    (0x005380F9, 5, 'push', '0x1f40000'),
    (0x005380FE, 3, 'shl', 'eax, 0x1e'),
    (0x00538103, 5, 'call', '0xac02a0'),
    (0x00538120, 2, 'cmp', 'ecx, edx'),
    (0x00538122, 2, 'jg', '0x53812f'),
    (0x00538124, 2, 'jl', '0x53812a'),
    (0x00538126, 2, 'cmp', 'edi, eax'),
    (0x00538128, 2, 'jae', '0x53812f'),
    (0x0053812A, 3, 'lea', 'eax, [ebp + 8]'),
    (0x0053812F, 3, 'lea', 'eax, [ebp - 0x10]'),
    (0x00538137, 6, 'mov', 'dword ptr [esi + 0x1440], ecx'),
    (0x0053813D, 6, 'mov', 'dword ptr [esi + 0x1444], edx'),
    (0x00538147, 3, 'ret', '8'),
)

for address, length, mnemonic, operand in expected_tariff_clamp_instructions:
    claims.append({
        'id': f'tariff_clamp_ins_{address:x}', 'kind': 'instructions', 'space': 'rva',
        'offset': hex(address - base), 'base': hex(address), 'arch': 'x86',
        'length': length, 'mnemonics': [mnemonic], 'operands': [operand] if operand else []
    })

# 2. Caller site verification in CChangeTariffs::Execute and CCountry::DailyUpdate
expected_caller_instructions = (
    (0x005824FD, 3, 'mov', 'esi, dword ptr [eax + ecx*4]'),
    (0x00582500, 5, 'call', '0x538070'),
    (0x00524A7B, 5, 'call', '0x538070'),
)

for address, length, mnemonic, operand in expected_caller_instructions:
    claims.append({
        'id': f'tariff_caller_ins_{address:x}', 'kind': 'instructions', 'space': 'rva',
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
wrong = dict(claims[0], id='negative_control_tariff_clamp', mnemonics=['nop'])
dependent = dict(claims[1], id='negative_dependent_tariff_clamp', depends_on=['negative_control_tariff_clamp'])
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
POLICY_ADDR  = HEAP_BASE + 0x2000

uc.mem_write(COUNTRY_ADDR + 0xA60, struct.pack('<I', POLICY_ADDR))

def emu_tariff_clamp(new_rate: int, min_lim_raw: int, max_lim_raw: int) -> int:
    esp = STACK_BASE + 0x80000
    ret_addr = 0x00401000

    uc.mem_write(POLICY_ADDR + 0xE8, struct.pack('<i', min_lim_raw))
    uc.mem_write(POLICY_ADDR + 0xF0, struct.pack('<i', max_lim_raw))
    uc.mem_write(COUNTRY_ADDR + 0x1440, struct.pack('<q', 0))

    # Push new_rate (int64)
    uc.mem_write(esp + 8, struct.pack('<I', (new_rate >> 32) & 0xFFFFFFFF))
    uc.mem_write(esp + 4, struct.pack('<I', new_rate & 0xFFFFFFFF))
    uc.mem_write(esp, struct.pack('<I', ret_addr))

    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_ESI, COUNTRY_ADDR)

    uc.emu_start(0x00538070, ret_addr)

    return struct.unpack('<q', uc.mem_read(COUNTRY_ADDR + 0x1440, 8))[0]

# Generate fixtures
fixtures = []

# Deterministic grid of rates and policy limits
for r in [-200000, -50000, 0, 500, 3276, 16384, 32768, 65536, 1000000]:
    for mn in [-100, -50, -25, 0, 10, 25]:
        for mx in [0, 25, 50, 100, 200]:
            fixtures.append((r, mn, mx))

random.seed(554433)
for _ in range(80):
    fixtures.append((
        random.randint(-1000000, 1000000),
        random.randint(-150, 50),
        random.randint(50, 300)
    ))

mismatches = 0
for r, mn, mx in fixtures:
    exp = set_tariff_rate_and_clamp(r, mn, mx)
    act = emu_tariff_clamp(r, mn, mx)
    if act != exp:
        mismatches += 1
        print(f"Mismatch: r={r}, mn={mn}, mx={mx} -> act={act}, exp={exp}")

assert mismatches == 0, f"{mismatches} mismatches found during country tariff clamp emulation"

# Record receipts in evidence/generated/country-tariff-clamp/
out = ROOT / 'evidence/generated/country-tariff-clamp'
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
ledger.record(report, session='country-tariff-clamp')
ledger.save()

print(f"Country tariff clamp: {verified_count} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Country tariff clamp emulation: {len(fixtures)} fixtures executed, 0 mismatches against country_tariff_clamp_model.")
