#!/usr/bin/env python3
"""Verify CCountry::SetCategorySpendingSlider routine (0x00538070..0x00538147, callers at 0x00524A7B, 0x00582500)."""
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
    UC_X86_REG_EIP,
)
from reverify.ledger import Ledger
from reverify.verifier import Claim, Verifier
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from country_spending_clamp_model import clamp_spending_slider

data = (ROOT.parent / 'base-game/v2game.exe').read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = 0x400000

claims = []

# 1. Key instructions in CCountry::SetCategorySpendingSlider (0x00538070..0x00538147) and callers
expected_instructions = (
    # Callers
    (0x00524A7B, 5, 'call', '0x538070'),
    (0x00582500, 5, 'call', '0x538070'),
    # Routine
    (0x538070, 1, 'push', 'ebp'),
    (0x538071, 2, 'mov', 'ebp, esp'),
    (0x538073, 3, 'sub', 'esp, 0x14'),
    (0x538076, 3, 'mov', 'eax, dword ptr [ebp + 8]'),
    (0x538079, 3, 'mov', 'ecx, dword ptr [ebp + 0xc]'),
    (0x53807c, 6, 'mov', 'dword ptr [esi + 0x1440], eax'),
    (0x538082, 6, 'mov', 'dword ptr [esi + 0x1444], ecx'),
    (0x538088, 6, 'mov', 'edx, dword ptr [esi + 0xa60]'),
    (0x53808e, 6, 'mov', 'eax, dword ptr [edx + 0xe8]'),
    (0x538094, 1, 'push', 'edi'),
    (0x538095, 1, 'cdq', ''),
    (0x538096, 4, 'shld', 'edx, eax, 0x1e'),
    (0x53809a, 2, 'push', '0'),
    (0x53809c, 5, 'push', '0x1f40000'),
    (0x5380a1, 3, 'shl', 'eax, 0x1e'),
    (0x5380a4, 1, 'push', 'edx'),
    (0x5380a5, 1, 'push', 'eax'),
    (0x5380a6, 5, 'call', '0xac02a0'),
    (0x5380ab, 6, 'mov', 'ecx, dword ptr [esi + 0x1444]'),
    (0x5380b1, 6, 'mov', 'edi, dword ptr [esi + 0x1440]'),
    (0x5380b7, 3, 'mov', 'dword ptr [ebp - 0x10], eax'),
    (0x5380ba, 3, 'mov', 'dword ptr [ebp - 0xc], edx'),
    (0x5380bd, 3, 'mov', 'dword ptr [ebp - 8], edi'),
    (0x5380c0, 3, 'mov', 'dword ptr [ebp - 4], ecx'),
    (0x5380c3, 2, 'cmp', 'edx, ecx'),
    (0x5380c5, 2, 'jg', '0x5380d2'),
    (0x5380c7, 2, 'jl', '0x5380cd'),
    (0x5380c9, 2, 'cmp', 'eax, edi'),
    (0x5380cb, 2, 'jae', '0x5380d2'),
    (0x5380cd, 3, 'lea', 'eax, [ebp - 8]'),
    (0x5380d0, 2, 'jmp', '0x5380d5'),
    (0x5380d2, 3, 'lea', 'eax, [ebp - 0x10]'),
    (0x5380d5, 2, 'mov', 'ecx, dword ptr [eax]'),
    (0x5380d7, 3, 'mov', 'edx, dword ptr [eax + 4]'),
    (0x5380da, 6, 'mov', 'dword ptr [esi + 0x1444], edx'),
    (0x5380e0, 6, 'mov', 'dword ptr [esi + 0x1440], ecx'),
    (0x5380e6, 6, 'mov', 'eax, dword ptr [esi + 0xa60]'),
    (0x5380ec, 6, 'mov', 'eax, dword ptr [eax + 0xf0]'),
    (0x5380f2, 1, 'cdq', ''),
    (0x5380f3, 4, 'shld', 'edx, eax, 0x1e'),
    (0x5380f7, 2, 'push', '0'),
    (0x5380f9, 5, 'push', '0x1f40000'),
    (0x5380fe, 3, 'shl', 'eax, 0x1e'),
    (0x538101, 1, 'push', 'edx'),
    (0x538102, 1, 'push', 'eax'),
    (0x538103, 5, 'call', '0xac02a0'),
    (0x538108, 6, 'mov', 'ecx, dword ptr [esi + 0x1444]'),
    (0x53810e, 6, 'mov', 'edi, dword ptr [esi + 0x1440]'),
    (0x538114, 3, 'mov', 'dword ptr [ebp - 0x10], eax'),
    (0x538117, 3, 'mov', 'dword ptr [ebp - 0xc], edx'),
    (0x53811a, 3, 'mov', 'dword ptr [ebp + 8], edi'),
    (0x53811d, 3, 'mov', 'dword ptr [ebp + 0xc], ecx'),
    (0x538120, 2, 'cmp', 'ecx, edx'),
    (0x538122, 2, 'jg', '0x53812f'),
    (0x538124, 2, 'jl', '0x53812a'),
    (0x538126, 2, 'cmp', 'edi, eax'),
    (0x538128, 2, 'jae', '0x53812f'),
    (0x53812a, 3, 'lea', 'eax, [ebp + 8]'),
    (0x53812d, 2, 'jmp', '0x538132'),
    (0x53812f, 3, 'lea', 'eax, [ebp - 0x10]'),
    (0x538132, 2, 'mov', 'ecx, dword ptr [eax]'),
    (0x538134, 3, 'mov', 'edx, dword ptr [eax + 4]'),
    (0x538137, 6, 'mov', 'dword ptr [esi + 0x1440], ecx'),
    (0x53813d, 6, 'mov', 'dword ptr [esi + 0x1444], edx'),
    (0x538143, 1, 'pop', 'edi'),
    (0x538144, 2, 'mov', 'esp, ebp'),
    (0x538146, 1, 'pop', 'ebp'),
    (0x538147, 3, 'ret', '8'),
)

for address, length, mnemonic, operand in expected_instructions:
    claims.append({
        'id': f'spend_clamp_{address:x}', 'kind': 'instructions', 'space': 'rva',
        'offset': hex(address - base), 'base': hex(address), 'arch': 'x86',
        'length': length, 'mnemonics': [mnemonic], 'operands': [operand] if operand else []
    })

verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]
verified_count = len(claims)

# Negative controls
wrong = dict(claims[0], id='negative_control_spend_clamp', mnemonics=['nop'])
dependent = dict(claims[1], id='negative_dependent_spend_clamp', depends_on=['negative_control_spend_clamp'])
controls = verifier.verify_all([Claim.from_dict(wrong), Claim.from_dict(dependent)])
assert [r['verdict'] for r in controls['results']] == ['REFUTED', 'INVALIDATED']

# 2. Dynamic Unicorn Emulation
sec = next(s for s in pe.sections if s.Name.startswith(b'.text'))
text_data = sec.get_data()
text_base = pe.OPTIONAL_HEADER.ImageBase + sec.VirtualAddress

uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)

code_start = text_base & ~0xFFF
code_size = (len(text_data) + 0xFFF) & ~0xFFF
uc.mem_map(code_start, code_size, unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC)
uc.mem_write(text_base, text_data)

stack_base = 0x00100000
stack_size = 0x00020000
uc.mem_map(stack_base, stack_size, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)

heap_base = 0x00200000
heap_size = 0x00100000
uc.mem_map(heap_base, heap_size, unicorn.UC_PROT_ALL)

country = 0x00200000
party = 0x00210000
uc.mem_write(country + 0xA60, party.to_bytes(4, 'little'))


def run_spending_clamp_emulation(proposed: int, raw_min: int, raw_max: int) -> int:
    uc.mem_write(party + 0xE8, raw_min.to_bytes(4, 'little', signed=True))
    uc.mem_write(party + 0xF0, raw_max.to_bytes(4, 'little', signed=True))
    uc.mem_write(country + 0x1440, (0).to_bytes(8, 'little', signed=True))

    ret_addr = 0x00555555
    esp = 0x0011FF00
    p_lo = proposed & 0xFFFFFFFF
    p_hi = (proposed >> 32) & 0xFFFFFFFF
    uc.mem_write(esp, ret_addr.to_bytes(4, 'little'))
    uc.mem_write(esp + 4, p_lo.to_bytes(4, 'little'))
    uc.mem_write(esp + 8, p_hi.to_bytes(4, 'little'))

    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_EBP, esp)
    uc.reg_write(UC_X86_REG_ESI, country)
    uc.reg_write(UC_X86_REG_EDI, 0x12345678)

    uc.emu_start(0x00538070, ret_addr, timeout=1000000)

    assert uc.reg_read(UC_X86_REG_EDI) == 0x12345678, "EDI clobbered"

    res = int.from_bytes(uc.mem_read(country + 0x1440, 8), 'little', signed=True)
    return res


# Deterministic fixtures
fixtures = [
    # Within bounds
    (10000, 200, 800),
    (16384, 100, 900),
    (20000, 300, 700),
    # Violate min bound (below min)
    (5000, 200, 800),
    (0, 200, 800),
    (-1000, 100, 500),
    # Violate max bound (above max)
    (30000, 200, 800),
    (50000, 100, 500),
    (100000, 0, 1000),
    # Boundary exact points
    (6553, 200, 800),
    (26214, 200, 800),
    # Zero bounds
    (0, 0, 0),
    (100, 0, 0),
    (-100, 0, 0),
    # Full range [0%, 100%]
    (0, 0, 1000),
    (32768, 0, 1000),
    (15000, 0, 1000),
]

# Random fixtures
random.seed(887766)
for _ in range(120):
    raw_min = random.randint(0, 500)
    raw_max = random.randint(raw_min, 1200)
    proposed = random.randint(-5000, 50000)
    fixtures.append((proposed, raw_min, raw_max))

fixture_count = 0
mismatches = 0

for prop, mi, ma in fixtures:
    exp = clamp_spending_slider(prop, mi, ma)
    act = run_spending_clamp_emulation(prop, mi, ma)
    fixture_count += 1
    if act != exp:
        mismatches += 1

assert mismatches == 0, f"{mismatches} mismatches found during country spending clamp emulation"

out = ROOT / 'evidence/generated/country-spending-clamp'
out.mkdir(parents=True, exist_ok=True)
(out / 'claims.json').write_text(json.dumps(claims, indent=2) + '\n')
(out / 'reverify.json').write_text(json.dumps(report, indent=2) + '\n')
(out / 'negative-controls.json').write_text(json.dumps(controls, indent=2) + '\n')
(out / 'emulation.json').write_text(json.dumps({
    'target_digest': digest,
    'total_fixtures': fixture_count,
    'mismatches': mismatches,
    'status': 'PASS'
}, indent=2) + '\n')

ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify')
ledger.record(report, session='country-spending-clamp')
ledger.save()

print(f"Country spending clamp: {verified_count} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Country spending clamp emulation: {fixture_count} fixtures executed, 0 mismatches against country_spending_clamp_model.")
