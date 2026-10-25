#!/usr/bin/env python3
"""Verify CCountry::DailyUpdateMilitarySupply routine (0x00520150..0x00520485, callers at 0x00538055, 0x0068BF20, 0x00524D3F, 0x00662B5F, 0x0067F737)."""
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
from country_military_supply_model import calculate_military_supply_factors

data = (ROOT.parent / 'base-game/v2game.exe').read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = 0x400000

claims = []

# 1. Key instructions in CCountry::DailyUpdateMilitarySupply and callers
expected_instructions = (
    # Callers
    (0x00538055, 5, 'call', '0x520150'),
    (0x0068BF20, 5, 'call', '0x520150'),
    (0x00524D3F, 5, 'call', '0x520150'),
    (0x00662B5F, 5, 'call', '0x520150'),
    (0x0067F737, 5, 'call', '0x520150'),
    # Prologue
    (0x00520150, 1, 'push', 'ebp'),
    (0x00520151, 2, 'mov', 'ebp, esp'),
    (0x00520153, 2, 'push', '-1'),
    (0x00520155, 5, 'push', '0xb8f33e'),
    (0x0052015A, 6, 'mov', 'eax, dword ptr fs:[0]'),
    (0x00520160, 1, 'push', 'eax'),
    (0x00520161, 7, 'mov', 'dword ptr fs:[0], esp'),
    (0x00520168, 6, 'sub', 'esp, 0xdc'),
    (0x0052017A, 3, 'mov', 'ebx, dword ptr [ebp + 8]'),
    # Calculation
    (0x005203E3, 6, 'mov', 'ecx, dword ptr [ebx + 0xbcc]'),
    (0x005203E9, 3, 'mov', 'edx, dword ptr [ecx + 0x60]'),
    (0x005203EC, 6, 'mov', 'esi, dword ptr [0x12586dc]'),
    (0x005203F2, 3, 'mov', 'ecx, dword ptr [esi + 0x40]'),
    (0x005203F5, 3, 'mov', 'ecx, dword ptr [ecx + 0x10]'),
    (0x005203F8, 6, 'mov', 'eax, dword ptr [ebx + 0xa60]'),
    (0x005203FE, 6, 'mov', 'eax, dword ptr [eax + 0x380]'),
    (0x00520404, 2, 'add', 'ecx, edx'),
    (0x00520406, 2, 'add', 'eax, ecx'),
    (0x00520408, 1, 'cdq', ''),
    (0x00520409, 4, 'shld', 'edx, eax, 0xf'),
    (0x0052040D, 3, 'shl', 'eax, 0xf'),
    (0x00520410, 4, 'shld', 'edx, eax, 0xf'),
    (0x00520414, 2, 'xor', 'edi, edi'),
    (0x00520416, 1, 'push', 'edi'),
    (0x00520417, 5, 'push', '0x1f40000'),
    (0x0052041C, 3, 'shl', 'eax, 0xf'),
    (0x0052041F, 1, 'push', 'edx'),
    (0x00520420, 1, 'push', 'eax'),
    (0x00520421, 5, 'call', '0xac02a0'),
    (0x00520426, 3, 'mov', 'dword ptr [ebp - 0x54], eax'),
    (0x00520429, 6, 'mov', 'dword ptr [ebx + 0x14e0], edi'),
    (0x0052042F, 3, 'mov', 'eax, dword ptr [esi + 0x40]'),
    (0x00520432, 3, 'mov', 'eax, dword ptr [eax + 0x70]'),
    (0x00520435, 3, 'mov', 'dword ptr [ebp - 0x50], edx'),
    (0x00520438, 1, 'cdq', ''),
    (0x00520439, 4, 'shld', 'edx, eax, 0xf'),
    (0x0052043D, 3, 'shl', 'eax, 0xf'),
    (0x00520440, 4, 'shld', 'edx, eax, 0xf'),
    (0x00520444, 1, 'push', 'edi'),
    (0x00520445, 5, 'push', '0x1f40000'),
    (0x0052044A, 3, 'shl', 'eax, 0xf'),
    (0x0052044D, 1, 'push', 'edx'),
    (0x0052044E, 1, 'push', 'eax'),
    (0x0052044F, 5, 'call', '0xac02a0'),
    (0x00520454, 6, 'mov', 'ecx, dword ptr [0x1258a48]'),
    (0x0052045A, 6, 'mov', 'dword ptr [ebp - 0xa4], eax'),
    (0x00520478, 6, 'mov', 'dword ptr [ebx + 0x13e8], edi'),
)

for address, length, mnemonic, operand in expected_instructions:
    claims.append({
        'id': f'mil_supply_{address:x}', 'kind': 'instructions', 'space': 'rva',
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
wrong = dict(claims[0], id='negative_control_mil_supply', mnemonics=['nop'])
dependent = dict(claims[1], id='negative_dependent_mil_supply', depends_on=['negative_control_mil_supply'])
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
tech_mgr = 0x00220000
defines_obj = 0x00230000
defines_sub = 0x00240000
page_singleton = 0x01258000
uc.mem_map(page_singleton, 0x2000, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
uc.mem_write(0x012586DC, defines_obj.to_bytes(4, 'little'))
uc.mem_write(defines_obj + 0x40, defines_sub.to_bytes(4, 'little'))

dummy_vec1 = 0x00260000
dummy_vec2 = 0x00270000
uc.mem_write(0x01258A48, dummy_vec1.to_bytes(4, 'little'))
uc.mem_write(0x01258A3C, dummy_vec2.to_bytes(4, 'little'))
uc.mem_write(dummy_vec1 + 0x18, (0x00280000).to_bytes(4, 'little'))
uc.mem_write(dummy_vec1 + 0x1C, (0x00280000).to_bytes(4, 'little'))
uc.mem_write(dummy_vec2 + 0x0C, (0x00290000).to_bytes(4, 'little'))
uc.mem_write(dummy_vec2 + 0x10, (0x00290000).to_bytes(4, 'little'))

uc.mem_write(country + 0xA60, party.to_bytes(4, 'little'))
uc.mem_write(country + 0xBCC, tech_mgr.to_bytes(4, 'little'))


def run_military_supply_emulation(
    party_bonus: int,
    global_base: int,
    tech_bonus: int,
    sec_supply: int,
) -> tuple[int, int]:
    uc.mem_write(party + 0x380, party_bonus.to_bytes(4, 'little', signed=True))
    uc.mem_write(defines_sub + 0x10, global_base.to_bytes(4, 'little', signed=True))
    uc.mem_write(tech_mgr + 0x60, tech_bonus.to_bytes(4, 'little', signed=True))
    uc.mem_write(defines_sub + 0x70, sec_supply.to_bytes(4, 'little', signed=True))

    # Pre-pollute maintenance pools to verify they are cleared to zero
    uc.mem_write(country + 0x14E0, (0x12345678).to_bytes(4, 'little'))
    uc.mem_write(country + 0x13E8, (0x87654321).to_bytes(4, 'little'))

    esp = 0x0011FE00
    ebp = 0x0011FF00
    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_EBP, ebp)
    uc.reg_write(UC_X86_REG_EBX, country)

    # Run from 0x005203E3 through factor calculation and pool resets up to 0x0052047E
    uc.emu_start(0x005203E3, 0x0052047E, timeout=1000000)

    # Verify maintenance pools were reset to 0
    assert int.from_bytes(uc.mem_read(country + 0x14E0, 4), 'little') == 0, "pool_14e0 not cleared"
    assert int.from_bytes(uc.mem_read(country + 0x13E8, 4), 'little') == 0, "pool_13e8 not cleared"

    # Read back primary and secondary factors
    f1_lo = int.from_bytes(uc.mem_read(ebp - 0x54, 4), 'little')
    f1_hi = int.from_bytes(uc.mem_read(ebp - 0x50, 4), 'little', signed=True)
    f1 = (f1_hi << 32) | f1_lo

    f2 = int.from_bytes(uc.mem_read(ebp - 0xA4, 4), 'little', signed=True)
    return f1, f2


# Deterministic fixtures
fixtures = [
    # Standard baseline
    (100, 200, 300, 500),
    # Zero bonuses
    (0, 0, 0, 0),
    # High technology bonus
    (0, 1000, 2500, 1000),
    # Negative policy penalties
    (-200, 500, 100, 200),
    # High base supply
    (500, 5000, 1000, 3000),
    # Negative secondary supply
    (100, 200, 300, -100),
]

# Random fixtures
random.seed(332211)
for _ in range(120):
    p_b = random.randint(-500, 2000)
    g_b = random.randint(0, 5000)
    t_b = random.randint(0, 3000)
    s_s = random.randint(-200, 4000)
    fixtures.append((p_b, g_b, t_b, s_s))

fixture_count = 0
mismatches = 0

for p_b, g_b, t_b, s_s in fixtures:
    exp = calculate_military_supply_factors(p_b, g_b, t_b, s_s)
    act = run_military_supply_emulation(p_b, g_b, t_b, s_s)
    fixture_count += 1
    if act != exp:
        mismatches += 1

assert mismatches == 0, f"{mismatches} mismatches found during country military supply factor emulation"

out = ROOT / 'evidence/generated/country-military-supply'
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
ledger.record(report, session='country-military-supply')
ledger.save()

print(f"Country military supply: {verified_count} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Country military supply emulation: {fixture_count} fixtures executed, 0 mismatches against country_military_supply_model.")
