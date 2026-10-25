#!/usr/bin/env python3
"""Verify province effective life rating calculation and 40.0 max clamp (0x004B9BD0..0x004B9C5F, 0x004B1DC4)."""
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
sys.path.insert(0, str(ROOT / 'src/v2re'))
from province_life_rating_model import compute_effective_life_rating, MAX_EFFECTIVE_LIFE_RATING

data = (ROOT.parent / 'base-game/v2game.exe').read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = 0x400000

claims = []

# 1. Key instructions in CProvince::CalculateEffectiveLifeRating (0x004B9BD0..0x004B9C5F)
expected_life_rating_instructions = (
    (0x004B9BD0, 1, 'push', 'ecx'),
    (0x004B9BD1, 6, 'mov', 'eax, dword ptr [ecx + 0x1a4]'),
    (0x004B9BD7, 1, 'cdq', ''),
    (0x004B9BD8, 4, 'shld', 'edx, eax, 0xf'),
    (0x004B9BDC, 3, 'shl', 'eax, 0xf'),
    (0x004B9BDF, 2, 'mov', 'dword ptr [esi], eax'),
    (0x004B9BE1, 6, 'mov', 'eax, dword ptr [ecx + 0x9c]'),
    (0x004B9BE7, 6, 'mov', 'eax, dword ptr [eax + 0x260]'),
    (0x004B9BED, 3, 'mov', 'dword ptr [esi + 4], edx'),
    (0x004B9BF0, 1, 'cdq', ''),
    (0x004B9BF1, 4, 'shld', 'edx, eax, 0x1e'),
    (0x004B9BF5, 2, 'push', '0'),
    (0x004B9BF7, 5, 'push', '0x1f40000'),
    (0x004B9BFC, 3, 'shl', 'eax, 0x1e'),
    (0x004B9C01, 5, 'call', '0xac02a0'),
    (0x004B9C0C, 5, 'add', 'eax, 0x8000'),
    (0x004B9C12, 3, 'adc', 'edx, 0'),
    (0x004B9C17, 5, 'call', '0xac9f20'),
    (0x004B9C1C, 4, 'shrd', 'eax, edx, 0xf'),
    (0x004B9C20, 3, 'sar', 'edx, 0xf'),
    (0x004B9C32, 6, 'mov', 'dword ptr [esi], 0'),
    (0x004B9C47, 6, 'cmp', 'dword ptr [esi], 0x140000'),
    (0x004B9C4F, 6, 'mov', 'dword ptr [esi], 0x140000'),
    (0x004B9C55, 7, 'mov', 'dword ptr [esi + 4], 0'),
    (0x004B9C5C, 2, 'mov', 'eax, esi'),
    (0x004B9C5F, 1, 'ret', ''),
)

for address, length, mnemonic, operand in expected_life_rating_instructions:
    claims.append({
        'id': f'life_rating_ins_{address:x}', 'kind': 'instructions', 'space': 'rva',
        'offset': hex(address - base), 'base': hex(address), 'arch': 'x86',
        'length': length, 'mnemonics': [mnemonic], 'operands': [operand] if operand else []
    })

# 2. Caller site verification in CProvince::DailyUpdate (0x004B1DBE..0x004B1DC4)
expected_caller_instructions = (
    (0x004B1DBE, 4, 'lea', 'esi, [esp + 0x18]'),
    (0x004B1DC2, 2, 'mov', 'ecx, edi'),
    (0x004B1DC4, 5, 'call', '0x4b9bd0'),
)

for address, length, mnemonic, operand in expected_caller_instructions:
    claims.append({
        'id': f'life_caller_ins_{address:x}', 'kind': 'instructions', 'space': 'rva',
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
wrong = dict(claims[0], id='negative_control_life_rating', mnemonics=['nop'])
dependent = dict(claims[1], id='negative_dependent_life_rating', depends_on=['negative_control_life_rating'])
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

def emu_life_rating(base_lr: int, tech_mod: int) -> int:
    esp = STACK_BASE + 0x80000
    prov_ptr = HEAP_BASE + 0x100
    country_ptr = HEAP_BASE + 0x500
    out_fp_ptr = HEAP_BASE + 0x1000
    
    uc.mem_write(prov_ptr + 0x1A4, struct.pack('<i', base_lr))
    uc.mem_write(prov_ptr + 0x9C, struct.pack('<I', country_ptr))
    uc.mem_write(country_ptr + 0x260, struct.pack('<i', tech_mod))
    
    ret_addr = 0x00401000
    uc.mem_write(esp, struct.pack('<I', ret_addr))
    
    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_ECX, prov_ptr)
    uc.reg_write(UC_X86_REG_ESI, out_fp_ptr)
    
    uc.emu_start(0x004B9BD0, ret_addr)
    
    lo, hi = struct.unpack('<ii', uc.mem_read(out_fp_ptr, 8))
    return (hi << 32) | (lo & 0xFFFFFFFF)

# Generate fixtures
fixtures = []
for lr in [-10, 0, 5, 10, 15, 20, 25, 30, 35, 40, 50]:
    for tm in [-500, -100, 0, 50, 100, 150, 200, 300, 500]:
        fixtures.append((lr, tm))

random.seed(98765)
for _ in range(100):
    fixtures.append((
        random.randint(-15, 60),
        random.randint(-200, 400),
    ))

mismatches = 0
for lr, tm in fixtures:
    exp = compute_effective_life_rating(lr, tm)
    act = emu_life_rating(lr, tm)
    if act != exp:
        mismatches += 1
        print(f"Mismatch: lr={lr}, tm={tm} -> act={act}, exp={exp}")

assert mismatches == 0, f"{mismatches} mismatches found during province life rating emulation"

# Record receipts in evidence/generated/province-life-rating/
out = ROOT / 'evidence/generated/province-life-rating'
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
ledger.record(report, session='province-life-rating')
ledger.save()

print(f"Province life rating: {verified_count} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Province life rating emulation: {len(fixtures)} fixtures executed, 0 mismatches against province_life_rating_model.")
