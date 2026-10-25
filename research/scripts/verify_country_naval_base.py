#!/usr/bin/env python3
"""Verify CCountry::CalculateNavalBaseScore routine (0x0052FCD0..0x00530020, caller at 0x0053805D)."""
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
from country_naval_base_model import calculate_naval_base_contribution

data = (ROOT.parent / 'base-game/v2game.exe').read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = 0x400000

claims = []

# 1. Key instructions in CCountry::CalculateNavalBaseScore
expected_instructions = (
    # Caller
    (0x0053805D, 5, 'call', '0x52fcd0'),
    # Function prologue
    (0x0052FCD0, 1, 'push', 'ebp'),
    (0x0052FCD1, 2, 'mov', 'ebp, esp'),
    (0x0052FCD3, 3, 'and', 'esp, 0xfffffff8'),
    (0x0052FCD6, 2, 'push', '-1'),
    (0x0052FCD8, 5, 'push', '0xb8f303'),
    (0x0052FCDD, 6, 'mov', 'eax, dword ptr fs:[0]'),
    # Reset
    (0x0052FD10, 3, 'cmp', 'dword ptr [ebp + 0xc], ebx'),
    (0x0052FD13, 2, 'jne', '0x52fd21'),
    (0x0052FD15, 6, 'mov', 'dword ptr [eax + 0x198], ebx'),
    (0x0052FD1B, 6, 'mov', 'dword ptr [eax + 0x19c], ebx'),
    # Calculation
    (0x0052FF12, 5, 'mov', 'eax, 0x51eb851f'),
    (0x0052FF17, 4, 'imul', 'dword ptr [esp + 0x14]'),
    (0x0052FF1B, 3, 'sar', 'edx, 5'),
    (0x0052FF1E, 2, 'mov', 'ecx, edx'),
    (0x0052FF20, 3, 'shr', 'ecx, 0x1f'),
    (0x0052FF23, 2, 'add', 'ecx, edx'),
    (0x0052FF25, 5, 'mov', 'eax, 0x51eb851f'),
    (0x0052FF2A, 4, 'imul', 'dword ptr [esp + 0x28]'),
    (0x0052FF2E, 3, 'sar', 'edx, 5'),
    (0x0052FF31, 2, 'mov', 'eax, edx'),
    (0x0052FF33, 3, 'shr', 'eax, 0x1f'),
    (0x0052FF36, 2, 'add', 'eax, edx'),
    (0x0052FF38, 1, 'cdq', ''),
    (0x0052FF39, 2, 'mov', 'esi, eax'),
    (0x0052FF3B, 2, 'mov', 'edi, edx'),
    (0x0052FF3D, 2, 'mov', 'eax, ecx'),
    (0x0052FF3F, 4, 'shld', 'edi, esi, 0xf'),
    (0x0052FF43, 1, 'cdq', ''),
    (0x0052FF44, 4, 'shld', 'edx, eax, 0x1e'),
    (0x0052FF48, 1, 'push', 'edi'),
    (0x0052FF49, 3, 'shl', 'esi, 0xf'),
    (0x0052FF4C, 1, 'push', 'esi'),
    (0x0052FF4D, 3, 'shl', 'eax, 0x1e'),
    (0x0052FF50, 1, 'push', 'edx'),
    (0x0052FF51, 1, 'push', 'eax'),
    (0x0052FF52, 5, 'call', '0xac02a0'),
    (0x0052FF57, 2, 'mov', 'edi, eax'),
    (0x0052FF59, 6, 'fld', 'qword ptr [0xe45820]'),
    (0x0052FF5F, 2, 'mov', 'esi, edx'),
    (0x0052FF61, 5, 'call', '0xb31c36'),
    (0x0052FF66, 2, 'cmp', 'esi, edx'),
    (0x0052FF68, 2, 'jg', '0x52ff74'),
    (0x0052FF6A, 2, 'jl', '0x52ff70'),
    (0x0052FF6C, 2, 'cmp', 'edi, eax'),
    (0x0052FF6E, 2, 'jae', '0x52ff74'),
    (0x0052FF70, 2, 'mov', 'edi, eax'),
    (0x0052FF72, 2, 'mov', 'esi, edx'),
    (0x0052FF74, 2, 'cmp', 'esi, ebx'),
    (0x0052FF76, 2, 'jl', '0x52ff89'),
    (0x0052FF78, 2, 'jg', '0x52ff82'),
    (0x0052FF7A, 6, 'cmp', 'edi, 0x8000'),
    (0x0052FF80, 2, 'jbe', '0x52ff89'),
    (0x0052FF82, 5, 'mov', 'edi, 0x8000'),
    (0x0052FF87, 2, 'xor', 'esi, esi'),
    (0x0052FF89, 4, 'mov', 'eax, dword ptr [esp + 0x24]'),
    (0x0052FF8D, 4, 'mov', 'ecx, dword ptr [esp + 0x20]'),
    (0x0052FF91, 1, 'push', 'eax'),
    (0x0052FF92, 1, 'push', 'ecx'),
    (0x0052FF93, 1, 'push', 'esi'),
    (0x0052FF94, 1, 'push', 'edi'),
    (0x0052FF95, 5, 'call', '0xac9f20'),
    (0x0052FF9A, 2, 'mov', 'esi, edx'),
    (0x0052FF9C, 2, 'mov', 'edi, eax'),
    (0x0052FF9E, 4, 'shrd', 'edi, esi, 0xf'),
    (0x0052FFA2, 3, 'sar', 'esi, 0xf'),
    (0x0052FFA5, 3, 'cmp', 'dword ptr [ebp + 0xc], ebx'),
    (0x0052FFA8, 2, 'jne', '0x52ffbb'),
    (0x0052FFAA, 3, 'mov', 'eax, dword ptr [ebp + 8]'),
    (0x0052FFAD, 6, 'add', 'dword ptr [eax + 0x198], edi'),
    (0x0052FFB3, 6, 'adc', 'dword ptr [eax + 0x19c], esi'),
    (0x0052FFB9, 2, 'jmp', '0x52fffc'),
)

for address, length, mnemonic, operand in expected_instructions:
    claims.append({
        'id': f'naval_ins_{address:x}', 'kind': 'instructions', 'space': 'rva',
        'offset': hex(address - base), 'base': hex(address), 'arch': 'x86',
        'length': length, 'mnemonics': [mnemonic], 'operands': [operand] if operand else []
    })

claims.append({
    'id': 'naval_base_floor_const', 'kind': 'bytes_at', 'space': 'rva',
    'offset': hex(0x00E45820 - base), 'expected': struct.pack('<d', 1638.9000244140625).hex()
})

verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]
verified_count = len(claims)

# Negative controls
wrong = dict(claims[0], id='negative_control_naval_base', mnemonics=['nop'])
dependent = dict(claims[1], id='negative_dependent_naval_base', depends_on=['negative_control_naval_base'])
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

rdata_sec = next(s for s in pe.sections if s.Name.startswith(b'.rdata'))
r_data = rdata_sec.get_data()
r_base = base + rdata_sec.VirtualAddress
r_start = r_base & ~0xFFF
r_size = (len(r_data) + 0xFFF) & ~0xFFF
uc.mem_map(r_start, r_size, unicorn.UC_PROT_READ)
uc.mem_write(r_base, r_data)

stack_base = 0x00100000
stack_size = 0x00020000
uc.mem_map(stack_base, stack_size, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)

heap_base = 0x00200000
heap_size = 0x00100000
uc.mem_map(heap_base, heap_size, unicorn.UC_PROT_ALL)

country = 0x00200000


def run_naval_emulation(val_14: int, val_28: int, base_weight: int, init_score: int) -> int:
    uc.mem_write(country + 0x198, init_score.to_bytes(8, 'little', signed=True))

    esp = 0x0011FE00
    ebp = 0x0011FF00

    uc.mem_write(ebp + 8, country.to_bytes(4, 'little'))
    uc.mem_write(ebp + 0xC, (0).to_bytes(4, 'little'))

    uc.mem_write(esp + 0x14, val_14.to_bytes(4, 'little', signed=True))
    uc.mem_write(esp + 0x28, val_28.to_bytes(4, 'little', signed=True))
    bw_lo = base_weight & 0xFFFFFFFF
    bw_hi = (base_weight >> 32) & 0xFFFFFFFF
    uc.mem_write(esp + 0x20, bw_lo.to_bytes(4, 'little'))
    uc.mem_write(esp + 0x24, bw_hi.to_bytes(4, 'little'))

    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_EBP, ebp)
    uc.reg_write(UC_X86_REG_EBX, 0)

    uc.emu_start(0x0052FF12, 0x0052FFB9, timeout=2000000)

    res = int.from_bytes(uc.mem_read(country + 0x198, 8), 'little', signed=True)
    return res


# Deterministic fixtures
fixtures = [
    # Ratio = 0.5 (within [0.05, 1.0])
    (5000, 10000, 100000, 0),
    # Ratio = 0.01 (violates floor 5% -> clamped to 1638)
    (100, 10000, 100000, 0),
    # Ratio = 2.0 (violates ceiling 100% -> clamped to 32768)
    (20000, 10000, 100000, 0),
    # Exact ratio = 1.0 (boundary 32768)
    (10000, 10000, 50000, 1200),
    # Ratio = 0.75
    (7500, 10000, 80000, 500),
    # Exact floor boundary (ratio = 0.05)
    (500, 10000, 65536, 0),
    # High initial accumulator
    (6000, 10000, 40000, 999999),
]

# Random fixtures
random.seed(443322)
for _ in range(120):
    v28 = random.randint(1000, 50000)
    # Range of v14 to cover under 5%, between 5% and 100%, and above 100%
    v14 = random.randint(50, v28 * 2)
    b_weight = random.randint(1000, 200000)
    ini = random.randint(0, 500000)
    fixtures.append((v14, v28, b_weight, ini))

fixture_count = 0
mismatches = 0

for v14, v28, bw, ini in fixtures:
    exp = calculate_naval_base_contribution(v14, v28, bw, ini)
    act = run_naval_emulation(v14, v28, bw, ini)
    fixture_count += 1
    if act != exp:
        mismatches += 1

assert mismatches == 0, f"{mismatches} mismatches found during country naval base emulation"

out = ROOT / 'evidence/generated/country-naval-base'
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
ledger.record(report, session='country-naval-base')
ledger.save()

print(f"Country naval base: {verified_count} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Country naval base emulation: {fixture_count} fixtures executed, 0 mismatches against country_naval_base_model.")
