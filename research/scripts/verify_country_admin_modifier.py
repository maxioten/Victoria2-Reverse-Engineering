#!/usr/bin/env python3
"""Verify CCountry::CalculateAdministrativeSpendingModifier routine (0x00538150..0x005381F2, callers at 0x00509F62 and 0x005077C2)."""
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
from country_admin_modifier_model import compute_admin_spending_modifier

data = (ROOT.parent / 'base-game/v2game.exe').read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = 0x400000

claims = []

# 1. Key instructions in CCountry::CalculateAdministrativeSpendingModifier (0x00538150..0x005381F2)
expected_admin_mod_instructions = (
    (0x00538150, 1, 'push', 'ebp'),
    (0x00538151, 2, 'mov', 'ebp, esp'),
    (0x00538153, 3, 'and', 'esp, 0xfffffff8'),
    (0x00538158, 5, 'push', '0xb733c0'),
    (0x0053816B, 3, 'sub', 'esp, 0x14'),
    (0x00538170, 2, 'mov', 'esi, ecx'),
    (0x00538172, 6, 'mov', 'eax, dword ptr [esi + 0xbcc]'),
    (0x00538178, 3, 'mov', 'eax, dword ptr [eax + 0x7c]'),
    (0x0053817E, 1, 'cdq', ''),
    (0x00538187, 4, 'shld', 'edx, eax, 0x1e'),
    (0x0053818B, 5, 'push', '0x1f40000'),
    (0x00538190, 3, 'shl', 'eax, 0x1e'),
    (0x00538195, 5, 'call', '0xac02a0'),
    (0x0053819A, 7, 'cmp', 'dword ptr [esi + 0x4cc], 0'),
    (0x005381A1, 6, 'lea', 'ecx, [esi + 0xa48]'),
    (0x005381A7, 3, 'mov', 'dword ptr [ebx + 4], edx'),
    (0x005381AB, 2, 'mov', 'dword ptr [ebx], eax'),
    (0x005381B1, 2, 'jg', '0x5381b7'),
    (0x005381B8, 6, 'add', 'esi, 0x12e8'),
    (0x005381BF, 5, 'call', '0x96a2c0'),
    (0x005381C4, 3, 'mov', 'ecx, dword ptr [eax + 4]'),
    (0x005381C7, 2, 'mov', 'edx, dword ptr [eax]'),
    (0x005381CB, 5, 'push', '0x1f40000'),
    (0x005381D2, 5, 'call', '0xac9f20'),
    (0x005381DB, 4, 'shrd', 'eax, edx, 0x1e'),
    (0x005381DF, 2, 'mov', 'dword ptr [edi], eax'),
    (0x005381E2, 2, 'mov', 'eax, edi'),
    (0x005381E4, 3, 'sar', 'edx, 0x1e'),
    (0x005381F2, 1, 'ret', ''),
)

for address, length, mnemonic, operand in expected_admin_mod_instructions:
    claims.append({
        'id': f'admin_mod_ins_{address:x}', 'kind': 'instructions', 'space': 'rva',
        'offset': hex(address - base), 'base': hex(address), 'arch': 'x86',
        'length': length, 'mnemonics': [mnemonic], 'operands': [operand] if operand else []
    })

# 2. Caller site verification in CCountry::DailyUpdate
expected_caller_instructions = (
    (0x00509F5B, 2, 'mov', 'edi, esp'),
    (0x00509F5D, 2, 'mov', 'ecx, ebx'),
    (0x00509F62, 5, 'call', '0x538150'),
    (0x005077BC, 4, 'lea', 'edi, [esp + 0xc]'),
    (0x005077C0, 2, 'mov', 'ecx, esi'),
    (0x005077C2, 5, 'call', '0x538150'),
)

for address, length, mnemonic, operand in expected_caller_instructions:
    claims.append({
        'id': f'admin_caller_ins_{address:x}', 'kind': 'instructions', 'space': 'rva',
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
wrong = dict(claims[0], id='negative_control_admin_mod', mnemonics=['nop'])
dependent = dict(claims[1], id='negative_dependent_admin_mod', depends_on=['negative_control_admin_mod'])
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

# Map zero page for synthetic FS:[0]
uc.mem_map(0, 0x1000)
uc.mem_write(0, struct.pack('<I', 0x12345678))

STACK_BASE = 0x02000000
STACK_SIZE = 0x00100000
uc.mem_map(STACK_BASE, STACK_SIZE)

HEAP_BASE = 0x03000000
uc.mem_map(HEAP_BASE, 0x100000)

COUNTRY_ADDR = HEAP_BASE + 0x1000
TECH_ADDR    = HEAP_BASE + 0x2000
OUT_MOD_ADDR = HEAP_BASE + 0x3000
POLICY_SLOT  = HEAP_BASE + 0x5000

# Install native stub at 0x0096A2C0 to return value from POLICY_SLOT:
# mov eax, [esp + 8]
# mov edx, [0x03005000]
# mov [eax], edx
# mov edx, [0x03005004]
# mov [eax + 4], edx
# ret 0xC
stub_bytes = bytes.fromhex('8b4424088b150050000389108b1504500003895004c20c00')
uc.mem_write(0x0096A2C0, stub_bytes)

uc.mem_write(COUNTRY_ADDR + 0xBCC, struct.pack('<I', TECH_ADDR))

def emu_admin_modifier(tech_val: int, ruling_party_flag: int, policy_mod_val: int) -> int:
    esp = STACK_BASE + 0x80000
    ret_addr = 0x00401000

    uc.mem_write(TECH_ADDR + 0x7C, struct.pack('<i', tech_val))
    uc.mem_write(COUNTRY_ADDR + 0x4CC, struct.pack('<i', ruling_party_flag))
    uc.mem_write(POLICY_SLOT, struct.pack('<q', policy_mod_val))
    uc.mem_write(OUT_MOD_ADDR, struct.pack('<i', 0))

    uc.mem_write(esp, struct.pack('<I', ret_addr))
    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_ECX, COUNTRY_ADDR)
    uc.reg_write(UC_X86_REG_EDI, OUT_MOD_ADDR)

    uc.emu_start(0x00538150, ret_addr)

    return struct.unpack('<i', uc.mem_read(OUT_MOD_ADDR, 4))[0]

# Generate fixtures
fixtures = []

for tech in [-100, 0, 10, 50, 100, 250, 500, 1000]:
    for party in [-1, 0, 1, 2]:
        for pol in [0, 16384, 32768, 49152, 65536, -32768]:
            fixtures.append((tech, party, pol))

random.seed(777666)
for _ in range(80):
    fixtures.append((
        random.randint(-500, 1500),
        random.randint(-10, 10),
        random.randint(-100000, 200000)
    ))

mismatches = 0
for tech, party, pol in fixtures:
    _, exp = compute_admin_spending_modifier(tech, party, pol, pol)
    act = emu_admin_modifier(tech, party, pol)
    if act != exp:
        mismatches += 1
        print(f"Mismatch: tech={tech}, party={party}, pol={pol} -> act={act}, exp={exp}")

assert mismatches == 0, f"{mismatches} mismatches found during country admin modifier emulation"

# Record receipts in evidence/generated/country-admin-modifier/
out = ROOT / 'evidence/generated/country-admin-modifier'
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
ledger.record(report, session='country-admin-modifier')
ledger.save()

print(f"Country admin modifier: {verified_count} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Country admin modifier emulation: {len(fixtures)} fixtures executed, 0 mismatches against country_admin_modifier_model.")
