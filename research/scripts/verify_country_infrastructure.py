#!/usr/bin/env python3
"""Verify CCountry::CalculateNationalInfrastructure routine (0x00530C70..0x00530E3B, caller at 0x00538063)."""
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
from country_infrastructure_model import calculate_national_infrastructure

data = (ROOT.parent / 'base-game/v2game.exe').read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = 0x400000

claims = []

# 1. Key instructions in CCountry::CalculateNationalInfrastructure (0x00530C70..0x00530E3B)
expected_infrastructure_instructions = (
    (0x00530C70, 1, 'push', 'ebp'),
    (0x00530C71, 2, 'mov', 'ebp, esp'),
    (0x00530C88, 3, 'sub', 'esp, 0x2c'),
    (0x00530C8B, 1, 'push', 'ebx'),
    (0x00530C8C, 1, 'push', 'esi'),
    (0x00530C91, 1, 'push', 'edi'),
    (0x00530C92, 3, 'mov', 'edi, dword ptr [ebp + 8]'),
    (0x00530C95, 6, 'mov', 'esi, dword ptr [edi + 0x9d8]'),
    (0x00530CB0, 6, 'cmp', 'esi, dword ptr [edi + 0x9d8]'),
    (0x00530CB6, 2, 'jb', '0x530cde'),
    (0x00530CB8, 6, 'cmp', 'esi, dword ptr [edi + 0x9dc]'),
    (0x00530CBE, 2, 'jae', '0x530cde'),
    (0x00530CC8, 6, 'mov', 'edx, dword ptr [ecx + 0xacc]'),
    (0x00530CCE, 3, 'mov', 'eax, dword ptr [edx + eax*4]'),
    (0x00530CD1, 1, 'push', 'eax'),
    (0x00530CD5, 5, 'call', '0x4b8870'),
    (0x00530CDA, 2, 'add', 'ebx, eax'),
    (0x00530D4B, 6, 'mov', 'eax, dword ptr [esi + 0x234]'),
    (0x00530D51, 6, 'add', 'eax, dword ptr [esi + 0x230]'),
    (0x00530D5A, 4, 'shld', 'edx, eax, 0x1e'),
    (0x00530D5E, 5, 'push', '0x1f40000'),
    (0x00530D63, 3, 'shl', 'eax, 0x1e'),
    (0x00530D68, 5, 'call', '0xac02a0'),
    (0x00530D6F, 6, 'mov', 'eax, dword ptr [esi + 0x238]'),
    (0x00530D78, 4, 'shld', 'edx, eax, 0x1e'),
    (0x00530D7E, 5, 'push', '0x1f40000'),
    (0x00530D83, 3, 'shl', 'eax, 0x1e'),
    (0x00530D88, 5, 'call', '0xac02a0'),
    (0x00530D91, 5, 'call', '0xac9f20'),
    (0x00530D9C, 4, 'shrd', 'eax, edx, 0xf'),
    (0x00530DA0, 3, 'sar', 'edx, 0xf'),
    (0x00530DA3, 3, 'add', 'dword ptr [ebp - 0x2c], eax'),
    (0x00530DA6, 3, 'adc', 'dword ptr [ebp - 0x28], edx'),
    (0x00530DC5, 4, 'shld', 'edx, esi, 0xf'),
    (0x00530DC9, 4, 'shld', 'ecx, eax, 0xf'),
    (0x00530DD7, 5, 'call', '0xac02a0'),
    (0x00530DEB, 4, 'shld', 'edx, eax, 0xf'),
    (0x00530DF6, 5, 'call', '0xac9f20'),
    (0x00530DFB, 4, 'shrd', 'eax, edx, 0xf'),
    (0x00530E02, 6, 'mov', 'dword ptr [edi + 0x1a0], eax'),
    (0x00530E08, 3, 'sar', 'edx, 0xf'),
    (0x00530E0B, 6, 'mov', 'dword ptr [edi + 0x1a4], edx'),
    (0x00530E11, 6, 'mov', 'eax, dword ptr [edi + 0xbdc]'),
    (0x00530E18, 4, 'shld', 'edx, eax, 0xf'),
    (0x00530E1C, 3, 'shl', 'eax, 0xf'),
    (0x00530E1F, 6, 'add', 'dword ptr [edi + 0x1a0], eax'),
    (0x00530E25, 6, 'adc', 'dword ptr [edi + 0x1a4], edx'),
    (0x00530E38, 3, 'ret', '4'),
)

for address, length, mnemonic, operand in expected_infrastructure_instructions:
    claims.append({
        'id': f'infra_ins_{address:x}', 'kind': 'instructions', 'space': 'rva',
        'offset': hex(address - base), 'base': hex(address), 'arch': 'x86',
        'length': length, 'mnemonics': [mnemonic], 'operands': [operand] if operand else []
    })

# Caller
claims.append({
    'id': 'infra_caller_0x00538063', 'kind': 'instructions', 'space': 'rva',
    'offset': hex(0x00538063 - base), 'base': hex(0x00538063), 'arch': 'x86',
    'length': 5, 'mnemonics': ['call'], 'operands': ['0x530c70']
})

verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]
verified_count = len(claims)

# Negative controls
wrong = dict(claims[0], id='negative_control_infrastructure', mnemonics=['nop'])
dependent = dict(claims[1], id='negative_dependent_infrastructure', depends_on=['negative_control_infrastructure'])
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

# Synthetic FS:0 exception-chain slot
uc.mem_map(0, 0x1000, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)

heap_base = 0x00200000
heap_size = 0x00180000
uc.mem_map(heap_base, heap_size, unicorn.UC_PROT_ALL)

# Map singletons
# 0x012588E8 -> 0x00230000
data_page1 = 0x01258000
uc.mem_map(data_page1, 0x2000, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
uc.mem_write(0x012588E8, (0x00230000).to_bytes(4, 'little'))
uc.mem_write(0x00230000 + 0xACC, (0x00240000).to_bytes(4, 'little'))

# 0x0125FDD8 -> 0x00260000
data_page2 = 0x0125F000
uc.mem_map(data_page2, 0x2000, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
uc.mem_write(0x0125FDD8, (0x00260000).to_bytes(4, 'little'))

# Stub for GetProvinceUnits (0x004B8870):
# mov eax, [esp + 4]; mov eax, [eax + 0x10]; ret 4 (8b 44 24 04 8b 40 10 c2 04 00)
uc.mem_write(0x004B8870, b"\x8b\x44\x24\x04\x8b\x40\x10\xc2\x04\x00")


def run_infrastructure_emulation(
    prov_units: list[int],
    tech_entries: list[tuple[bool, int, int, int]],
    base_bonus: int,
):
    country_addr = 0x00200000
    prov_ids_addr = 0x00210000
    tech_manager = 0x00220000
    prov_table_addr = 0x00240000
    tech_obj_addr = 0x00260000
    tech_entries_addr = 0x00270000
    ret_addr = 0x00555555

    # 1. Setup Provinces
    num_provs = len(prov_units)
    for i, u in enumerate(prov_units):
        p_obj = 0x00280000 + i * 0x40
        uc.mem_write(prov_ids_addr + i * 4, i.to_bytes(4, 'little'))
        uc.mem_write(prov_table_addr + i * 4, p_obj.to_bytes(4, 'little'))
        uc.mem_write(p_obj + 0x10, u.to_bytes(4, 'little'))

    uc.mem_write(country_addr + 0x9D8, prov_ids_addr.to_bytes(4, 'little'))
    uc.mem_write(country_addr + 0x9DC, (prov_ids_addr + num_provs * 4).to_bytes(4, 'little'))

    # 2. Setup Tech Manager & Entries
    num_tech = len(tech_entries)
    tech_array = 0x00290000
    uc.mem_write(country_addr + 0xBCC, tech_manager.to_bytes(4, 'little'))
    uc.mem_write(tech_manager + 0x310, tech_array.to_bytes(4, 'little'))

    for j, (active, v234, v230, v238) in enumerate(tech_entries):
        e_obj = 0x002A0000 + j * 0x300
        uc.mem_write(tech_array + j * 4, e_obj.to_bytes(4, 'little'))
        uc.mem_write(tech_entries_addr + j * 4, e_obj.to_bytes(4, 'little'))
        uc.mem_write(e_obj + 0x39, (1 if active else 0).to_bytes(1, 'little'))
        uc.mem_write(e_obj + 0x230, v230.to_bytes(4, 'little', signed=True))
        uc.mem_write(e_obj + 0x234, v234.to_bytes(4, 'little', signed=True))
        uc.mem_write(e_obj + 0x238, v238.to_bytes(4, 'little', signed=True))

    uc.mem_write(tech_obj_addr + 0x0C, tech_entries_addr.to_bytes(4, 'little'))
    uc.mem_write(tech_obj_addr + 0x10, (tech_entries_addr + num_tech * 4).to_bytes(4, 'little'))

    # 3. Setup Country Fields
    uc.mem_write(country_addr + 0xBDC, base_bonus.to_bytes(4, 'little', signed=True))
    uc.mem_write(country_addr + 0x1A0, (0).to_bytes(4, 'little'))
    uc.mem_write(country_addr + 0x1A4, (0).to_bytes(4, 'little'))

    # Stack
    esp = 0x0011FF00
    uc.mem_write(esp, ret_addr.to_bytes(4, 'little'))
    uc.mem_write(esp + 4, country_addr.to_bytes(4, 'little'))

    # Set registers
    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_EBP, esp)
    uc.reg_write(UC_X86_REG_EBX, 0x12345678)
    uc.reg_write(UC_X86_REG_ESI, 0x23456789)
    uc.reg_write(UC_X86_REG_EDI, 0x3456789A)

    uc.emu_start(0x00530C70, ret_addr, timeout=2000000)

    # Read back result
    res_lo = int.from_bytes(uc.mem_read(country_addr + 0x1A0, 4), 'little')
    res_hi = int.from_bytes(uc.mem_read(country_addr + 0x1A4, 4), 'little', signed=True)
    res_64 = (res_hi << 32) | res_lo

    # Check ABI preservation
    assert uc.reg_read(UC_X86_REG_EBX) == 0x12345678, "EBX clobbered"
    assert uc.reg_read(UC_X86_REG_ESI) == 0x23456789, "ESI clobbered"
    assert uc.reg_read(UC_X86_REG_EDI) == 0x3456789A, "EDI clobbered"

    return res_64


# Fixtures
fixtures = [
    # Empty provinces, no tech
    ([], [], 100),
    # Provinces with simple units, 1 active tech
    ([10, 20, 30], [(True, 50000, 10000, 32768)], 50),
    # Multiple active tech entries
    ([5, 15], [(True, 20000, 10000, 16384), (True, 40000, 20000, 32768)], 0),
    # Inactive tech entries mixed with active
    ([100], [(False, 100000, 100000, 100000), (True, 30000, 10000, 32768)], 200),
]

random.seed(334455)
for _ in range(120):
    num_p = random.randint(0, 8)
    p_units = [random.randint(1, 100) for _ in range(num_p)]
    num_t = random.randint(1, 5)
    t_entries = [
        (random.choice([True, False]),
         random.randint(1000, 80000),
         random.randint(1000, 80000),
         random.randint(1000, 65536))
        for _ in range(num_t)
    ]
    # Ensure at least one active entry occasionally
    if not any(t[0] for t in t_entries):
        t_entries[0] = (True, 32768, 16384, 32768)
    b_bonus = random.randint(0, 500)
    fixtures.append((p_units, t_entries, b_bonus))

fixture_count = 0
mismatches = 0

for p_units, t_entries, b_bonus in fixtures:
    exp = calculate_national_infrastructure(p_units, t_entries, b_bonus)
    act = run_infrastructure_emulation(p_units, t_entries, b_bonus)
    fixture_count += 1

    if act != exp:
        mismatches += 1

assert mismatches == 0, f"{mismatches} mismatches found during national infrastructure emulation"

out = ROOT / 'evidence/generated/country-infrastructure'
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
ledger.record(report, session='country-infrastructure')
ledger.save()

print(f"Country infrastructure: {verified_count} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Country infrastructure emulation: {fixture_count} fixtures executed, 0 mismatches against country_infrastructure_model.")
