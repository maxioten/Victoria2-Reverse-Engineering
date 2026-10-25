#!/usr/bin/env python3
"""Verify CCountry::CalculateCategorySpending routine (0x00539760..0x00539874, caller at 0x00539910)."""
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
from country_category_spending_model import calculate_category_spending

data = (ROOT.parent / 'base-game/v2game.exe').read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = 0x400000

claims = []

# 1. Key instructions in CCountry::CalculateCategorySpending (0x00539760..0x00539874)
expected_spending_instructions = (
    (0x00539760, 1, 'push', 'ebp'),
    (0x00539761, 2, 'mov', 'ebp, esp'),
    (0x00539763, 3, 'sub', 'esp, 0x14'),
    (0x00539766, 1, 'push', 'ebx'),
    (0x00539767, 3, 'mov', 'ebx, dword ptr [ebp + 8]'),
    (0x0053976A, 1, 'push', 'edi'),
    (0x0053976B, 2, 'mov', 'edi, eax'),
    (0x0053976D, 8, 'movzx', 'ecx, byte ptr [edi + ebx + 0xecc]'),
    (0x00539775, 6, 'mov', 'eax, dword ptr [edi + 0xf0c]'),
    (0x0053977B, 3, 'mov', 'edx, dword ptr [eax + ecx*8]'),
    (0x0053977E, 4, 'mov', 'eax, dword ptr [eax + ecx*8 + 4]'),
    (0x00539782, 6, 'mov', 'ecx, dword ptr [edi + 0x1448]'),
    (0x00539788, 1, 'push', 'eax'),
    (0x00539789, 6, 'mov', 'eax, dword ptr [edi + 0x144c]'),
    (0x0053978F, 1, 'push', 'edx'),
    (0x00539790, 1, 'push', 'eax'),
    (0x00539791, 1, 'push', 'ecx'),
    (0x00539792, 5, 'call', '0xac9f20'),
    (0x00539797, 8, 'movzx', 'ecx, byte ptr [edi + ebx + 0xf24]'),
    (0x0053979F, 4, 'shrd', 'eax, edx, 0xf'),
    (0x005397A3, 3, 'sar', 'edx, 0xf'),
    (0x005397A6, 3, 'mov', 'dword ptr [esi + 4], edx'),
    (0x005397A9, 6, 'mov', 'edx, dword ptr [edi + 0x1454]'),
    (0x005397AF, 2, 'mov', 'dword ptr [esi], eax'),
    (0x005397B1, 6, 'mov', 'eax, dword ptr [edi + 0x1450]'),
    (0x005397B7, 1, 'push', 'edx'),
    (0x005397B8, 1, 'push', 'eax'),
    (0x005397B9, 6, 'mov', 'eax, dword ptr [edi + 0xf64]'),
    (0x005397BF, 4, 'mov', 'edx, dword ptr [eax + ecx*8 + 4]'),
    (0x005397C3, 3, 'mov', 'eax, dword ptr [eax + ecx*8]'),
    (0x005397C6, 1, 'push', 'edx'),
    (0x005397C7, 1, 'push', 'eax'),
    (0x005397C8, 5, 'call', '0xac9f20'),
    (0x005397CD, 8, 'movzx', 'ecx, byte ptr [edi + ebx + 0xf7c]'),
    (0x005397D5, 4, 'shrd', 'eax, edx, 0xf'),
    (0x005397D9, 3, 'sar', 'edx, 0xf'),
    (0x005397DC, 2, 'add', 'dword ptr [esi], eax'),
    (0x005397DE, 6, 'mov', 'eax, dword ptr [edi + 0xfbc]'),
    (0x005397E4, 3, 'adc', 'dword ptr [esi + 4], edx'),
    (0x005397E7, 3, 'mov', 'edx, dword ptr [eax + ecx*8]'),
    (0x005397EA, 2, 'add', 'dword ptr [esi], edx'),
    (0x005397EC, 4, 'mov', 'eax, dword ptr [eax + ecx*8 + 4]'),
    (0x005397F0, 6, 'mov', 'ecx, dword ptr [edi + 0x145c]'),
    (0x005397F6, 3, 'adc', 'dword ptr [esi + 4], eax'),
    (0x005397F9, 8, 'movzx', 'eax, byte ptr [edi + ebx + 0xfd4]'),
    (0x00539801, 6, 'mov', 'edx, dword ptr [edi + 0x1458]'),
    (0x00539807, 6, 'mov', 'edi, dword ptr [edi + 0x1014]'),
    (0x0053980D, 1, 'push', 'ecx'),
    (0x0053980E, 4, 'mov', 'ecx, dword ptr [edi + eax*8 + 4]'),
    (0x00539812, 1, 'push', 'edx'),
    (0x00539813, 3, 'mov', 'edx, dword ptr [edi + eax*8]'),
    (0x00539816, 1, 'push', 'ecx'),
    (0x00539817, 1, 'push', 'edx'),
    (0x00539818, 5, 'call', '0xac9f20'),
    (0x0053981D, 4, 'shrd', 'eax, edx, 0xf'),
    (0x00539821, 3, 'sar', 'edx, 0xf'),
    (0x00539824, 2, 'add', 'dword ptr [esi], eax'),
    (0x00539826, 2, 'mov', 'ecx, dword ptr [esi]'),
    (0x00539828, 4, 'xorpd', 'xmm0, xmm0'),
    (0x0053982C, 5, 'movlpd', 'qword ptr [ebp - 0x14], xmm0'),
    (0x00539831, 3, 'mov', 'dword ptr [ebp - 0xc], ecx'),
    (0x00539834, 3, 'adc', 'dword ptr [esi + 4], edx'),
    (0x00539837, 3, 'mov', 'eax, dword ptr [esi + 4]'),
    (0x0053983A, 3, 'mov', 'dword ptr [ebp - 8], eax'),
    (0x0053983D, 2, 'test', 'eax, eax'),
    (0x0053983F, 2, 'jl', '0x53985e'),
    (0x00539841, 2, 'jg', '0x539847'),
    (0x00539843, 2, 'test', 'ecx, ecx'),
    (0x00539845, 2, 'je', '0x53985e'),
    (0x00539847, 3, 'lea', 'eax, [ebp - 0xc]'),
    (0x0053984A, 2, 'mov', 'ecx, dword ptr [eax]'),
    (0x0053984C, 3, 'mov', 'edx, dword ptr [eax + 4]'),
    (0x0053984F, 2, 'mov', 'dword ptr [esi], ecx'),
    (0x00539851, 3, 'mov', 'dword ptr [esi + 4], edx'),
    (0x00539854, 2, 'mov', 'eax, esi'),
    (0x00539856, 1, 'pop', 'edi'),
    (0x00539857, 1, 'pop', 'ebx'),
    (0x00539858, 2, 'mov', 'esp, ebp'),
    (0x0053985A, 1, 'pop', 'ebp'),
    (0x0053985B, 3, 'ret', '4'),
    (0x0053985E, 3, 'lea', 'eax, [ebp - 0x14]'),
    (0x00539861, 2, 'mov', 'ecx, dword ptr [eax]'),
    (0x00539863, 3, 'mov', 'edx, dword ptr [eax + 4]'),
    (0x00539866, 1, 'pop', 'edi'),
    (0x00539867, 2, 'mov', 'dword ptr [esi], ecx'),
    (0x00539869, 3, 'mov', 'dword ptr [esi + 4], edx'),
    (0x0053986C, 2, 'mov', 'eax, esi'),
    (0x0053986E, 1, 'pop', 'ebx'),
    (0x0053986F, 2, 'mov', 'esp, ebp'),
    (0x00539871, 1, 'pop', 'ebp'),
    (0x00539872, 3, 'ret', '4'),
)

for address, length, mnemonic, operand in expected_spending_instructions:
    claims.append({
        'id': f'spend_ins_{address:x}', 'kind': 'instructions', 'space': 'rva',
        'offset': hex(address - base), 'base': hex(address), 'arch': 'x86',
        'length': length, 'mnemonics': [mnemonic], 'operands': [operand] if operand else []
    })

# 2. Confirmed Callers
callers = (
    (0x00539910, 'call', '0x539760'),
    (0x00663027, 'call', '0x539760'),
    (0x0071DCFE, 'call', '0x539760'),
    (0x007205A1, 'call', '0x539760'),
)

for address, mnemonic, operand in callers:
    claims.append({
        'id': f'spend_caller_{address:x}', 'kind': 'instructions', 'space': 'rva',
        'offset': hex(address - base), 'base': hex(address), 'arch': 'x86',
        'length': 5, 'mnemonics': [mnemonic], 'operands': [operand]
    })

verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]
verified_count = len(claims)

# Negative controls
wrong = dict(claims[0], id='negative_control_category_spending', mnemonics=['nop'])
dependent = dict(claims[1], id='negative_dependent_category_spending', depends_on=['negative_control_category_spending'])
controls = verifier.verify_all([Claim.from_dict(wrong), Claim.from_dict(dependent)])
assert [r['verdict'] for r in controls['results']] == ['REFUTED', 'INVALIDATED']

# 3. Dynamic Unicorn Emulation
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


def run_spending_emulation(
    s1: int, s2: int, s3: int,
    b1: int, b2: int, b3: int, b4: int,
    cat_idx: int = 0
):
    country_addr = 0x00200000
    t1_addr = 0x00210000
    t2_addr = 0x00220000
    t3_addr = 0x00230000
    t4_addr = 0x00240000
    out_buf = 0x00250000
    ret_addr = 0x00555555

    # Write tables
    def pack_i64(v):
        return (v & 0xFFFFFFFFFFFFFFFF).to_bytes(8, 'little', signed=False)

    # Set up category index and sub-indices (all pointing to index 1 in their respective tables)
    uc.mem_write(country_addr + cat_idx + 0xECC, (1).to_bytes(1, 'little'))
    uc.mem_write(country_addr + cat_idx + 0xF24, (1).to_bytes(1, 'little'))
    uc.mem_write(country_addr + cat_idx + 0xF7C, (1).to_bytes(1, 'little'))
    uc.mem_write(country_addr + cat_idx + 0xFD4, (1).to_bytes(1, 'little'))

    # Table pointers
    uc.mem_write(country_addr + 0xF0C, t1_addr.to_bytes(4, 'little'))
    uc.mem_write(country_addr + 0xF64, t2_addr.to_bytes(4, 'little'))
    uc.mem_write(country_addr + 0xFBC, t3_addr.to_bytes(4, 'little'))
    uc.mem_write(country_addr + 0x1014, t4_addr.to_bytes(4, 'little'))

    # Table values at index 1 (offset 8)
    uc.mem_write(t1_addr + 8, pack_i64(b1))
    uc.mem_write(t2_addr + 8, pack_i64(b2))
    uc.mem_write(t3_addr + 8, pack_i64(b3))
    uc.mem_write(t4_addr + 8, pack_i64(b4))

    # Sliders
    uc.mem_write(country_addr + 0x1448, pack_i64(s1))
    uc.mem_write(country_addr + 0x1450, pack_i64(s2))
    uc.mem_write(country_addr + 0x1458, pack_i64(s3))

    # Stack setup
    # Call pushes [cat_idx] then [ret_addr]
    esp = 0x0011FFE0
    uc.mem_write(esp, ret_addr.to_bytes(4, 'little'))
    uc.mem_write(esp + 4, cat_idx.to_bytes(4, 'little'))

    # Clear output buffer
    uc.mem_write(out_buf, b"\x00" * 8)

    # Set registers
    uc.reg_write(UC_X86_REG_EAX, country_addr)
    uc.reg_write(UC_X86_REG_ESI, out_buf)
    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_EBP, esp)
    uc.reg_write(UC_X86_REG_EBX, 0x12345678)
    uc.reg_write(UC_X86_REG_EDI, 0x87654321)

    uc.emu_start(0x00539760, ret_addr, timeout=2000000)

    # Read back result
    res_bytes = uc.mem_read(out_buf, 8)
    res_val = int.from_bytes(res_bytes, 'little', signed=True)

    # Verify ABI preservation
    assert uc.reg_read(UC_X86_REG_EBX) == 0x12345678, "EBX clobbered"
    assert uc.reg_read(UC_X86_REG_EDI) == 0x87654321, "EDI clobbered"
    assert uc.reg_read(UC_X86_REG_EAX) == out_buf, "EAX did not return ESI"

    return res_val


# 4. Generate exhaustive fixtures
fixtures = [
    # Zero values
    (0, 0, 0, 0, 0, 0, 0),
    # Standard positive scaling (slider=32768 corresponds to 1.0x factor)
    (32768, 32768, 32768, 100, 200, 50, 300),
    # 50% sliders (16384)
    (16384, 16384, 16384, 1000, 2000, 100, 3000),
    # High sliders (200% = 65536)
    (65536, 65536, 65536, 500, 1000, 250, 1500),
    # Negative base3 causing non-positive sum -> clamped to 0
    (32768, 32768, 32768, 100, 100, -1000, 100),
    # Negative base3 exactly cancelling -> clamped to 0
    (32768, 32768, 32768, 100, 100, -300, 100),
    # Asymmetric sliders
    (32768, 0, 16384, 1500, 2000, 0, 800),
    (0, 32768, 0, 5000, 4000, 100, 2000),
]

random.seed(991122)
for _ in range(150):
    s1 = random.randint(0, 100000)
    s2 = random.randint(0, 100000)
    s3 = random.randint(0, 100000)
    b1 = random.randint(0, 50000)
    b2 = random.randint(0, 50000)
    b3 = random.randint(-100000, 50000)
    b4 = random.randint(0, 50000)
    fixtures.append((s1, s2, s3, b1, b2, b3, b4))

fixture_count = 0
mismatches = 0

for s1, s2, s3, b1, b2, b3, b4 in fixtures:
    exp = calculate_category_spending(s1, s2, s3, b1, b2, b3, b4)
    act = run_spending_emulation(s1, s2, s3, b1, b2, b3, b4)
    fixture_count += 1

    if act != exp:
        mismatches += 1

assert mismatches == 0, f"{mismatches} mismatches found during category spending emulation"

out = ROOT / 'evidence/generated/country-category-spending'
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
ledger.record(report, session='country-category-spending')
ledger.save()

print(f"Country category spending: {verified_count} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Country category spending emulation: {fixture_count} fixtures executed, 0 mismatches against country_category_spending_model.")
