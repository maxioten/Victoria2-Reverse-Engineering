#!/usr/bin/env python3
"""Verify CProvincePromotionBuffer::AllocateTargetQuota routine (0x004EE150..0x004EE2FB, callers at 0x004C1412, 0x004D1638, 0x004EF185, 0x005221B0)."""
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
from province_target_quota_model import calculate_target_quota_allocations

data = (ROOT.parent / 'base-game/v2game.exe').read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = 0x400000

claims = []

# 1. Key instructions in CProvincePromotionBuffer::AllocateTargetQuota and callers
expected_instructions = (
    # 4 Callers
    (0x004C1412, 5, 'call', '0x4ee150'),
    (0x004D1638, 5, 'call', '0x4ee150'),
    (0x004EF185, 5, 'call', '0x4ee150'),
    (0x005221B0, 5, 'call', '0x4ee150'),
    # Function body
    (0x4ee150, 1, 'push', 'ebp'),
    (0x4ee151, 2, 'mov', 'ebp, esp'),
    (0x4ee153, 3, 'mov', 'eax, dword ptr [ebp + 8]'),
    (0x4ee156, 3, 'sub', 'esp, 8'),
    (0x4ee159, 1, 'push', 'ebx'),
    (0x4ee15a, 3, 'mov', 'ebx, dword ptr [ebp + 0x10]'),
    (0x4ee15d, 1, 'push', 'esi'),
    (0x4ee15e, 3, 'mov', 'esi, dword ptr [eax + 0x48]'),
    (0x4ee161, 2, 'sub', 'ebx, esi'),
    (0x4ee163, 1, 'push', 'edi'),
    (0x4ee164, 6, 'je', '0x4ee2f5'),
    (0x4ee16a, 3, 'mov', 'ecx, dword ptr [ebp + 0x14]'),
    (0x4ee16d, 3, 'mov', 'edi, dword ptr [ebp + 0x18]'),
    (0x4ee170, 2, 'mov', 'edx, ecx'),
    (0x4ee172, 2, 'or', 'edx, edi'),
    (0x4ee174, 6, 'je', '0x4ee2f5'),
    (0x4ee17a, 2, 'mov', 'eax, ebx'),
    (0x4ee17c, 1, 'cdq', ''),
    (0x4ee17d, 1, 'push', 'edi'),
    (0x4ee17e, 4, 'shld', 'edx, eax, 0xf'),
    (0x4ee182, 1, 'push', 'ecx'),
    (0x4ee183, 3, 'shl', 'eax, 0xf'),
    (0x4ee186, 1, 'push', 'edx'),
    (0x4ee187, 1, 'push', 'eax'),
    (0x4ee188, 5, 'call', '0xac9f20'),
    (0x4ee18d, 2, 'push', '0'),
    (0x4ee18f, 5, 'push', '0x1f40000'),
    (0x4ee194, 2, 'test', 'ebx, ebx'),
    (0x4ee196, 2, 'jns', '0x4ee1fc'),
    (0x4ee198, 4, 'shrd', 'eax, edx, 0x1e'),
    (0x4ee19c, 3, 'sar', 'edx, 0x1e'),
    (0x4ee19f, 1, 'cdq', ''),
    (0x4ee1a0, 3, 'and', 'edx, 3'),
    (0x4ee1a3, 3, 'lea', 'edi, [edx + eax]'),
    (0x4ee1a6, 5, 'mov', 'eax, dword ptr [0x12586dc]'),
    (0x4ee1ab, 3, 'mov', 'ecx, dword ptr [eax + 0x10]'),
    (0x4ee1ae, 3, 'mov', 'eax, dword ptr [ecx + 0x68]'),
    (0x4ee1b1, 1, 'cdq', ''),
    (0x4ee1b2, 4, 'shld', 'edx, eax, 0x1e'),
    (0x4ee1b6, 3, 'shl', 'eax, 0x1e'),
    (0x4ee1b9, 1, 'push', 'edx'),
    (0x4ee1ba, 1, 'push', 'eax'),
    (0x4ee1bb, 3, 'sar', 'edi, 2'),
    (0x4ee1be, 5, 'call', '0xac02a0'),
    (0x4ee1c3, 2, 'mov', 'ecx, eax'),
    (0x4ee1c5, 3, 'mov', 'dword ptr [ebp - 4], edx'),
    (0x4ee1c8, 2, 'mov', 'eax, esi'),
    (0x4ee1ca, 3, 'mov', 'esi, dword ptr [ebp - 4]'),
    (0x4ee1cd, 1, 'cdq', ''),
    (0x4ee1ce, 4, 'shld', 'edx, eax, 0xf'),
    (0x4ee1d2, 1, 'push', 'esi'),
    (0x4ee1d3, 1, 'push', 'ecx'),
    (0x4ee1d4, 3, 'shl', 'eax, 0xf'),
    (0x4ee1d7, 1, 'push', 'edx'),
    (0x4ee1d8, 1, 'push', 'eax'),
    (0x4ee1d9, 5, 'call', '0xac9f20'),
    (0x4ee1de, 4, 'shrd', 'eax, edx, 0x1e'),
    (0x4ee1e2, 3, 'sar', 'edx, 0x1e'),
    (0x4ee1e5, 3, 'cmp', 'eax, 0x32'),
    (0x4ee1e8, 2, 'jge', '0x4ee1ef'),
    (0x4ee1ea, 5, 'mov', 'eax, 0x32'),
    (0x4ee1ef, 2, 'neg', 'eax'),
    (0x4ee1f1, 2, 'cmp', 'edi, eax'),
    (0x4ee1f3, 3, 'cmovg', 'edi, eax'),
    (0x4ee1f6, 2, 'cmp', 'edi, ebx'),
    (0x4ee1f8, 2, 'jge', '0x4ee257'),
    (0x4ee1fa, 2, 'jmp', '0x4ee255'),
    (0x4ee1fc, 2, 'mov', 'edi, eax'),
    (0x4ee1fe, 4, 'shrd', 'edi, edx, 0x1e'),
    (0x4ee202, 3, 'sar', 'edx, 0x1e'),
    (0x4ee205, 6, 'mov', 'edx, dword ptr [0x12586dc]'),
    (0x4ee20b, 3, 'mov', 'eax, dword ptr [edx + 0x10]'),
    (0x4ee20e, 3, 'mov', 'eax, dword ptr [eax + 0x64]'),
    (0x4ee211, 1, 'cdq', ''),
    (0x4ee212, 4, 'shld', 'edx, eax, 0x1e'),
    (0x4ee216, 3, 'shl', 'eax, 0x1e'),
    (0x4ee219, 1, 'push', 'edx'),
    (0x4ee21a, 1, 'push', 'eax'),
    (0x4ee21b, 5, 'call', '0xac02a0'),
    (0x4ee220, 2, 'mov', 'ecx, eax'),
    (0x4ee222, 3, 'mov', 'dword ptr [ebp - 4], edx'),
    (0x4ee225, 2, 'mov', 'eax, esi'),
    (0x4ee227, 3, 'mov', 'esi, dword ptr [ebp - 4]'),
    (0x4ee22a, 1, 'cdq', ''),
    (0x4ee22b, 4, 'shld', 'edx, eax, 0xf'),
    (0x4ee22f, 1, 'push', 'esi'),
    (0x4ee230, 1, 'push', 'ecx'),
    (0x4ee231, 3, 'shl', 'eax, 0xf'),
    (0x4ee234, 1, 'push', 'edx'),
    (0x4ee235, 1, 'push', 'eax'),
    (0x4ee236, 5, 'call', '0xac9f20'),
    (0x4ee23b, 4, 'shrd', 'eax, edx, 0x1e'),
    (0x4ee23f, 3, 'sar', 'edx, 0x1e'),
    (0x4ee242, 3, 'cmp', 'eax, 0x32'),
    (0x4ee245, 2, 'jge', '0x4ee24c'),
    (0x4ee247, 5, 'mov', 'eax, 0x32'),
    (0x4ee24c, 2, 'cmp', 'edi, eax'),
    (0x4ee24e, 3, 'cmovl', 'edi, eax'),
    (0x4ee251, 2, 'cmp', 'edi, ebx'),
    (0x4ee253, 2, 'jle', '0x4ee257'),
    (0x4ee255, 2, 'mov', 'edi, ebx'),
    (0x4ee257, 3, 'mov', 'ecx, dword ptr [ebp + 0xc]'),
    (0x4ee25a, 6, 'mov', 'eax, dword ptr [ecx + 0x11c]'),
    (0x4ee260, 6, 'sub', 'eax, dword ptr [ecx + 0x118]'),
    (0x4ee266, 3, 'sar', 'eax, 3'),
    (0x4ee269, 2, 'test', 'edi, edi'),
    (0x4ee26b, 2, 'jns', '0x4ee2c5'),
    (0x4ee26d, 2, 'neg', 'edi'),
    (0x4ee26f, 2, 'mov', 'esi, edi'),
    (0x4ee278, 3, 'mov', 'dword ptr [ebp - 4], eax'),
    (0x4ee27b, 2, 'test', 'eax, eax'),
    (0x4ee27d, 2, 'jle', '0x4ee2f5'),
    (0x4ee27f, 2, 'jmp', '0x4ee284'),
    (0x4ee281, 3, 'mov', 'ecx, dword ptr [ebp + 0xc]'),
    (0x4ee284, 2, 'test', 'esi, esi'),
    (0x4ee286, 2, 'je', '0x4ee2f5'),
    (0x4ee288, 6, 'mov', 'ecx, dword ptr [ecx + 0x118]'),
    (0x4ee28e, 3, 'mov', 'edx, dword ptr [ebp + 0x10]'),
    (0x4ee291, 3, 'mov', 'eax, dword ptr [ecx + edx*8]'),
    (0x4ee294, 3, 'mov', 'edi, dword ptr [ebp + 8]'),
    (0x4ee297, 3, 'mov', 'ecx, dword ptr [eax + 0x28]'),
    (0x4ee29a, 3, 'mov', 'edx, dword ptr [edi + 0x5c]'),
    (0x4ee29d, 3, 'mov', 'ecx, dword ptr [edx + ecx*4]'),
    (0x4ee2a0, 2, 'cmp', 'esi, ecx'),
    (0x4ee2a2, 2, 'mov', 'ebx, esi'),
    (0x4ee2a4, 3, 'cmovg', 'ebx, ecx'),
    (0x4ee2a7, 1, 'push', 'ebx'),
    (0x4ee2a8, 1, 'push', 'eax'),
    (0x4ee2a9, 5, 'call', '0x4ee650'),
    (0x4ee2ae, 3, 'mov', 'eax, dword ptr [ebp + 0x10]'),
    (0x4ee2b1, 1, 'inc', 'eax'),
    (0x4ee2b2, 2, 'sub', 'esi, ebx'),
    (0x4ee2b4, 3, 'mov', 'dword ptr [ebp + 0x10], eax'),
    (0x4ee2b7, 3, 'cmp', 'eax, dword ptr [ebp - 4]'),
    (0x4ee2ba, 2, 'jl', '0x4ee281'),
    (0x4ee2bc, 1, 'pop', 'edi'),
    (0x4ee2bd, 1, 'pop', 'esi'),
    (0x4ee2be, 1, 'pop', 'ebx'),
    (0x4ee2bf, 2, 'mov', 'esp, ebp'),
    (0x4ee2c1, 1, 'pop', 'ebp'),
    (0x4ee2c2, 3, 'ret', '0x14'),
    (0x4ee2c5, 2, 'xor', 'ebx, ebx'),
    (0x4ee2c7, 3, 'mov', 'dword ptr [ebp + 0x10], eax'),
    (0x4ee2ca, 2, 'test', 'eax, eax'),
    (0x4ee2cc, 2, 'jle', '0x4ee2f5'),
    (0x4ee2ce, 2, 'jmp', '0x4ee2d3'),
    (0x4ee2d0, 3, 'mov', 'ecx, dword ptr [ebp + 0xc]'),
    (0x4ee2d3, 2, 'test', 'edi, edi'),
    (0x4ee2d5, 2, 'je', '0x4ee2f5'),
    (0x4ee2d7, 6, 'mov', 'eax, dword ptr [ecx + 0x118]'),
    (0x4ee2dd, 4, 'mov', 'ecx, dword ptr [eax + ebx*8]'),
    (0x4ee2e0, 3, 'mov', 'esi, dword ptr [ebp + 8]'),
    (0x4ee2e3, 3, 'lea', 'eax, [eax + ebx*8]'),
    (0x4ee2e6, 1, 'push', 'edi'),
    (0x4ee2e7, 1, 'push', 'ecx'),
    (0x4ee2e8, 5, 'call', '0x4ee780'),
    (0x4ee2ed, 1, 'inc', 'ebx'),
    (0x4ee2ee, 2, 'sub', 'edi, eax'),
    (0x4ee2f0, 3, 'cmp', 'ebx, dword ptr [ebp + 0x10]'),
    (0x4ee2f3, 2, 'jl', '0x4ee2d0'),
    (0x4ee2f5, 1, 'pop', 'edi'),
    (0x4ee2f6, 1, 'pop', 'esi'),
    (0x4ee2f7, 1, 'pop', 'ebx'),
    (0x4ee2f8, 2, 'mov', 'esp, ebp'),
    (0x4ee2fa, 1, 'pop', 'ebp'),
    (0x4ee2fb, 3, 'ret', '0x14'),
)

for address, length, mnemonic, operand in expected_instructions:
    claims.append({
        'id': f'quota_alloc_{address:x}', 'kind': 'instructions', 'space': 'rva',
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
wrong = dict(claims[0], id='negative_control_quota_alloc', mnemonics=['nop'])
dependent = dict(claims[1], id='negative_dependent_quota_alloc', depends_on=['negative_control_quota_alloc'])
controls = verifier.verify_all([Claim.from_dict(wrong), Claim.from_dict(dependent)])
assert [r['verdict'] for r in controls['results']] == ['REFUTED', 'INVALIDATED']

# 2. Dynamic Unicorn Emulation
sec = next(s for s in pe.sections if s.Name.startswith(b'.text'))
text_data = sec.get_data()
text_base = pe.OPTIONAL_HEADER.ImageBase + sec.VirtualAddress

uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)

code_start = text_base & ~0xFFF
code_size = (len(text_data) + 0xFFF) & ~0xFFF
uc.mem_map(code_start, code_size, unicorn.UC_PROT_ALL)
uc.mem_write(text_base, text_data)

stack_base = 0x00100000
stack_size = 0x00020000
uc.mem_map(stack_base, stack_size, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)

heap_base = 0x00200000
heap_size = 0x00100000
uc.mem_map(heap_base, heap_size, unicorn.UC_PROT_ALL)

singleton_page = 0x01258000
uc.mem_map(singleton_page, 0x2000, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
uc.mem_write(0x012586DC, (0x00210000).to_bytes(4, 'little'))

defines_ptr = 0x00220000
uc.mem_write(0x00210000 + 0x10, defines_ptr.to_bytes(4, 'little'))
uc.mem_write(defines_ptr + 0x64, (1000).to_bytes(4, 'little', signed=True))
uc.mem_write(defines_ptr + 0x68, (1000).to_bytes(4, 'little', signed=True))

stub_demote = b'\x8b\x4c\x24\x08\x8b\x44\x24\x04\x8b\x50\x28\x01\x0c\x95\x00\x00\x25\x00\xc2\x08\x00'
uc.mem_write(0x004EE650, stub_demote)

stub_promo = b'\x8b\x4c\x24\x08\x8b\x54\x24\x04\x8b\x52\x28\x8b\x04\x95\x00\x00\x26\x00\x39\xc1\x0f\x4c\xc1\x89\x04\x95\x00\x00\x25\x00\xc2\x08\x00'
uc.mem_write(0x004EE780, stub_promo)

buffer_obj = 0x00230000
pop_type_obj = 0x00240000
avail_array = 0x00260000
allocated_array = 0x00250000
uc.mem_write(buffer_obj + 0x5C, avail_array.to_bytes(4, 'little'))


def run_quota_allocation_emulation(
    desired: int,
    current: int,
    rate_weight: int,
    target_caps: list[int],
) -> list[int]:
    uc.mem_write(buffer_obj + 0x48, current.to_bytes(4, 'little'))
    num_t = len(target_caps)
    cand_array = 0x00270000
    uc.mem_write(pop_type_obj + 0x118, cand_array.to_bytes(4, 'little'))
    uc.mem_write(pop_type_obj + 0x11C, (cand_array + num_t * 8).to_bytes(4, 'little'))

    for i in range(16):
        uc.mem_write(allocated_array + i * 4, (0).to_bytes(4, 'little'))

    for i, cap in enumerate(target_caps):
        cand_obj = 0x00280000 + i * 0x40
        uc.mem_write(cand_array + i * 8, cand_obj.to_bytes(4, 'little'))
        uc.mem_write(cand_obj + 0x28, i.to_bytes(4, 'little'))
        uc.mem_write(avail_array + i * 4, cap.to_bytes(4, 'little'))

    ret_addr = 0x00555555
    esp = 0x0011FF00
    rw_lo = rate_weight & 0xFFFFFFFF
    rw_hi = (rate_weight >> 32) & 0xFFFFFFFF

    uc.mem_write(esp, ret_addr.to_bytes(4, 'little'))
    uc.mem_write(esp + 4, buffer_obj.to_bytes(4, 'little'))
    uc.mem_write(esp + 8, pop_type_obj.to_bytes(4, 'little'))
    uc.mem_write(esp + 0xC, desired.to_bytes(4, 'little', signed=True))
    uc.mem_write(esp + 0x10, rw_lo.to_bytes(4, 'little'))
    uc.mem_write(esp + 0x14, rw_hi.to_bytes(4, 'little'))

    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_EBP, esp)
    uc.reg_write(UC_X86_REG_EBX, 0x12345678)
    uc.reg_write(UC_X86_REG_ESI, 0x23456789)
    uc.reg_write(UC_X86_REG_EDI, 0x3456789A)

    uc.emu_start(0x004EE150, ret_addr, timeout=2000000)

    assert uc.reg_read(UC_X86_REG_EBX) == 0x12345678, "EBX clobbered"
    assert uc.reg_read(UC_X86_REG_ESI) == 0x23456789, "ESI clobbered"
    assert uc.reg_read(UC_X86_REG_EDI) == 0x3456789A, "EDI clobbered"

    return [int.from_bytes(uc.mem_read(allocated_array + i * 4, 4), 'little') for i in range(num_t)]


# Deterministic fixtures
fixtures = [
    # Full satisfaction across multiple targets
    (1000, 500, 32768, [100, 200, 300]),
    # Demotion satisfaction
    (200, 500, 32768, [150, 150, 150]),
    # Small positive delta clamped to 20 (< 50)
    (520, 500, 32768, [10, 20, 30]),
    # Small negative delta clamped to 20 (< 50)
    (480, 500, 32768, [10, 20, 30]),
    # Zero delta (desired == current)
    (500, 500, 32768, [100, 100]),
    # Zero rate weight
    (1000, 500, 0, [100, 100]),
    # Half rate weight
    (800, 500, 16384, [50, 100, 200]),
    # Exhaustion before satisfying quota
    (1000, 500, 32768, [100, 100]),
    # Single target
    (600, 500, 32768, [500]),
]

# Random fixtures
random.seed(665544)
for _ in range(110):
    curr = random.randint(100, 5000)
    des = random.randint(50, 6000)
    rw = random.choice([0, 8192, 16384, 24576, 32768, 65536])
    n_targets = random.randint(1, 5)
    caps = [random.randint(10, 1000) for _ in range(n_targets)]
    fixtures.append((des, curr, rw, caps))

fixture_count = 0
mismatches = 0

for des, curr, rw, caps in fixtures:
    exp = calculate_target_quota_allocations(des, curr, rw, caps)
    act = run_quota_allocation_emulation(des, curr, rw, caps)
    fixture_count += 1
    if act != exp:
        mismatches += 1

assert mismatches == 0, f"{mismatches} mismatches found during province target quota allocation emulation"

out = ROOT / 'evidence/generated/province-target-quota'
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
ledger.record(report, session='province-target-quota')
ledger.save()

print(f"Province target quota: {verified_count} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Province target quota emulation: {fixture_count} fixtures executed, 0 mismatches against province_target_quota_model.")
