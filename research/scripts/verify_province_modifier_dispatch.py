#!/usr/bin/env python3
"""Verify CProvince::UpdateModifiers modifier dispatch routine (0x004D3FF5..0x004D4067, caller at 0x00686228)."""
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
from province_modifier_dispatch_model import dispatch_province_modifier

data = (ROOT.parent / 'base-game/v2game.exe').read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = 0x400000

claims = []

# 1. Key instructions in CProvince::UpdateModifiers switch block
expected_dispatch_instructions = (
    # Caller in outer province traversal loop
    (0x00686228, 5, 'call', '0x4d3bb0'),
    # Function prologue
    (0x004D3BB0, 1, 'push', 'ebp'),
    (0x004D3BB1, 2, 'mov', 'ebp, esp'),
    (0x004D3BB3, 3, 'and', 'esp, 0xfffffff8'),
    (0x004D3BB6, 3, 'sub', 'esp, 0x2c'),
    (0x004D3BBC, 2, 'mov', 'esi, eax'),
    # Dispatch preparation and bounds check
    (0x004D3FF5, 3, 'mov', 'edx, dword ptr [edi + edx*4]'),
    (0x004D3FF8, 6, 'mov', 'edx, dword ptr [edx + 0x1404]'),
    (0x004D3FFE, 1, 'dec', 'edx'),
    (0x004D3FFF, 3, 'cmp', 'edx, 7'),
    (0x004D4002, 2, 'ja', '0x4d4067'),
    (0x004D4004, 7, 'jmp', 'dword ptr [edx*4 + 0x4d41f0]'),
    # Slot 0: +0x524
    (0x004D400B, 3, 'mov', 'ecx, dword ptr [ecx + 0x30]'),
    (0x004D400E, 6, 'mov', 'ecx, dword ptr [ecx + 0x524]'),
    (0x004D4014, 2, 'jmp', '0x4d4061'),
    # Slot 1: +0x528 (attrition modifier)
    (0x004D4016, 3, 'mov', 'edx, dword ptr [ecx + 0x30]'),
    (0x004D4019, 6, 'mov', 'ecx, dword ptr [edx + 0x528]'),
    (0x004D401F, 2, 'jmp', '0x4d4061'),
    # Slot 2: +0x52C
    (0x004D4021, 3, 'mov', 'ecx, dword ptr [ecx + 0x30]'),
    (0x004D4024, 6, 'mov', 'ecx, dword ptr [ecx + 0x52c]'),
    (0x004D402A, 2, 'jmp', '0x4d4061'),
    # Slot 3: +0x530
    (0x004D402C, 3, 'mov', 'edx, dword ptr [ecx + 0x30]'),
    (0x004D402F, 6, 'mov', 'ecx, dword ptr [edx + 0x530]'),
    (0x004D4035, 2, 'jmp', '0x4d4061'),
    # Slot 4: +0x534
    (0x004D4037, 3, 'mov', 'ecx, dword ptr [ecx + 0x30]'),
    (0x004D403A, 6, 'mov', 'ecx, dword ptr [ecx + 0x534]'),
    (0x004D4040, 2, 'jmp', '0x4d4061'),
    # Slot 5: +0x538
    (0x004D4042, 3, 'mov', 'edx, dword ptr [ecx + 0x30]'),
    (0x004D4045, 6, 'mov', 'ecx, dword ptr [edx + 0x538]'),
    (0x004D404B, 2, 'jmp', '0x4d4061'),
    # Slot 6: +0x53C
    (0x004D404D, 3, 'mov', 'ecx, dword ptr [ecx + 0x30]'),
    (0x004D4050, 6, 'mov', 'ecx, dword ptr [ecx + 0x53c]'),
    (0x004D4056, 2, 'jmp', '0x4d4061'),
    # Slot 7: +0x540
    (0x004D4058, 3, 'mov', 'edx, dword ptr [ecx + 0x30]'),
    (0x004D405B, 6, 'mov', 'ecx, dword ptr [edx + 0x540]'),
    # Accumulation and fallthrough
    (0x004D4061, 6, 'add', 'dword ptr [esi + 0x280], ecx'),
    (0x004D4067, 6, 'mov', 'edx, dword ptr [eax + 0xbe0]'),
)

for address, length, mnemonic, operand in expected_dispatch_instructions:
    claims.append({
        'id': f'dispatch_ins_{address:x}', 'kind': 'instructions', 'space': 'rva',
        'offset': hex(address - base), 'base': hex(address), 'arch': 'x86',
        'length': length, 'mnemonics': [mnemonic], 'operands': [operand] if operand else []
    })

# Jump table at 0x004D41F0
jt_targets = (0x004D400B, 0x004D4016, 0x004D4021, 0x004D402C, 0x004D4037, 0x004D4042, 0x004D404D, 0x004D4058)
claims.append({
    'id': 'dispatch_jump_table_bytes', 'kind': 'bytes_at', 'space': 'rva',
    'offset': hex(0x004D41F0 - base), 'expected': struct.pack('<8I', *jt_targets).hex()
})

verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]
verified_count = len(claims)

# Negative controls
wrong = dict(claims[0], id='negative_control_dispatch', mnemonics=['nop'])
dependent = dict(claims[1], id='negative_dependent_dispatch', depends_on=['negative_control_dispatch'])
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

heap_base = 0x00200000
heap_size = 0x00100000
uc.mem_map(heap_base, heap_size, unicorn.UC_PROT_ALL)


def run_dispatch_emulation(initial_acc: int, mod_type: int, slots: list[int]) -> int:
    esi = 0x00210000
    uc.mem_write(esi + 0x280, initial_acc.to_bytes(4, 'little', signed=True))

    ecx = 0x00220000
    table_addr = 0x00230000
    uc.mem_write(ecx + 0x30, table_addr.to_bytes(4, 'little'))
    for i in range(8):
        val = slots[i] if i < len(slots) else 0
        uc.mem_write(table_addr + 0x524 + i * 4, val.to_bytes(4, 'little', signed=True))

    edi = 0x00240000
    mod_obj = 0x00250000
    uc.mem_write(edi + 0, mod_obj.to_bytes(4, 'little'))
    uc.mem_write(mod_obj + 0x1404, mod_type.to_bytes(4, 'little', signed=True))

    edx = 0

    uc.reg_write(UC_X86_REG_ESI, esi)
    uc.reg_write(UC_X86_REG_ECX, ecx)
    uc.reg_write(UC_X86_REG_EDI, edi)
    uc.reg_write(UC_X86_REG_EDX, edx)

    uc.emu_start(0x004D3FF5, 0x004D4067, timeout=1000000)

    res = int.from_bytes(uc.mem_read(esi + 0x280, 4), 'little', signed=True)
    return res


fixtures = []
# Boundary cases: 0 (out of bounds), 1..8 (each slot), 9..15 (out of bounds)
base_slots = [15, -8, 120, -50, 42, 999, -1, 33]
for m in range(0, 16):
    fixtures.append((500, m, list(base_slots)))

# Zero initial accumulator
for m in range(1, 9):
    fixtures.append((0, m, list(base_slots)))

# Negative accumulator
for m in range(1, 9):
    fixtures.append((-300, m, list(base_slots)))

# Random fixtures
random.seed(998877)
for _ in range(100):
    init_acc = random.randint(-100000, 100000)
    m_type = random.randint(-2, 12)
    s_vals = [random.randint(-5000, 5000) for _ in range(8)]
    fixtures.append((init_acc, m_type, s_vals))

fixture_count = 0
mismatches = 0

for init_acc, m_type, s_vals in fixtures:
    exp = dispatch_province_modifier(init_acc, m_type, s_vals)
    act = run_dispatch_emulation(init_acc, m_type, s_vals)
    fixture_count += 1
    if act != exp:
        mismatches += 1

assert mismatches == 0, f"{mismatches} mismatches found during province modifier dispatch emulation"

out = ROOT / 'evidence/generated/province-modifier-dispatch'
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
ledger.record(report, session='province-modifier-dispatch')
ledger.save()

print(f"Province modifier dispatch: {verified_count} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Province modifier dispatch emulation: {fixture_count} fixtures executed, 0 mismatches against province_modifier_dispatch_model.")
