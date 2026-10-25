#!/usr/bin/env python3
"""Verify CBuildingProject::UpdateFundingStatus routine (0x004A4EB0..0x004A4F2E, callers at 0x004A4FED, 0x004A5005, 0x005887A6)."""
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
from project_buffer_model import compute_project_funding_status

data = (ROOT.parent / 'base-game/v2game.exe').read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = 0x400000

claims = []

expected_instructions = (
    # Callers
    (0x004A4FED, 5, 'call', '0x4a4eb0'),
    (0x004A5005, 5, 'call', '0x4a4eb0'),
    (0x005887A6, 5, 'call', '0x4a4eb0'),

    # CBuildingProject::UpdateFundingStatus (0x004A4EB0..0x004A4F2E)
    (0x004A4EB0, 1, 'push', 'ebp'),
    (0x004A4EB1, 2, 'mov', 'ebp, esp'),
    (0x004A4EB3, 3, 'mov', 'eax, dword ptr [esi + 0x7c]'),
    (0x004A4EB6, 3, 'sub', 'esp, 0xc'),
    (0x004A4EB9, 1, 'push', 'edi'),
    (0x004A4EBA, 2, 'test', 'eax, eax'),
    (0x004A4EBC, 2, 'js', '0x4a4f1e'),
    (0x004A4EBE, 3, 'cmp', 'eax, 1'),
    (0x004A4EC1, 2, 'jle', '0x4a4ec8'),
    (0x004A4EC3, 3, 'cmp', 'eax, 3'),
    (0x004A4EC6, 2, 'jne', '0x4a4f1e'),
    (0x004A4EC8, 3, 'lea', 'eax, [ebp - 8]'),
    (0x004A4ECB, 1, 'push', 'eax'),
    (0x004A4ECC, 2, 'mov', 'ecx, esi'),
    (0x004A4ECE, 5, 'call', '0x4a5020'),
    (0x004A4ED3, 6, 'fld', 'qword ptr [0xe45ba0]'),
    (0x004A4ED9, 2, 'mov', 'edi, eax'),
    (0x004A4EDB, 5, 'call', '0xb31c36'),
    (0x004A4EE0, 3, 'mov', 'ecx, dword ptr [edi + 4]'),
    (0x004A4EE3, 1, 'push', 'edx'),
    (0x004A4EE4, 2, 'mov', 'edx, dword ptr [edi]'),
    (0x004A4EE6, 1, 'push', 'eax'),
    (0x004A4EE7, 1, 'push', 'ecx'),
    (0x004A4EE8, 1, 'push', 'edx'),
    (0x004A4EE9, 5, 'call', '0xac9f20'),
    (0x004A4EEE, 4, 'shrd', 'eax, edx, 0xf'),
    (0x004A4EF2, 3, 'sar', 'edx, 0xf'),
    (0x004A4EF5, 3, 'cmp', 'dword ptr [esi + 0x64], edx'),
    (0x004A4EF8, 2, 'jg', '0x4a4f11'),
    (0x004A4EFA, 2, 'jl', '0x4a4f01'),
    (0x004A4EFC, 3, 'cmp', 'dword ptr [esi + 0x60], eax'),
    (0x004A4EFF, 2, 'jae', '0x4a4f11'),
    (0x004A4F01, 5, 'mov', 'eax, 1'),
    (0x004A4F06, 6, 'mov', 'byte ptr [esi + 0x80], al'),
    (0x004A4F0C, 1, 'pop', 'edi'),
    (0x004A4F0D, 2, 'mov', 'esp, ebp'),
    (0x004A4F0F, 1, 'pop', 'ebp'),
    (0x004A4F10, 1, 'ret', ''),
    (0x004A4F11, 2, 'xor', 'eax, eax'),
    (0x004A4F13, 6, 'mov', 'byte ptr [esi + 0x80], al'),
    (0x004A4F19, 1, 'pop', 'edi'),
    (0x004A4F1A, 2, 'mov', 'esp, ebp'),
    (0x004A4F1C, 1, 'pop', 'ebp'),
    (0x004A4F1D, 1, 'ret', ''),
    (0x004A4F1E, 3, 'cmp', 'eax, 4'),
    (0x004A4F21, 3, 'setne', 'al'),
    (0x004A4F24, 6, 'mov', 'byte ptr [esi + 0x80], al'),
    (0x004A4F2A, 1, 'pop', 'edi'),
    (0x004A4F2B, 2, 'mov', 'esp, ebp'),
    (0x004A4F2D, 1, 'pop', 'ebp'),
    (0x004A4F2E, 1, 'ret', ''),
)

for address, length, mnemonic, operand in expected_instructions:
    claims.append({
        'id': f'proj_buf_{address:x}', 'kind': 'instructions', 'space': 'rva',
        'offset': hex(address - base), 'base': hex(address), 'arch': 'x86',
        'length': length, 'mnemonics': [mnemonic], 'operands': [operand] if operand else []
    })

# Double precision buffer constant at 0x00E45BA0 (36045.30078125)
claims.append({
    'id': 'proj_buf_float_constant', 'kind': 'bytes_at', 'space': 'rva',
    'offset': hex(0x00E45BA0 - base), 'base': hex(0x00E45BA0),
    'expected': struct.pack('<d', 36045.30078125).hex()
})

verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]
verified_count = len(claims)

# Negative controls
wrong = dict(claims[3], id='negative_control_proj_buf', mnemonics=['nop'])
dependent = dict(claims[4], id='negative_dependent_proj_buf', depends_on=['negative_control_proj_buf'])
controls = verifier.verify_all([Claim.from_dict(wrong), Claim.from_dict(dependent)])
assert [r['verdict'] for r in controls['results']] == ['REFUTED', 'INVALIDATED']

# --- Unicorn Emulation ---
uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)

for s in pe.sections:
    name = s.Name.decode().strip(chr(0))
    va = pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress
    size = (s.Misc_VirtualSize + 0xFFF) & ~0xFFF
    prot = unicorn.UC_PROT_READ
    if s.Characteristics & 0x20000000:
        prot |= unicorn.UC_PROT_EXEC
    if s.Characteristics & 0x80000000:
        prot |= unicorn.UC_PROT_WRITE
    uc.mem_map(va, size, prot)
    uc.mem_write(va, s.get_data())

stack_base = 0x00100000
stack_size = 0x00020000
uc.mem_map(stack_base, stack_size, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)

heap_base = 0x00200000
heap_size = 0x00010000
uc.mem_map(heap_base, heap_size, unicorn.UC_PROT_ALL)

current_mock_cost = 0

def hook_cost_call(uc_inst, address, size, user_data):
    esp = uc_inst.reg_read(UC_X86_REG_ESP)
    ret_addr = struct.unpack('<I', uc_inst.mem_read(esp, 4))[0]
    arg_ptr = struct.unpack('<I', uc_inst.mem_read(esp + 4, 4))[0]
    uc_inst.mem_write(arg_ptr, current_mock_cost.to_bytes(8, 'little', signed=True))
    uc_inst.reg_write(UC_X86_REG_EAX, arg_ptr)
    uc_inst.reg_write(UC_X86_REG_ESP, esp + 8)
    uc_inst.reg_write(UC_X86_REG_EIP, ret_addr)

uc.hook_add(unicorn.UC_HOOK_CODE, hook_cost_call, None, 0x004A5020, 0x004A5020)

project_addr = heap_base + 0x100

def run_project_buffer_emulation(stage: int, current_funds: int, base_cost: int) -> tuple[int, int]:
    global current_mock_cost
    current_mock_cost = base_cost

    uc.mem_write(project_addr + 0x60, (current_funds & 0xFFFFFFFFFFFFFFFF).to_bytes(8, 'little'))
    uc.mem_write(project_addr + 0x7c, (stage & 0xFFFFFFFF).to_bytes(4, 'little'))
    uc.mem_write(project_addr + 0x80, b'\xAA')

    esp = stack_base + 0x10000
    uc.reg_write(UC_X86_REG_EBP, esp)
    uc.reg_write(UC_X86_REG_ESI, project_addr)

    esp -= 4
    uc.mem_write(esp, (0x004A4F2E).to_bytes(4, 'little'))
    uc.reg_write(UC_X86_REG_ESP, esp)

    uc.emu_start(0x004A4EB0, 0x004A4F2E)

    needs_funding = uc.mem_read(project_addr + 0x80, 1)[0]
    eax = uc.reg_read(UC_X86_REG_EAX)
    return needs_funding, eax

fixtures = [
    # Stage 4: completed, always 0
    (4, 0, 10000),
    (4, 100000, 10000),
    (4, -5000, 10000),

    # Stage 2: waiting/blocked, always 1
    (2, 0, 10000),
    (2, 100000, 10000),
    (2, -5000, 10000),

    # Negative stages: always 1
    (-1, 0, 10000),
    (-5, 50000, 10000),

    # Stage > 4: always 1
    (5, 0, 10000),
    (6, 100000, 10000),

    # Stage 0: initial active stage, cost 10000 -> threshold = 11000
    (0, 0, 10000),
    (0, 10999, 10000),
    (0, 11000, 10000),
    (0, 11001, 10000),
    (0, 20000, 10000),
    (0, -100, 10000),

    # Stage 1: procurement stage, cost 32768 -> threshold = 36045
    (1, 0, 32768),
    (1, 36044, 32768),
    (1, 36045, 32768),
    (1, 36046, 32768),
    (1, 50000, 32768),

    # Stage 3: active construction stage, cost 50000 -> threshold = 55001
    (3, 0, 50000),
    (3, 55000, 50000),
    (3, 55001, 50000),
    (3, 55002, 50000),
    (3, 100000, 50000),

    # Zero cost
    (0, 0, 0),
    (0, 1, 0),
    (1, 0, 0),
    (3, -5, 0),

    # Large 64-bit cost (high dword > 0)
    (0, 0x100000000, 0x100000000),
    (0, 0x200000000, 0x100000000),
]

random.seed(443322)
for _ in range(110):
    st = random.choice([-2, -1, 0, 1, 2, 3, 4, 5])
    cost = random.randint(0, 500000)
    thresh = (cost * 36045) >> 15
    choice = random.randint(0, 4)
    if choice == 0:
        funds = random.randint(max(0, thresh - 5), thresh + 5)
    elif choice == 1:
        funds = 0
    elif choice == 2:
        funds = random.randint(-1000, -1)
    elif choice == 3:
        funds = random.randint(0, thresh * 2 + 10)
    else:
        funds = random.randint(0, 2000000)
    fixtures.append((st, funds, cost))

fixture_count = 0
mismatches = 0

for st, fds, cst in fixtures:
    exp = compute_project_funding_status(st, fds, cst)
    act = run_project_buffer_emulation(st, fds, cst)
    fixture_count += 1
    if act != exp:
        mismatches += 1
        print(f"Mismatch at st={st}, funds={fds}, cost={cst}: act={act}, exp={exp}")

assert mismatches == 0, f"{mismatches} mismatches found during project buffer funding emulation"

out = ROOT / 'evidence/generated/project-buffer'
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
ledger.record(report, session='project-buffer')
ledger.save()

print(f"Project buffer funding: {verified_count} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Project buffer funding emulation: {fixture_count} fixtures executed, 0 mismatches against project_buffer_model.")
