#!/usr/bin/env python3
"""Verify CPop::SetSize routine (0x00955FD0..0x00956054, callers at 0x009584C8, etc.)."""
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
from pop_set_size_model import PopState, pop_set_size_model

data = (ROOT.parent / 'base-game/v2game.exe').read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = 0x400000

claims = []

# 1. Key instructions in CPop::SetSize (0x00955FD0..0x00956054)
expected_pop_set_size_instructions = (
    (0x00955FD0, 1, 'push', 'ebp'),
    (0x00955FD1, 2, 'mov', 'ebp, esp'),
    (0x00955FD3, 3, 'sub', 'esp, 8'),
    (0x00955FD6, 1, 'push', 'ebx'),
    (0x00955FD7, 1, 'push', 'edi'),
    (0x00955FD8, 2, 'mov', 'edi, eax'),
    (0x00955FDA, 2, 'test', 'edi, edi'),
    (0x00955FDC, 2, 'jns', '0x955fe2'),
    (0x00955FDE, 2, 'xor', 'edi, edi'),
    (0x00955FE0, 2, 'jmp', '0x955fef'),
    (0x00955FE2, 6, 'cmp', 'edi, 0x1e8480'),
    (0x00955FE8, 2, 'jle', '0x955fef'),
    (0x00955FEA, 5, 'mov', 'edi, 0x1e8480'),
    (0x00955FEF, 3, 'mov', 'eax, dword ptr [esi + 0x68]'),
    (0x00955FF2, 4, 'cmp', 'byte ptr [eax + 0x40], 0'),
    (0x00955FF6, 2, 'jne', '0x955ffd'),
    (0x00955FF8, 3, 'mov', 'dword ptr [esi + 0x60], edi'),
    (0x00955FFB, 2, 'jmp', '0x95603f'),
    (0x00955FFD, 3, 'mov', 'eax, dword ptr [esi + 0x60]'),
    (0x00956000, 2, 'cmp', 'edi, eax'),
    (0x00956002, 2, 'jge', '0x95603f'),
    (0x00956004, 3, 'mov', 'ecx, dword ptr [esi + 0x64]'),
    (0x00956007, 3, 'mov', 'ebx, dword ptr [ecx + 0x58]'),
    (0x0095600A, 2, 'sub', 'eax, edi'),
    (0x0095600C, 3, 'mov', 'dword ptr [ebp - 4], eax'),
    (0x0095600F, 5, 'call', '0x4c25b0'),
    (0x00956014, 6, 'imul', 'ebx, ebx, 0xb0'),
    (0x0095601A, 2, 'mov', 'eax, dword ptr [eax]'),
    (0x0095601C, 3, 'lea', 'edx, [ebp - 4]'),
    (0x0095601F, 1, 'push', 'edx'),
    (0x00956020, 4, 'lea', 'ecx, [ebx + eax + 0x10]'),
    (0x00956024, 1, 'push', 'ecx'),
    (0x00956025, 2, 'mov', 'edx, esi'),
    (0x00956027, 5, 'call', '0x4ee550'),
    (0x0095602C, 3, 'mov', 'eax, dword ptr [esi + 0x64]'),
    (0x0095602F, 6, 'mov', 'eax, dword ptr [eax + 0x188]'),
    (0x00956035, 3, 'lea', 'edx, [ebp - 4]'),
    (0x00956038, 1, 'push', 'edx'),
    (0x00956039, 1, 'push', 'esi'),
    (0x0095603A, 5, 'call', '0x4d1020'),
    (0x0095603F, 3, 'mov', 'ecx, dword ptr [esi + 0x58]'),
    (0x00956042, 3, 'mov', 'dword ptr [esi + 0x5c], ecx'),
    (0x00956045, 3, 'mov', 'dword ptr [esi + 0x58], edi'),
    (0x00956048, 2, 'test', 'ecx, ecx'),
    (0x0095604A, 2, 'jne', '0x95604f'),
    (0x0095604C, 3, 'mov', 'dword ptr [esi + 0x5c], edi'),
    (0x0095604F, 1, 'pop', 'edi'),
    (0x00956050, 1, 'pop', 'ebx'),
    (0x00956051, 2, 'mov', 'esp, ebp'),
    (0x00956053, 1, 'pop', 'ebp'),
    (0x00956054, 1, 'ret', ''),
)

for address, length, mnemonic, operand in expected_pop_set_size_instructions:
    claims.append({
        'id': f'set_size_ins_{address:x}', 'kind': 'instructions', 'space': 'rva',
        'offset': hex(address - base), 'base': hex(address), 'arch': 'x86',
        'length': length, 'mnemonics': [mnemonic], 'operands': [operand] if operand else []
    })

# 2. Callers to CPop::SetSize
callers = (
    (0x009584C8, 'call', '0x955fd0'),
    (0x009584EB, 'call', '0x955fd0'),
    (0x009587BE, 'call', '0x955fd0'),
    (0x009587E1, 'call', '0x955fd0'),
    (0x00958A81, 'call', '0x955fd0'),
    (0x00958AA4, 'call', '0x955fd0'),
)

for address, mnemonic, operand in callers:
    claims.append({
        'id': f'set_size_caller_{address:x}', 'kind': 'instructions', 'space': 'rva',
        'offset': hex(address - base), 'base': hex(address), 'arch': 'x86',
        'length': 5, 'mnemonics': [mnemonic], 'operands': [operand]
    })

# Reverify evaluation
verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]
verified_count = len(claims)

# Negative controls
wrong = dict(claims[0], id='negative_control_pop_set_size', mnemonics=['nop'])
dependent = dict(claims[1], id='negative_dependent_pop_set_size', depends_on=['negative_control_pop_set_size'])
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
heap_size = 0x00080000
uc.mem_map(heap_base, heap_size, unicorn.UC_PROT_ALL)

data_page = 0x01258000
uc.mem_map(data_page, 0x2000, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
uc.mem_write(0x01258728, (0x00240000).to_bytes(4, 'little'))
uc.mem_write(0x00240000, (0x00250000).to_bytes(4, 'little'))

# Stubs for callees
uc.mem_write(0x004C25B0, b"\xa1\x28\x87\x25\x01\xc3")  # mov eax, [0x01258728]; ret
uc.mem_write(0x004EE550, b"\xc2\x08\x00")              # ret 8
uc.mem_write(0x004D1020, b"\xc2\x08\x00")              # ret 8


def run_emulation(pop: PopState, new_size: int):
    pop_addr = 0x00200000
    prov_addr = 0x00210000
    type_addr = 0x00220000
    ret_addr = 0x00555555

    uc.mem_write(prov_addr + 0x58, pop.prov_id.to_bytes(4, 'little'))
    uc.mem_write(prov_addr + 0x188, (0x00230000).to_bytes(4, 'little'))

    uc.mem_write(type_addr + 0x40, pop.flag_40.to_bytes(1, 'little'))

    uc.mem_write(pop_addr + 0x58, pop.prev_size.to_bytes(4, 'little'))
    uc.mem_write(pop_addr + 0x5C, pop.prev_prev_size.to_bytes(4, 'little'))
    uc.mem_write(pop_addr + 0x60, pop.tracked_size.to_bytes(4, 'little'))
    uc.mem_write(pop_addr + 0x64, prov_addr.to_bytes(4, 'little'))
    uc.mem_write(pop_addr + 0x68, type_addr.to_bytes(4, 'little'))

    esp = 0x0011FFE0
    uc.mem_write(esp, ret_addr.to_bytes(4, 'little'))

    calls = {"called_4d1020": False, "delta_4d1020": None}

    def hook_code(uc_inst, address, size, user_data):
        if address == 0x004D1020:
            calls["called_4d1020"] = True
            current_esp = uc_inst.reg_read(UC_X86_REG_ESP)
            ptr_delta = int.from_bytes(uc_inst.mem_read(current_esp + 8, 4), 'little')
            calls["delta_4d1020"] = int.from_bytes(uc_inst.mem_read(ptr_delta, 4), 'little')

    hook_handle = uc.hook_add(unicorn.UC_HOOK_CODE, hook_code)

    uc.reg_write(UC_X86_REG_EAX, new_size & 0xFFFFFFFF)
    uc.reg_write(UC_X86_REG_ESI, pop_addr)
    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_EBP, esp)
    uc.reg_write(UC_X86_REG_EBX, 0x11223344)
    uc.reg_write(UC_X86_REG_EDI, 0x55667788)

    uc.emu_start(0x00955FD0, ret_addr, timeout=2000000)
    uc.hook_del(hook_handle)

    res_prev = int.from_bytes(uc.mem_read(pop_addr + 0x58, 4), 'little')
    res_prev_prev = int.from_bytes(uc.mem_read(pop_addr + 0x5C, 4), 'little')
    res_tracked = int.from_bytes(uc.mem_read(pop_addr + 0x60, 4), 'little')

    res_ebx = uc.reg_read(UC_X86_REG_EBX)
    res_edi = uc.reg_read(UC_X86_REG_EDI)
    assert res_ebx == 0x11223344
    assert res_edi == 0x55667788

    actual = PopState(
        prev_size=res_prev,
        prev_prev_size=res_prev_prev,
        tracked_size=res_tracked,
        flag_40=pop.flag_40,
        prov_id=pop.prov_id,
    )
    return actual, calls


test_new_sizes = [
    -1000000, -500, -1, 0, 1, 10, 50, 100, 500, 1000, 5000,
    10000, 50000, 100000, 500000, 1000000, 1999999, 2000000,
    2000001, 2500000, 10000000
]
test_pops = [
    PopState(prev_size=1000, prev_prev_size=950, tracked_size=1000, flag_40=1, prov_id=12),
    PopState(prev_size=0, prev_prev_size=0, tracked_size=500, flag_40=1, prov_id=45),  # new pop (prev=0)
    PopState(prev_size=2000000, prev_prev_size=1950000, tracked_size=2000000, flag_40=1, prov_id=3),
    PopState(prev_size=5000, prev_prev_size=4800, tracked_size=5000, flag_40=0, prov_id=7),  # flag_40 = 0
    PopState(prev_size=10000, prev_prev_size=9800, tracked_size=10000, flag_40=1, prov_id=99),
    PopState(prev_size=0, prev_prev_size=0, tracked_size=0, flag_40=0, prov_id=1),
    PopState(prev_size=1, prev_prev_size=1, tracked_size=1, flag_40=1, prov_id=10),
    PopState(prev_size=150000, prev_prev_size=140000, tracked_size=150000, flag_40=1, prov_id=500),
]

# Random fixtures
random.seed(445566)
for _ in range(50):
    ps = random.randint(0, 2500000)
    pps = random.randint(0, 2500000)
    ts = random.randint(0, 2500000)
    fl = random.choice([0, 1])
    pr = random.randint(1, 1000)
    test_pops.append(PopState(prev_size=ps, prev_prev_size=pps, tracked_size=ts, flag_40=fl, prov_id=pr))

fixture_count = 0
mismatches = 0

for pop in test_pops:
    for ns in test_new_sizes:
        exp_pop, exp_info = pop_set_size_model(pop, ns)
        act_pop, calls = run_emulation(pop, ns)
        fixture_count += 1

        if act_pop != exp_pop:
            mismatches += 1

        if exp_info["called_promotion"]:
            if not calls["called_4d1020"] or calls["delta_4d1020"] != exp_info["delta_out"]:
                mismatches += 1
        else:
            if calls["called_4d1020"]:
                mismatches += 1

assert mismatches == 0, f"{mismatches} mismatches found during pop set size emulation"

# Record receipts
out = ROOT / 'evidence/generated/pop-set-size'
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
ledger.record(report, session='pop-set-size')
ledger.save()

print(f"POP set size: {verified_count} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"POP set size emulation: {fixture_count} fixtures executed, 0 mismatches against pop_set_size_model.")
