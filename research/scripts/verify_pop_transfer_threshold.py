#!/usr/bin/env python3
"""Verify POP demographic transfer and survival threshold in CPop::Update (0x009584A6, 0x0095879C, 0x00958A5F)."""
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
from pop_set_size_model import PopState
from pop_transfer_threshold_model import pop_transfer_threshold_model

data = (ROOT.parent / 'base-game/v2game.exe').read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = 0x400000

claims = []

# 1. Key instructions across all 3 demographic transfer channels in CPop::Update
expected_channel_instructions = (
    # Channel 1: Promotion (0x009584A6..0x009584FB)
    (0x009584A6, 3, 'mov', 'edx, dword ptr [edi + 0x68]'),
    (0x009584A9, 2, 'mov', 'ecx, ebx'),
    (0x009584AB, 2, 'sub', 'ecx, eax'),
    (0x009584AD, 6, 'cmp', 'ecx, dword ptr [edx + 0x3c8]'),
    (0x009584B3, 2, 'jge', '0x9584bb'),
    (0x009584B5, 6, 'mov', 'dword ptr [edi + 0x190], ebx'),
    (0x009584BB, 2, 'mov', 'eax, ebx'),
    (0x009584BD, 6, 'sub', 'eax, dword ptr [edi + 0x190]'),
    (0x009584C3, 2, 'mov', 'esi, edi'),
    (0x009584C5, 3, 'mov', 'dword ptr [ebp - 0x44], eax'),
    (0x009584C8, 5, 'call', '0x955fd0'),
    (0x009584CD, 3, 'mov', 'eax, dword ptr [ebp - 0x44]'),
    (0x009584D0, 2, 'sub', 'eax, ebx'),
    (0x009584D2, 6, 'add', 'dword ptr [edi + 0x164], eax'),
    (0x009584D8, 3, 'mov', 'esi, dword ptr [ebp - 0x2c]'),
    (0x009584DB, 3, 'mov', 'eax, dword ptr [esi + 0x58]'),
    (0x009584DE, 6, 'mov', 'ebx, dword ptr [edi + 0x190]'),
    (0x009584E4, 2, 'add', 'ebx, eax'),
    (0x009584E6, 3, 'mov', 'dword ptr [ebp - 0x44], eax'),
    (0x009584E9, 2, 'mov', 'eax, ebx'),
    (0x009584EB, 5, 'call', '0x955fd0'),
    (0x009584F0, 3, 'sub', 'ebx, dword ptr [ebp - 0x44]'),
    (0x009584F3, 2, 'mov', 'eax, esi'),
    (0x009584F5, 6, 'add', 'dword ptr [eax + 0x164], ebx'),

    # Channel 2: Assimilation (0x0095879C..0x009587F1)
    (0x0095879C, 3, 'mov', 'edx, dword ptr [edi + 0x68]'),
    (0x0095879F, 2, 'mov', 'ecx, ebx'),
    (0x009587A1, 2, 'sub', 'ecx, eax'),
    (0x009587A3, 6, 'cmp', 'ecx, dword ptr [edx + 0x3c8]'),
    (0x009587A9, 2, 'jge', '0x9587b1'),
    (0x009587AB, 6, 'mov', 'dword ptr [edi + 0x194], ebx'),
    (0x009587B1, 2, 'mov', 'eax, ebx'),
    (0x009587B3, 6, 'sub', 'eax, dword ptr [edi + 0x194]'),
    (0x009587B9, 2, 'mov', 'esi, edi'),
    (0x009587BB, 3, 'mov', 'dword ptr [ebp - 0x44], eax'),
    (0x009587BE, 5, 'call', '0x955fd0'),
    (0x009587C3, 3, 'mov', 'eax, dword ptr [ebp - 0x44]'),
    (0x009587C6, 2, 'sub', 'eax, ebx'),
    (0x009587C8, 6, 'add', 'dword ptr [edi + 0x164], eax'),
    (0x009587CE, 3, 'mov', 'esi, dword ptr [ebp - 0x2c]'),
    (0x009587D1, 3, 'mov', 'eax, dword ptr [esi + 0x58]'),
    (0x009587D4, 6, 'mov', 'ebx, dword ptr [edi + 0x194]'),
    (0x009587DA, 2, 'add', 'ebx, eax'),
    (0x009587DC, 3, 'mov', 'dword ptr [ebp - 0x44], eax'),
    (0x009587DF, 2, 'mov', 'eax, ebx'),
    (0x009587E1, 5, 'call', '0x955fd0'),
    (0x009587E6, 3, 'sub', 'ebx, dword ptr [ebp - 0x44]'),
    (0x009587E9, 2, 'mov', 'eax, esi'),
    (0x009587EB, 6, 'add', 'dword ptr [eax + 0x164], ebx'),

    # Channel 3: Conversion (0x00958A5F..0x00958AB4)
    (0x00958A5F, 3, 'mov', 'edx, dword ptr [edi + 0x68]'),
    (0x00958A62, 2, 'mov', 'ecx, ebx'),
    (0x00958A64, 2, 'sub', 'ecx, eax'),
    (0x00958A66, 6, 'cmp', 'ecx, dword ptr [edx + 0x3c8]'),
    (0x00958A6C, 2, 'jge', '0x958a74'),
    (0x00958A6E, 6, 'mov', 'dword ptr [edi + 0x198], ebx'),
    (0x00958A74, 2, 'mov', 'eax, ebx'),
    (0x00958A76, 6, 'sub', 'eax, dword ptr [edi + 0x198]'),
    (0x00958A7C, 2, 'mov', 'esi, edi'),
    (0x00958A7E, 3, 'mov', 'dword ptr [ebp - 0x44], eax'),
    (0x00958A81, 5, 'call', '0x955fd0'),
    (0x00958A86, 3, 'mov', 'eax, dword ptr [ebp - 0x44]'),
    (0x00958A89, 2, 'sub', 'eax, ebx'),
    (0x00958A8B, 6, 'add', 'dword ptr [edi + 0x16c], eax'),
    (0x00958A91, 3, 'mov', 'esi, dword ptr [ebp - 0x1c]'),
    (0x00958A94, 3, 'mov', 'eax, dword ptr [esi + 0x58]'),
    (0x00958A97, 6, 'mov', 'ebx, dword ptr [edi + 0x198]'),
    (0x00958A9D, 2, 'add', 'ebx, eax'),
    (0x00958A9F, 3, 'mov', 'dword ptr [ebp - 0x44], eax'),
    (0x00958AA2, 2, 'mov', 'eax, ebx'),
    (0x00958AA4, 5, 'call', '0x955fd0'),
    (0x00958AA9, 3, 'sub', 'ebx, dword ptr [ebp - 0x44]'),
    (0x00958AAC, 2, 'mov', 'eax, esi'),
    (0x00958AAE, 6, 'add', 'dword ptr [eax + 0x16c], ebx'),
)

for address, length, mnemonic, operand in expected_channel_instructions:
    claims.append({
        'id': f'trans_ins_{address:x}', 'kind': 'instructions', 'space': 'rva',
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
wrong = dict(claims[0], id='negative_control_pop_transfer', mnemonics=['nop'])
dependent = dict(claims[1], id='negative_dependent_pop_transfer', depends_on=['negative_control_pop_transfer'])
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
heap_size = 0x00080000
uc.mem_map(heap_base, heap_size, unicorn.UC_PROT_ALL)

data_page = 0x01258000
uc.mem_map(data_page, 0x2000, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
uc.mem_write(0x01258728, (0x00240000).to_bytes(4, 'little'))
uc.mem_write(0x00240000, (0x00250000).to_bytes(4, 'little'))

# Stubs for SetSize dependencies
uc.mem_write(0x004C25B0, b"\xa1\x28\x87\x25\x01\xc3")  # mov eax, [0x01258728]; ret
uc.mem_write(0x004EE550, b"\xc2\x08\x00")              # ret 8
uc.mem_write(0x004D1020, b"\xc2\x08\x00")              # ret 8


def run_channel_emulation(channel_name: str, src_pop: PopState, tgt_pop: PopState,
                         src_acc: int, tgt_acc: int, req_delta: int, min_thresh: int):
    src_addr = 0x00200000
    tgt_addr = 0x00201000
    prov_addr = 0x00210000
    type_addr = 0x00220000
    stop_addr = 0x00555555

    # Config province & type
    uc.mem_write(prov_addr + 0x58, (1).to_bytes(4, 'little'))
    uc.mem_write(prov_addr + 0x188, (0x00230000).to_bytes(4, 'little'))
    uc.mem_write(type_addr + 0x40, (1).to_bytes(1, 'little'))
    uc.mem_write(type_addr + 0x3C8, min_thresh.to_bytes(4, 'little'))

    # Setup source POP
    uc.mem_write(src_addr + 0x58, src_pop.prev_size.to_bytes(4, 'little'))
    uc.mem_write(src_addr + 0x5C, src_pop.prev_prev_size.to_bytes(4, 'little'))
    uc.mem_write(src_addr + 0x60, src_pop.tracked_size.to_bytes(4, 'little'))
    uc.mem_write(src_addr + 0x64, prov_addr.to_bytes(4, 'little'))
    uc.mem_write(src_addr + 0x68, type_addr.to_bytes(4, 'little'))
    # Accumulator (0x164 or 0x16C)
    acc_offset = 0x16C if channel_name == 'Conversion' else 0x164
    slot_offset = {'Promotion': 0x190, 'Assimilation': 0x194, 'Conversion': 0x198}[channel_name]
    uc.mem_write(src_addr + acc_offset, (src_acc & 0xFFFFFFFF).to_bytes(4, 'little', signed=False))
    uc.mem_write(src_addr + slot_offset, (req_delta & 0xFFFFFFFF).to_bytes(4, 'little', signed=False))

    # Setup target POP
    uc.mem_write(tgt_addr + 0x58, tgt_pop.prev_size.to_bytes(4, 'little'))
    uc.mem_write(tgt_addr + 0x5C, tgt_pop.prev_prev_size.to_bytes(4, 'little'))
    uc.mem_write(tgt_addr + 0x60, tgt_pop.tracked_size.to_bytes(4, 'little'))
    uc.mem_write(tgt_addr + 0x64, prov_addr.to_bytes(4, 'little'))
    uc.mem_write(tgt_addr + 0x68, type_addr.to_bytes(4, 'little'))
    uc.mem_write(tgt_addr + acc_offset, (tgt_acc & 0xFFFFFFFF).to_bytes(4, 'little', signed=False))

    # Stack frame
    ebp = 0x0011FF00
    esp = ebp - 0x80
    # Store target pop pointer in ebp frame
    target_slot = 0x1C if channel_name == 'Conversion' else 0x2C
    uc.mem_write(ebp - target_slot, tgt_addr.to_bytes(4, 'little'))

    if channel_name == 'Promotion':
        start_va = 0x009584A6
        end_va = 0x009584FB
    elif channel_name == 'Assimilation':
        start_va = 0x0095879C
        end_va = 0x009587F1
    else:
        start_va = 0x00958A5F
        end_va = 0x00958AB4

    # Set registers
    uc.reg_write(UC_X86_REG_EAX, req_delta & 0xFFFFFFFF)
    uc.reg_write(UC_X86_REG_EBX, src_pop.prev_size & 0xFFFFFFFF)
    uc.reg_write(UC_X86_REG_EDI, src_addr)
    uc.reg_write(UC_X86_REG_EBP, ebp)
    uc.reg_write(UC_X86_REG_ESP, esp)

    uc.emu_start(start_va, end_va, timeout=2000000)

    # Read back results
    new_src_size = int.from_bytes(uc.mem_read(src_addr + 0x58, 4), 'little')
    new_tgt_size = int.from_bytes(uc.mem_read(tgt_addr + 0x58, 4), 'little')
    new_src_acc = int.from_bytes(uc.mem_read(src_addr + acc_offset, 4), 'little', signed=True)
    new_tgt_acc = int.from_bytes(uc.mem_read(tgt_addr + acc_offset, 4), 'little', signed=True)
    effective_slot = int.from_bytes(uc.mem_read(src_addr + slot_offset, 4), 'little')

    return new_src_size, new_tgt_size, new_src_acc, new_tgt_acc, effective_slot


channels = ['Promotion', 'Assimilation', 'Conversion']
fixtures = []

# Base fixtures
base_cases = [
    # (src_size, tgt_size, req_delta, min_thresh)
    (1000, 500, 200, 100),   # normal: rem=800 >= 100
    (1000, 500, 950, 100),   # micro-pop absorption: rem=50 < 100 -> absorbs all 1000
    (1000, 500, 1000, 100),  # exact exhaustion: rem=0 < 100 -> absorbs all 1000
    (500, 0, 100, 50),       # target empty: rem=400 >= 50
    (500, 0, 480, 50),       # target empty with micro absorption: rem=20 < 50 -> absorbs all 500
    (200, 1999900, 150, 20), # near cap: rem=50 >= 20, target caps at 2M
    (300, 1999900, 290, 50), # near cap + absorption: rem=10 < 50 -> absorbs 300, target caps
]

random.seed(887766)
for _ in range(30):
    s_sz = random.randint(50, 50000)
    t_sz = random.randint(0, 1900000)
    r_dl = random.randint(1, s_sz)
    m_th = random.randint(10, 200)
    base_cases.append((s_sz, t_sz, r_dl, m_th))

fixture_count = 0
mismatches = 0

for ch in channels:
    for s_sz, t_sz, r_dl, m_th in base_cases:
        src_pop = PopState(prev_size=s_sz, prev_prev_size=s_sz, tracked_size=s_sz, flag_40=1, prov_id=1)
        tgt_pop = PopState(prev_size=t_sz, prev_prev_size=t_sz, tracked_size=t_sz, flag_40=1, prov_id=1)

        exp = pop_transfer_threshold_model(src_pop, tgt_pop, 0, 0, r_dl, m_th)
        act_src_sz, act_tgt_sz, act_src_acc, act_tgt_acc, act_slot = run_channel_emulation(
            ch, src_pop, tgt_pop, 0, 0, r_dl, m_th
        )
        fixture_count += 1

        if (act_src_sz != exp.source_pop.prev_size or
            act_tgt_sz != exp.target_pop.prev_size or
            act_src_acc != exp.source_acc or
            act_tgt_acc != exp.target_acc or
            act_slot != exp.effective_delta):
            mismatches += 1

assert mismatches == 0, f"{mismatches} mismatches found during pop demographic transfer emulation"

out = ROOT / 'evidence/generated/pop-transfer-threshold'
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
ledger.record(report, session='pop-transfer-threshold')
ledger.save()

print(f"POP transfer threshold: {verified_count} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"POP transfer threshold emulation: {fixture_count} fixtures executed, 0 mismatches against pop_transfer_threshold_model.")
