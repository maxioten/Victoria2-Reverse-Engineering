#!/usr/bin/env python3
"""Verify EventOption_EvaluateAIChance (0x008AEB00) and callers in Event_Fire."""
import hashlib
import json
from pathlib import Path
import struct
import capstone
import pefile
import unicorn
from unicorn.x86_const import (
    UC_X86_REG_EAX, UC_X86_REG_ESP,
)
from reverify.ledger import Ledger
from reverify.verifier import Claim, Verifier
from ai_chance_model import evaluate_ai_chance

ROOT = Path(__file__).resolve().parents[1]
data = (ROOT.parent / 'base-game/v2game.exe').read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
image = pe.get_memory_mapped_image()
base = 0x400000

claims = []

# 1. Call sites in Event_Fire (0x008A8120)
# 0x008A8268: CALL 0x008AEB00 (total weight summation)
# 0x008A8325: CALL 0x008AEB00 (option selection loop)
for call_site in (0x008A8268, 0x008A8325):
    claims.append({
        'id': f'call_ai_chance_{call_site:x}', 'kind': 'instructions', 'space': 'rva',
        'offset': hex(call_site - base), 'base': hex(call_site), 'arch': 'x86',
        'length': 5, 'mnemonics': ['call'], 'operands': ['0x8aeb00']
    })

# 2. Instruction checks in EventOption_EvaluateAIChance (0x008AEB00)
expected_instructions = (
    (0x8aeb00, 1, 'push', 'ebp'),
    (0x8aeb06, 3, 'mov', 'eax, dword ptr [ebp + 8]'),
    (0x8aeb09, 3, 'mov', 'ecx, dword ptr [eax + 8]'),
    (0x8aeb0c, 3, 'mov', 'dword ptr [ebp - 8], ecx'),
    (0x8aeb0f, 3, 'mov', 'ecx, dword ptr [eax + 0x10]'),
    (0x8aeb12, 3, 'sub', 'ecx, dword ptr [eax + 0xc]'),
    (0x8aeb15, 3, 'sar', 'ecx, 2'),
    (0x8aeb1b, 2, 'test', 'ecx, ecx'),
    (0x8aeb1d, 6, 'je', '0x8aeba3'),
    (0x8aeb3d, 3, 'mov', 'esi, dword ptr [edi + 0xc]'),
    (0x8aeb40, 3, 'sub', 'esi, dword ptr [edi + 8]'),
    (0x8aeb45, 3, 'sar', 'esi, 2'),
    (0x8aeb56, 2, 'mov', 'edx, dword ptr [ecx]'),
    (0x8aeb5b, 3, 'mov', 'edx, dword ptr [edx + 0x18]'),
    (0x8aeb5f, 2, 'call', 'edx'),
    (0x8aeb61, 2, 'test', 'al, al'),
    (0x8aeb63, 2, 'je', '0x8aeb91'),
    (0x8aeb76, 3, 'mov', 'eax, dword ptr [eax + 0x20]'),
    (0x8aeb79, 3, 'imul', 'dword ptr [ebp - 8]'),
    (0x8aeb7e, 5, 'push', '0x3e8'),
    (0x8aeb85, 5, 'call', '0xac02a0'),
    (0x8aeb8d, 2, 'test', 'eax, eax'),
    (0x8aeb8f, 2, 'jle', '0x8aeb9d'),
    (0x8aeba3, 3, 'mov', 'eax, dword ptr [eax + 0x1c]'),
    (0x8aeba6, 3, 'imul', 'dword ptr [ebp - 8]'),
    (0x8aebab, 5, 'push', '0x3e8'),
    (0x8aebb2, 5, 'call', '0xac02a0'),
    (0x8aebb7, 3, 'mov', 'ecx, dword ptr [ebp + 0xc]'),
    (0x8aebba, 2, 'mov', 'dword ptr [ecx], eax'),
    (0x8aebbc, 2, 'mov', 'eax, ecx'),
    (0x8aebc1, 3, 'ret', '0xc'),
)

for address, length, mnemonic, operand in expected_instructions:
    claims.append({
        'id': f'ai_chance_ins_{address:x}', 'kind': 'instructions', 'space': 'rva',
        'offset': hex(address - base), 'base': hex(address), 'arch': 'x86',
        'length': length, 'mnemonics': [mnemonic], 'operands': [operand]
    })

verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]

# Negative controls
wrong = dict(claims[0], id='negative_control', operands=['0x8ae000'])
dependent = dict(claims[1], id='negative_dependent', depends_on=['negative_control'])
controls = verifier.verify_all([Claim.from_dict(wrong), Claim.from_dict(dependent)])
assert [r['verdict'] for r in controls['results']] == ['REFUTED', 'INVALIDATED']

# 3. Unicorn dynamic verification: fresh instance per test for isolated memory
return_addr = 0x12345678

def run_ai_chance(base_val, multiplier, modifiers):
    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
    uc.mem_map(0x400000, 0x1100000, unicorn.UC_PROT_ALL)
    uc.mem_write(0x400000, image)

    stack_base = 0x200000
    uc.mem_map(stack_base, 0x40000, unicorn.UC_PROT_ALL)
    uc.mem_map(0x12340000, 0x10000, unicorn.UC_PROT_ALL)
    uc.mem_write(0x12345678, b'\x90\x90')

    def hook_code(u, address, size, user_data):
        if address == return_addr:
            u.emu_stop()

    uc.hook_add(unicorn.UC_HOOK_CODE, hook_code)

    esp = stack_base + 0x10000
    block_ptr = stack_base + 0x5000
    out_ptr = stack_base + 0x5100
    mod_vec = stack_base + 0x5200

    uc.mem_write(block_ptr + 8, struct.pack('<i', base_val))
    uc.mem_write(block_ptr + 0x1c, struct.pack('<i', multiplier))

    mod_ptrs = []
    curr_ptr = stack_base + 0x6000
    for factor, cond_results in modifiers:
        mod_obj = curr_ptr; curr_ptr += 0x100
        cond_vec = curr_ptr; curr_ptr += 0x100
        cond_ptrs = []
        for res in cond_results:
            cond_obj = curr_ptr; curr_ptr += 0x40
            vtable = curr_ptr; curr_ptr += 0x40
            code = curr_ptr; curr_ptr += 0x40
            uc.mem_write(code, b'\xb0' + bytes([1 if res else 0]) + b'\xc2\x04\x00')
            uc.mem_write(vtable + 0x18, struct.pack('<I', code))
            uc.mem_write(cond_obj, struct.pack('<I', vtable))
            cond_ptrs.append(cond_obj)

        for i, cp in enumerate(cond_ptrs):
            uc.mem_write(cond_vec + i*4, struct.pack('<I', cp))
        uc.mem_write(mod_obj + 8, struct.pack('<I', cond_vec))
        uc.mem_write(mod_obj + 0xc, struct.pack('<I', cond_vec + len(cond_ptrs)*4))
        uc.mem_write(mod_obj + 0x20, struct.pack('<i', factor))
        mod_ptrs.append(mod_obj)

    for i, mp in enumerate(mod_ptrs):
        uc.mem_write(mod_vec + i*4, struct.pack('<I', mp))
    uc.mem_write(block_ptr + 0xc, struct.pack('<I', mod_vec))
    uc.mem_write(block_ptr + 0x10, struct.pack('<I', mod_vec + len(mod_ptrs)*4))

    uc.mem_write(esp, struct.pack('<IIII', return_addr, block_ptr, out_ptr, 0))
    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.emu_start(0x008AEB00, return_addr)

    ret_eax = uc.reg_read(UC_X86_REG_EAX)
    val = struct.unpack('<i', uc.mem_read(out_ptr, 4))[0]
    return val, (ret_eax == out_ptr)

test_fixtures = [
    # (base_val, multiplier, modifiers)
    (0, 1000, []),
    (100, 1000, []),
    (500, 1000, []),
    (1000, 1000, []),
    (1000, 500, []),
    (1000, 2000, []),
    (1000, 0, []),
    (1000, 1000, [(500, [True])]),
    (1000, 1000, [(500, [False])]),
    (1000, 1000, [(2000, [True])]),
    (1000, 1000, [(500, [True, True])]),
    (1000, 1000, [(500, [True, False])]),
    (1000, 1000, [(500, [False, True])]),
    (1000, 1000, [(500, [True, True, True])]),
    (1000, 1000, [(500, [True, True, False])]),
    (1000, 1000, [(500, [True]), (2000, [True])]),
    (1000, 1000, [(500, [True]), (2000, [False])]),
    (1000, 1000, [(500, [False]), (2000, [True])]),
    (1000, 1000, [(200, [True]), (300, [True]), (400, [True])]),
    (1000, 1000, [(0, [True]), (5000, [True])]), # early break on zero
    (1000, 1000, [(-500, [True]), (2000, [True])]), # early break on negative
    (50, 1000, [(100, [True])]), # 50 * 100 / 1000 = 5
    (10, 1000, [(50, [True])]),  # 10 * 50 / 1000 = 0
    (100000, 1000, [(1500, [True]), (1200, [True])]),
    (2500, 1500, [(800, [True]), (1250, [True])]),
]

for b in [10, 100, 1000, 5000]:
    for m in [500, 1000, 1500]:
        test_fixtures.append((b, m, []))
        test_fixtures.append((b, m, [(800, [True])]))
        test_fixtures.append((b, m, [(800, [False])]))
        test_fixtures.append((b, m, [(1250, [True]), (750, [True])]))
        test_fixtures.append((b, m, [(1250, [True]), (750, [False])]))
        test_fixtures.append((b, m, [(500, [True, True, True])]))

mismatches = 0
emulation_records = []

for base_val, multiplier, modifiers in test_fixtures:
    actual_val, actual_ret_ok = run_ai_chance(base_val, multiplier, modifiers)
    expected_val = evaluate_ai_chance(base_val, multiplier, modifiers)

    passed = (actual_val == expected_val and actual_ret_ok)
    if not passed:
        mismatches += 1
        print(f"MISMATCH: base={base_val}, mult={multiplier}, actual=({actual_val}, {actual_ret_ok}) vs expected=({expected_val}, True)")

    emulation_records.append({
        'base': base_val, 'multiplier': multiplier, 'num_modifiers': len(modifiers),
        'actual': actual_val, 'expected': expected_val, 'return_ptr_match': actual_ret_ok,
        'pass': passed
    })

assert mismatches == 0, f"{mismatches} mismatches in AI chance evaluation"

out = ROOT / 'evidence/generated/ai-chance'
out.mkdir(parents=True, exist_ok=True)
(out / 'claims.json').write_text(json.dumps(claims, indent=2) + '\n')
(out / 'reverify.json').write_text(json.dumps(report, indent=2) + '\n')
(out / 'negative-controls.json').write_text(json.dumps(controls, indent=2) + '\n')
(out / 'emulation.json').write_text(json.dumps({
    'total_fixtures': len(test_fixtures),
    'mismatches': mismatches,
    'records_sample': emulation_records[:20]
}, indent=2) + '\n')

ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify')
ledger.record(report, session='event-option-ai-chance')
ledger.save()

print(f"AI chance: {len(claims)} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"AI chance emulation: {len(test_fixtures)} fixtures executed, 0 mismatches against ai_chance_model.")
