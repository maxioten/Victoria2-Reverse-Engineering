#!/usr/bin/env python3
"""Verify CPromotionQuotaManager::ConsumeCapacity routine (0x004D1020..0x004D119E, caller at 0x00958486)."""
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
from promotion_quota_model import consume_promotion_capacity

data = (ROOT.parent / 'base-game/v2game.exe').read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = 0x400000

claims = []

# 1. Key instructions in CPromotionQuotaManager::ConsumeCapacity (0x004D1020..0x004D119E)
expected_promotion_quota_instructions = (
    (0x004D1020, 1, 'push', 'ebp'),
    (0x004D1021, 2, 'mov', 'ebp, esp'),
    (0x004D1023, 3, 'and', 'esp, 0xfffffff8'),
    (0x004D1026, 3, 'sub', 'esp, 0x14'),
    (0x004D102C, 3, 'mov', 'edi, dword ptr [eax + 0x60]'),
    (0x004D102F, 2, 'test', 'edi, edi'),
    (0x004D1031, 6, 'je', '0x4d1198'),
    (0x004D1037, 3, 'mov', 'ecx, dword ptr [ebp + 0xc]'),
    (0x004D103A, 2, 'mov', 'eax, dword ptr [ecx]'),
    (0x004D1040, 2, 'test', 'eax, eax'),
    (0x004D1042, 6, 'je', '0x4d1198'),
    (0x004D104A, 6, 'mov', 'ecx, dword ptr [esi + 0xf4]'),
    (0x004D1050, 6, 'sub', 'ecx, dword ptr [esi + 0xf0]'),
    (0x004D1056, 6, 'mov', 'edi, dword ptr [edi + 0x224]'),
    (0x004D105C, 6, 'lea', 'eax, [esi + 0xf0]'),
    (0x004D1062, 3, 'sar', 'ecx, 4'),
    (0x004D106B, 2, 'test', 'ecx, ecx'),
    (0x004D106D, 6, 'jle', '0x4d1190'),
    (0x004D1073, 2, 'mov', 'edi, dword ptr [eax]'),
    (0x004D1075, 3, 'add', 'edi, 8'),
    (0x004D1078, 2, 'mov', 'ebx, dword ptr [edi]'),
    (0x004D107A, 3, 'cmp', 'ebx, dword ptr [ebp + 8]'),
    (0x004D107D, 2, 'je', '0x4d108c'),
    (0x004D107F, 1, 'inc', 'edx'),
    (0x004D1080, 3, 'add', 'edi, 0x10'),
    (0x004D1083, 2, 'cmp', 'edx, ecx'),
    (0x004D1085, 2, 'jl', '0x4d1078'),
    (0x004D1092, 3, 'shl', 'edx, 4'),
    (0x004D1095, 4, 'mov', 'ecx, dword ptr [ecx + edx + 0xc]'),
    (0x004D1099, 2, 'cmp', 'ecx, edi'),
    (0x004D109D, 2, 'mov', 'ecx, edi'),
    (0x004D109F, 3, 'mov', 'ebx, dword ptr [ebp + 0xc]'),
    (0x004D10A2, 2, 'sub', 'edi, ecx'),
    (0x004D10A4, 2, 'mov', 'dword ptr [ebx], edi'),
    (0x004D10A8, 4, 'sub', 'dword ptr [edx + edi + 0xc], ecx'),
    (0x004D10B6, 3, 'sub', 'dword ptr [edi + 0x60], ecx'),
    (0x004D10BB, 5, 'cmp', 'dword ptr [edx + edi + 0xc], 0'),
    (0x004D10C4, 6, 'jg', '0x4d115b'),
    (0x004D119E, 3, 'ret', '8'),
)

for address, length, mnemonic, operand in expected_promotion_quota_instructions:
    claims.append({
        'id': f'quota_ins_{address:x}', 'kind': 'instructions', 'space': 'rva',
        'offset': hex(address - base), 'base': hex(address), 'arch': 'x86',
        'length': length, 'mnemonics': [mnemonic], 'operands': [operand] if operand else []
    })

# 2. Caller site verification in CPop::Update (0x00958481..0x00958486)
expected_caller_instructions = (
    (0x00958481, 3, 'lea', 'ecx, [ebp - 0x28]'),
    (0x00958484, 1, 'push', 'ecx'),
    (0x00958485, 1, 'push', 'edi'),
    (0x00958486, 5, 'call', '0x4d1020'),
)

for address, length, mnemonic, operand in expected_caller_instructions:
    claims.append({
        'id': f'quota_caller_ins_{address:x}', 'kind': 'instructions', 'space': 'rva',
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
wrong = dict(claims[0], id='negative_control_promotion_quota', mnemonics=['nop'])
dependent = dict(claims[1], id='negative_dependent_promotion_quota', depends_on=['negative_control_promotion_quota'])
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

STACK_BASE = 0x02000000
STACK_SIZE = 0x00100000
uc.mem_map(STACK_BASE, STACK_SIZE)

HEAP_BASE = 0x03000000
uc.mem_map(HEAP_BASE, 0x100000)

MANAGER_ADDR = HEAP_BASE + 0x1000
TLIST_ADDR   = HEAP_BASE + 0x2000
ENTRIES_BASE = HEAP_BASE + 0x3000
TARGET_OBJ_BASE = HEAP_BASE + 0x4000
MAP_SLOT     = HEAP_BASE + 0x5000
INOUT_ADDR   = HEAP_BASE + 0x6000
CONTEXT_OBJ  = HEAP_BASE + 0x7000
ARRAY_SLOT   = HEAP_BASE + 0x8000
NIL_NODE     = HEAP_BASE + 0x9000

# Mock 0x004C8D10: mov eax, MAP_SLOT; ret
uc.mem_write(0x004C8D10, b'\xb8\x00\x50\x00\x03\xc3')
# Mock 0x004F2760: ret
uc.mem_write(0x004F2760, b'\xc3')

# Setup valid STL _Tree nil node
uc.mem_write(NIL_NODE + 0x00, struct.pack('<I', NIL_NODE))
uc.mem_write(NIL_NODE + 0x04, struct.pack('<I', NIL_NODE))
uc.mem_write(NIL_NODE + 0x08, struct.pack('<I', NIL_NODE))
uc.mem_write(NIL_NODE + 0x14, struct.pack('<B', 1))
uc.mem_write(NIL_NODE + 0x15, struct.pack('<B', 1))

# Manager setup
uc.mem_write(MANAGER_ADDR + 0x60, struct.pack('<I', TLIST_ADDR))
uc.mem_write(TLIST_ADDR + 0x224, struct.pack('<I', 0))
uc.mem_write(TLIST_ADDR + 0x130, struct.pack('<I', NIL_NODE))
uc.mem_write(TLIST_ADDR + 0x13C, struct.pack('<I', ARRAY_SLOT))
uc.mem_write(CONTEXT_OBJ + 0x28, struct.pack('<i', 0))

def emu_consume_capacity(target_key_idx: int, req_amount: int, entries_data: list[tuple[int, int]]) -> tuple[int, list[int], list[int]]:
    """
    entries_data: [(capacity, quota), ...]
    target_key_idx: índice del elemento destino a buscar (0 .. len-1) o -1 para no match.
    """
    esp = STACK_BASE + 0x80000
    ret_addr = 0x00401000

    num_e = len(entries_data)
    uc.mem_write(TLIST_ADDR + 0xF0, struct.pack('<I', ENTRIES_BASE))
    uc.mem_write(TLIST_ADDR + 0xF4, struct.pack('<I', ENTRIES_BASE + num_e * 16))

    target_keys = []
    for idx, (cap, quota) in enumerate(entries_data):
        t_obj = TARGET_OBJ_BASE + idx * 0x100
        target_keys.append(t_obj)
        uc.mem_write(ENTRIES_BASE + idx * 16 + 0x00, struct.pack('<I', 0))
        uc.mem_write(ENTRIES_BASE + idx * 16 + 0x04, struct.pack('<I', 0))
        uc.mem_write(ENTRIES_BASE + idx * 16 + 0x08, struct.pack('<I', t_obj))
        uc.mem_write(ENTRIES_BASE + idx * 16 + 0x0C, struct.pack('<i', cap))

        uc.mem_write(t_obj + 0x60, struct.pack('<i', quota))
        uc.mem_write(t_obj + 0x68, struct.pack('<I', CONTEXT_OBJ))

    search_key = target_keys[target_key_idx] if 0 <= target_key_idx < num_e else 0xDEADBEEF

    uc.mem_write(INOUT_ADDR, struct.pack('<i', req_amount))

    uc.mem_write(esp + 8, struct.pack('<I', INOUT_ADDR))
    uc.mem_write(esp + 4, struct.pack('<I', search_key))
    uc.mem_write(esp, struct.pack('<I', ret_addr))

    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_EAX, MANAGER_ADDR)

    def hook_unmapped(u, access, address, size, value, user_data):
        eip = u.reg_read(UC_X86_REG_EIP)
        print(f"UNMAPPED MEMORY: access={access}, address=0x{address:08X}, size={size}, EIP=0x{eip:08X}")
        return False

    h = uc.hook_add(unicorn.UC_HOOK_MEM_READ_UNMAPPED | unicorn.UC_HOOK_MEM_WRITE_UNMAPPED, hook_unmapped)
    uc.emu_start(0x004D1020, ret_addr)
    uc.hook_del(h)

    final_rem = struct.unpack('<i', uc.mem_read(INOUT_ADDR, 4))[0]
    final_caps = []
    final_quotas = []
    for idx in range(num_e):
        c = struct.unpack('<i', uc.mem_read(ENTRIES_BASE + idx * 16 + 0x0C, 4))[0]
        q = struct.unpack('<i', uc.mem_read(TARGET_OBJ_BASE + idx * 0x100 + 0x60, 4))[0]
        final_caps.append(c)
        final_quotas.append(q)

    return final_rem, final_caps, final_quotas

# Generate fixtures
fixtures = []

# Case 1: Single entry, req < cap
fixtures.append((0, 300, [(500, 1000)]))

# Case 2: Single entry, req == cap
fixtures.append((0, 500, [(500, 1000)]))

# Case 3: Single entry, req > cap
fixtures.append((0, 800, [(500, 1000)]))

# Case 4: Zero requested
fixtures.append((0, 0, [(500, 1000)]))

# Case 5: Multiple entries (match index 1)
fixtures.append((1, 250, [(400, 800), (300, 600), (200, 500)]))

# Case 6: Key not found
fixtures.append((-1, 250, [(400, 800), (300, 600)]))

# Deterministic randomized fixtures
random.seed(332211)
for _ in range(100):
    num_entries = random.randint(1, 5)
    e_data = [(random.randint(10, 2000), random.randint(100, 5000)) for _ in range(num_entries)]
    t_idx = random.randint(-1, num_entries - 1)
    req = random.randint(0, 3000)
    fixtures.append((t_idx, req, e_data))

mismatches = 0
for t_idx, req, e_data in fixtures:
    model_entries = [{'key': idx, 'capacity': cap, 'quota': q} for idx, (cap, q) in enumerate(e_data)]
    exp_rem, _, exp_updated = consume_promotion_capacity(t_idx, req, model_entries)
    exp_caps = [e['capacity'] for e in exp_updated]
    exp_quotas = [e['quota'] for e in exp_updated]

    act_rem, act_caps, act_quotas = emu_consume_capacity(t_idx, req, e_data)

    if act_rem != exp_rem or act_caps != exp_caps or act_quotas != exp_quotas:
        mismatches += 1
        print(f"Mismatch: t_idx={t_idx}, req={req} -> act=({act_rem}, {act_caps}, {act_quotas}), exp=({exp_rem}, {exp_caps}, {exp_quotas})")

assert mismatches == 0, f"{mismatches} mismatches found during promotion quota emulation"

# Record receipts in evidence/generated/promotion-quota/
out = ROOT / 'evidence/generated/promotion-quota'
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
ledger.record(report, session='promotion-quota')
ledger.save()

print(f"Promotion quota: {verified_count} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Promotion quota emulation: {len(fixtures)} fixtures executed, 0 mismatches against promotion_quota_model.")
