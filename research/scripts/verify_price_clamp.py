#!/usr/bin/env python3
"""Verify World Market price bounds (kPriceMinFactor/kPriceMaxFactor) and clamping logic."""
import hashlib
import json
from pathlib import Path
import struct
import capstone
import pefile
import unicorn
from unicorn.x86_const import (
    UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
    UC_X86_REG_EDI, UC_X86_REG_EIP, UC_X86_REG_ESP, UC_X86_REG_EBP,
)
from reverify.ledger import Ledger
from reverify.verifier import Claim, Verifier
from price_clamp_model import clamp_price, compute_price_bounds

ROOT = Path(__file__).resolve().parents[1]
data = (ROOT.parent / 'base-game/v2game.exe').read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
image = pe.get_memory_mapped_image()
base = 0x400000
cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

claims = []

# 1. Constant bytes: kPriceMinFactor and kPriceMaxFactor
# kPriceMinFactor at 0x00E45C30 = 6554.10009765625 (0.2 * 32768 + 0.5)
# kPriceMaxFactor at 0x00E45C28 = 163840.5 (5.0 * 32768 + 0.5)
claims.append({
    'id': 'price_min_factor_bytes', 'kind': 'bytes_at', 'space': 'rva',
    'offset': hex(0x00E45C30 - base), 'expected': '000000a0199ab940'
})
claims.append({
    'id': 'price_max_factor_bytes', 'kind': 'bytes_at', 'space': 'rva',
    'offset': hex(0x00E45C28 - base), 'expected': '0000000004000441'
})

# 2. Call sites to price calculator 0x00482930
# 0x00489BA6 in Economy_Update: CALL 0x00482930
# 0x0068BF4A in EconomyManager_UpdateFull: CALL 0x00482930
for call_site in (0x00489BA6, 0x0068BF4A):
    claims.append({
        'id': f'call_price_calc_{call_site:x}', 'kind': 'instructions', 'space': 'rva',
        'offset': hex(call_site - base), 'base': hex(call_site), 'arch': 'x86',
        'length': 5, 'mnemonics': ['call'], 'operands': ['0x482930']
    })

# 3. Price clamping instructions in 0x00482C46..0x00482D1E
expected_instructions = (
    (0x482c46, 6, 'fld', 'qword ptr [0xe45c30]'),
    (0x482c84, 3, 'mov', 'ebx, dword ptr [eax + 0x30]'),
    (0x482c87, 3, 'mov', 'edx, dword ptr [eax + 0x34]'),
    (0x482c90, 5, 'call', '0xb31c36'),
    (0x482c9c, 5, 'call', '0xac9f20'),
    (0x482ca1, 6, 'fld', 'qword ptr [0xe45c28]'),
    (0x482ca9, 4, 'shrd', 'eax, ebx, 0xf'),
    (0x482cb0, 3, 'sar', 'ebx, 0xf'),
    (0x482cb3, 5, 'call', '0xb31c36'),
    (0x482cc2, 5, 'call', '0xac9f20'),
    (0x482cc7, 4, 'shrd', 'eax, edx, 0xf'),
    (0x482ccb, 3, 'sar', 'edx, 0xf'),
    (0x482cce, 2, 'cmp', 'edi, ebx'),
    (0x482cd0, 2, 'jg', '0x482ce6'),
    (0x482cd2, 2, 'jl', '0x482cdc'),
    (0x482cd4, 3, 'mov', 'ecx, dword ptr [ebp - 0x20]'),
    (0x482cd7, 3, 'cmp', 'ecx, dword ptr [ebp - 0x50]'),
    (0x482cda, 2, 'jae', '0x482ce6'),
    (0x482cdc, 3, 'mov', 'edx, dword ptr [ebp - 0x50]'),
    (0x482cdf, 3, 'mov', 'dword ptr [ebp - 0x20], edx'),
    (0x482ce2, 2, 'mov', 'edi, ebx'),
    (0x482ce4, 2, 'jmp', '0x482cf6'),
    (0x482ce6, 2, 'cmp', 'edx, edi'),
    (0x482ce8, 2, 'jg', '0x482d1e'),
    (0x482cea, 2, 'jl', '0x482cf1'),
    (0x482cec, 3, 'cmp', 'eax, dword ptr [ebp - 0x20]'),
    (0x482cef, 2, 'jae', '0x482d1e'),
    (0x482cf1, 3, 'mov', 'dword ptr [ebp - 0x20], eax'),
    (0x482cf4, 2, 'mov', 'edi, edx'),
    (0x482cf6, 6, 'mov', 'ecx, dword ptr [0x125ba10]'),
    (0x482d19, 5, 'call', '0x47da50'),
    (0x482d1e, 3, 'mov', 'eax, dword ptr [ebp - 0x20]'),
)

for address, length, mnemonic, operand in expected_instructions:
    claims.append({
        'id': f'clamp_ins_{address:x}', 'kind': 'instructions', 'space': 'rva',
        'offset': hex(address - base), 'base': hex(address), 'arch': 'x86',
        'length': length, 'mnemonics': [mnemonic], 'operands': [operand]
    })

verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]

# Negative controls: wrong factor constant address and dependent claim
wrong = dict(claims[0], id='negative_control', expected='ffffffffffffffff')
dependent = dict(claims[1], id='negative_dependent', depends_on=['negative_control'])
controls = verifier.verify_all([Claim.from_dict(wrong), Claim.from_dict(dependent)])
assert [r['verdict'] for r in controls['results']] == ['REFUTED', 'INVALIDATED']

# 4. Unicorn dynamic verification of the full calculation & clamping block
uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
uc.mem_map(0x400000, 0x1100000)
uc.mem_write(0x400000, image)

stack_base = 0x200000
uc.mem_map(stack_base, 0x20000)
good_struct = stack_base + 0x5000

test_base_prices_float = [
    0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 20.0, 50.0, 100.0, 500.0, 1000.0
]

fixtures = []
for bp_float in test_base_prices_float:
    bp = int(bp_float * 32768)
    min_p, max_p = compute_price_bounds(bp)
    test_raws = [
        0, -1000, -bp,
        min_p // 2, min_p - 100, min_p - 1, min_p, min_p + 1, min_p + 100,
        (min_p + max_p) // 2,
        max_p - 100, max_p - 1, max_p, max_p + 1, max_p + 100,
        max_p * 2, max_p * 10,
        (1 << 33) + 12345, (1 << 34) + 67890
    ]
    for raw in test_raws:
        fixtures.append((bp, raw))

emulation_records = []
mismatches = 0

for bp, raw in fixtures:
    ebp = stack_base + 0x10000
    esp = ebp - 0xc0  # sub esp, 0xc0

    uc.mem_write(good_struct + 0x30, struct.pack('<Q', bp))
    uc.mem_write(ebp - 0x14, struct.pack('<I', good_struct))

    raw_low = raw & 0xffffffff
    raw_high = (raw >> 32) & 0xffffffff
    uc.mem_write(ebp - 0x20, struct.pack('<I', raw_low))

    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_EBP, ebp)
    uc.reg_write(UC_X86_REG_EDI, raw_high)

    # Load min_factor on float stack
    uc.emu_start(0x00482C46, 0x00482C4C)

    # Stop hook at boundary: 0x482cf6 (clamped) or 0x482d1e (in range)
    def stop_hook(u, addr, size, user_data):
        if addr in (0x482CF6, 0x482D1E):
            u.emu_stop()

    hook = uc.hook_add(unicorn.UC_HOOK_CODE, stop_hook)
    uc.emu_start(0x00482C81, 0x00482D20)
    uc.hook_del(hook)

    end_eip = uc.reg_read(UC_X86_REG_EIP)
    actual_low = struct.unpack('<I', uc.mem_read(ebp - 0x20, 4))[0]
    actual_high = uc.reg_read(UC_X86_REG_EDI)
    actual_price = (actual_high << 32) | actual_low
    if actual_price >= (1 << 63):
        actual_price -= (1 << 64)
    actual_clamped = (end_eip == 0x482CF6)

    expected_price, expected_clamped = clamp_price(bp, raw)

    if actual_price != expected_price or actual_clamped != expected_clamped:
        mismatches += 1
        print(f"MISMATCH for bp={bp}, raw={raw}: actual=({actual_price}, {actual_clamped}) vs expected=({expected_price}, {expected_clamped})")

    emulation_records.append({
        'base_price': bp, 'raw_price': raw,
        'actual_price': actual_price, 'actual_clamped': actual_clamped,
        'expected_price': expected_price, 'expected_clamped': expected_clamped,
        'pass': (actual_price == expected_price and actual_clamped == expected_clamped)
    })

assert mismatches == 0, f"{mismatches} mismatches encountered in price clamping emulation"

out = ROOT / 'evidence/generated/price-clamp'
out.mkdir(parents=True, exist_ok=True)
(out / 'claims.json').write_text(json.dumps(claims, indent=2) + '\n')
(out / 'reverify.json').write_text(json.dumps(report, indent=2) + '\n')
(out / 'negative-controls.json').write_text(json.dumps(controls, indent=2) + '\n')
(out / 'emulation.json').write_text(json.dumps({
    'total_fixtures': len(fixtures),
    'mismatches': mismatches,
    'records_sample': emulation_records[:20]
}, indent=2) + '\n')

ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify')
ledger.record(report, session='world-market-price-clamp')
ledger.save()

print(f"Price clamp: {len(claims)} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Price clamp emulation: {len(fixtures)} fixtures executed, 0 mismatches against price_clamp_model.")
