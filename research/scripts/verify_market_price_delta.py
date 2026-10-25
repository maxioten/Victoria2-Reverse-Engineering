#!/usr/bin/env python3
"""Verify market price delta daily bounding (0x00BD2DC0, 0x00482B96..0x00482C40)."""
import hashlib
import json
from pathlib import Path
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
from market_price_delta_model import compute_market_price_delta

ROOT = Path(__file__).resolve().parents[1]
data = (ROOT.parent / 'base-game/v2game.exe').read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
image = pe.get_memory_mapped_image()
base = 0x400000

claims = []

# 1. Double constant: 328.17999267578125 at 0x00E458F8 (1% daily step in 32768 point fixed)
claims.append({
    'id': 'max_price_step_constant_bytes', 'kind': 'bytes_at', 'space': 'rva',
    'offset': hex(0x00E458F8 - base),
    'expected': struct.pack('<d', 328.17999267578125).hex()
})

# 2. Key instructions in MaxPriceStep Initializer (0x00BD2DC0)
expected_init_instructions = (
    (0x00BD2DC0, 6, 'fld', 'qword ptr [0xe458f8]'),
    (0x00BD2DC6, 5, 'call', '0xb31c36'),
    (0x00BD2DCB, 5, 'mov', 'dword ptr [0x125b9e0], eax'),
    (0x00BD2DD0, 6, 'mov', 'dword ptr [0x125b9e4], edx'),
    (0x00BD2DD6, 1, 'ret', ''),
)

for address, length, mnemonic, operand in expected_init_instructions:
    claims.append({
        'id': f'step_init_ins_{address:x}', 'kind': 'instructions', 'space': 'rva',
        'offset': hex(address - base), 'base': hex(address), 'arch': 'x86',
        'length': length, 'mnemonics': [mnemonic], 'operands': [operand] if operand else []
    })

# 3. Key instructions in Market Price Delta Bounding (0x00482B92..0x00482C40)
expected_delta_instructions = (
    (0x00482B92, 4, 'shrd', 'eax, edx, 0xf'),
    (0x00482BA9, 3, 'sar', 'edx, 0xf'),
    (0x00482BAE, 6, 'sub', 'edi, dword ptr [0x125b9e0]'),
    (0x00482BB7, 6, 'sbb', 'ecx, dword ptr [0x125b9e4]'),
    (0x00482BBF, 2, 'jg', '0x482bf1'),
    (0x00482BE6, 2, 'neg', 'edx'),
    (0x00482BE8, 3, 'adc', 'ecx, 0'),
    (0x00482BEB, 2, 'neg', 'ecx'),
    (0x00482BF1, 6, 'add', 'eax, dword ptr [0x125b9e0]'),
    (0x00482BFA, 6, 'adc', 'ecx, dword ptr [0x125b9e4]'),
    (0x00482C00, 2, 'cmp', 'ecx, edx'),
    (0x00482C02, 2, 'jg', '0x482c20'),
    (0x00482C41, 5, 'call', '0x47da50'),
)

for address, length, mnemonic, operand in expected_delta_instructions:
    claims.append({
        'id': f'price_delta_ins_{address:x}', 'kind': 'instructions', 'space': 'rva',
        'offset': hex(address - base), 'base': hex(address), 'arch': 'x86',
        'length': length, 'mnemonics': [mnemonic], 'operands': [operand]
    })

verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]

# Negative controls
wrong = dict(claims[0], id='negative_control', expected='1122334455667788')
dependent = dict(claims[1], id='negative_dependent', depends_on=['negative_control'])
controls = verifier.verify_all([Claim.from_dict(wrong), Claim.from_dict(dependent)])
assert [r['verdict'] for r in controls['results']] == ['REFUTED', 'INVALIDATED']

# 4. Unicorn dynamic verification of initial step conversion (0x00BD2DC0)
def verify_init_step():
    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
    uc.mem_map(0x400000, 0x1100000, unicorn.UC_PROT_ALL)
    uc.mem_write(0x400000, image)

    # Map zero page and stack
    uc.mem_map(0, 0x1000, unicorn.UC_PROT_ALL)
    stack_base = 0x200000
    uc.mem_map(stack_base, 0x10000, unicorn.UC_PROT_ALL)
    esp = stack_base + 0x8000
    uc.mem_write(esp, struct.pack('<I', 0x12345678))
    uc.reg_write(UC_X86_REG_ESP, esp)

    # Execute 0x00BD2DC0
    uc.emu_start(0x00BD2DC0, 0x12345678, timeout=1000000)

    # Read back 0x0125B9E0 (64-bit step)
    lo = struct.unpack('<I', uc.mem_read(0x0125B9E0, 4))[0]
    hi = struct.unpack('<I', uc.mem_read(0x0125B9E4, 4))[0]
    return (hi << 32) | lo

max_step_actual = verify_init_step()
assert max_step_actual == 328, f"Expected 328 max step, got {max_step_actual}"

# 5. Unicorn dynamic emulation of price delta bounding (0x00482B96..0x00482C41)
def simulate_price_delta(current_price: int, target_price: int):
    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
    uc.mem_map(0x400000, 0x1100000, unicorn.UC_PROT_ALL)
    uc.mem_write(0x400000, image)

    uc.mem_map(0, 0x1000, unicorn.UC_PROT_ALL)
    stack_base = 0x200000
    uc.mem_map(stack_base, 0x10000, unicorn.UC_PROT_ALL)
    ebp = stack_base + 0x8000
    esp = ebp - 0x70

    # Heap structures
    heap_base = 0x1600000
    uc.mem_map(heap_base, 0x10000, unicorn.UC_PROT_ALL)

    # Set up global max step = 328
    uc.mem_write(0x0125B9E0, struct.pack('<II', 328, 0))
    # Zero out delta register at 0x125BA10
    uc.mem_write(0x0125BA10, struct.pack('<II', 0, 0))

    # Market structure (ebx)
    ebx_ptr = heap_base + 0x100
    uc.reg_write(UC_X86_REG_EBX, ebx_ptr)
    price_vec = heap_base + 0x400
    uc.mem_write(ebx_ptr + 0x2C8, struct.pack('<I', price_vec))

    # Current price at price_vec[edi*8] (edi = 0)
    edi_idx = 0
    uc.mem_write(price_vec + edi_idx * 8, struct.pack('<q', current_price))

    # Set up scaled target price in eax:edx before shrd/sar 0xF
    scaled_target = target_price << 15
    t_lo = scaled_target & 0xFFFFFFFF
    t_hi = (scaled_target >> 32) & 0xFFFFFFFF
    if target_price < 0 and t_hi == 0:
        t_hi = 0xFFFFFFFF
    uc.reg_write(UC_X86_REG_EAX, t_lo)
    uc.reg_write(UC_X86_REG_EDX, t_hi)

    # Hook at 0x00482C41 (call 0x47da50)
    delta_recorded = None
    def hook_code(uc, address, size, user_data):
        nonlocal delta_recorded
        if address == 0x00482C41:
            esp_val = uc.reg_read(UC_X86_REG_ESP)
            d_lo, d_hi = struct.unpack('<ii', uc.mem_read(esp_val, 8))
            delta_recorded = (d_hi << 32) | (d_lo & 0xFFFFFFFF)
            uc.emu_stop()

    hook = uc.hook_add(unicorn.UC_HOOK_CODE, hook_code)

    uc.reg_write(UC_X86_REG_EBP, ebp)
    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_EDI, edi_idx)

    # Execute from 0x00482B8C to 0x00482C41
    uc.emu_start(0x00482B8C, 0x00482C45, timeout=2000000)

    # convert signed 64-bit delta
    if delta_recorded >= (1 << 63):
        delta_recorded -= (1 << 64)

    return delta_recorded

# Test battery
test_fixtures = [
    # (current, target)
    (32768, 32768),        # exact match -> delta = 0
    (32768, 32768 + 100),  # within +328 -> delta = +100
    (32768, 32768 - 100),  # within -328 -> delta = -100
    (32768, 32768 + 328),  # exact upper limit -> delta = +328
    (32768, 32768 - 328),  # exact lower limit -> delta = -328
    (32768, 32768 + 500),  # exceeds upper limit -> delta = +328
    (32768, 32768 - 500),  # exceeds lower limit -> delta = -328
    (32768, 32768 + 10000),# large surge -> delta = +328
    (32768, 32768 - 10000),# large crash -> delta = -328
    (65536, 65536 + 200),
    (65536, 65536 - 200),
    (65536, 100000),
    (65536, 10000),
    (10000, 10000 + 50),
    (10000, 10000 - 50),
]

for cur in (10000, 32768, 65536, 100000):
    for offset in (-1000, -500, -329, -328, -200, -1, 0, 1, 200, 328, 329, 500, 1000):
        test_fixtures.append((cur, cur + offset))

fixture_count = 0
for cur_price, tgt_price in test_fixtures:
    expected_delta, expected_new = compute_market_price_delta(cur_price, tgt_price, max_step=328)
    actual_delta = simulate_price_delta(cur_price, tgt_price)

    assert actual_delta == expected_delta, (
        f"Delta mismatch for cur={cur_price}, tgt={tgt_price}: actual={actual_delta} vs expected={expected_delta}"
    )
    fixture_count += 1

out = ROOT / 'evidence/generated/market-price-delta'
out.mkdir(parents=True, exist_ok=True)
(out / 'claims.json').write_text(json.dumps(claims, indent=2) + '\n')
(out / 'reverify.json').write_text(json.dumps(report, indent=2) + '\n')
(out / 'negative-controls.json').write_text(json.dumps(controls, indent=2) + '\n')
(out / 'emulation.json').write_text(json.dumps({
    'max_step_verified': max_step_actual,
    'total_fixtures': fixture_count,
    'mismatches': 0,
}, indent=2) + '\n')

ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify')
ledger.record(report, session='market-price-delta')
ledger.save()

print(f"Market price delta: {len(claims)} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Market price delta emulation: {fixture_count} fixtures executed, 0 mismatches against market_price_delta_model.")
