#!/usr/bin/env python3
"""Verify factory production and input consumption logic (0x004DD470..0x004DD5D0, 0x004F3560)."""
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
sys.path.insert(0, str(ROOT / 'src/v2re'))
from factory_production_model import compute_factory_production

data = (ROOT.parent / 'base-game/v2game.exe').read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = 0x400000

claims = []

# 1. Key instructions in CProductionType::ProduceGoods (0x004DD470..0x004DD5D0)
expected_produce_instructions = (
    (0x004DD470, 1, 'push', 'ebp'),
    (0x004DD471, 2, 'mov', 'ebp, esp'),
    (0x004DD473, 3, 'sub', 'esp, 0x1c'),
    (0x004DD476, 3, 'mov', 'ecx, dword ptr [eax + 0x24]'),
    (0x004DD479, 3, 'mov', 'edx, dword ptr [eax + 0x20]'),
    (0x004DD480, 3, 'mov', 'ecx, dword ptr [eax + 0x34]'),
    (0x004DD484, 3, 'mov', 'edx, dword ptr [eax + 0x30]'),
    (0x004DD489, 5, 'call', '0xac9f20'),
    (0x004DD490, 3, 'mov', 'eax, dword ptr [ebp + 0x14]'),
    (0x004DD495, 1, 'cdq', ''),
    (0x004DD496, 4, 'shld', 'edx, eax, 0xf'),
    (0x004DD49A, 4, 'shrd', 'ecx, esi, 0xf'),
    (0x004DD49F, 3, 'shl', 'eax, 0xf'),
    (0x004DD4A3, 3, 'sar', 'esi, 0xf'),
    (0x004DD4A8, 5, 'call', '0xac9f20'),
    (0x004DD4B7, 4, 'shrd', 'ebx, esi, 0xf'),
    (0x004DD4BF, 3, 'sar', 'esi, 0xf'),
    (0x004DD4C9, 5, 'call', '0x47dbb0'),
    (0x004DD4D9, 5, 'call', '0x47de60'),
    (0x004DD539, 5, 'call', '0xac9f20'),
    (0x004DD541, 4, 'shrd', 'eax, edx, 0xf'),
    (0x004DD54A, 3, 'sar', 'edx, 0xf'),
    (0x004DD54F, 5, 'call', '0xac9f20'),
    (0x004DD554, 4, 'shrd', 'eax, edx, 0xf'),
    (0x004DD558, 3, 'sar', 'edx, 0xf'),
    (0x004DD5AD, 5, 'call', '0x47dca0'),
    (0x004DD5C5, 5, 'call', '0x47d9e0'),
    (0x004DD5CF, 1, 'pop', 'ebp'),
)

for address, length, mnemonic, operand in expected_produce_instructions:
    claims.append({
        'id': f'factory_prod_ins_{address:x}', 'kind': 'instructions', 'space': 'rva',
        'offset': hex(address - base), 'base': hex(address), 'arch': 'x86',
        'length': length, 'mnemonics': [mnemonic], 'operands': [operand] if operand else []
    })

# 2. Key instructions in caller site in CStateBuilding::Produce (0x004F3547..0x004F356A)
expected_caller_instructions = (
    (0x004F3547, 3, 'mov', 'edx, dword ptr [esi + 0x20]'),
    (0x004F354A, 3, 'mov', 'eax, dword ptr [esi + 0x18]'),
    (0x004F354D, 6, 'mov', 'ecx, dword ptr [eax + 0x12c]'),
    (0x004F3559, 6, 'lea', 'eax, [esi + 0xe0]'),
    (0x004F3560, 5, 'call', '0x4dd470'),
    (0x004F356A, 5, 'call', '0x47dbb0'),
)

for address, length, mnemonic, operand in expected_caller_instructions:
    claims.append({
        'id': f'factory_caller_ins_{address:x}', 'kind': 'instructions', 'space': 'rva',
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
wrong = dict(claims[0], id='negative_control_factory', mnemonics=['nop'])
dependent = dict(claims[1], id='negative_dependent_factory', depends_on=['negative_control_factory'])
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

# Patch helper routines with native RET N stubs
uc.mem_write(0x0047DBB0, b'\xc2\x08\x00') # ret 8
uc.mem_write(0x0047DE60, b'\xc2\x0c\x00') # ret 12
uc.mem_write(0x0047DCA0, b'\xc2\x04\x00') # ret 4
uc.mem_write(0x0047D9E0, b'\xc2\x0c\x00') # ret 12

captured_output = None
def hook_code(uc, address, size, user_data):
    global captured_output
    if address == 0x0047DE60:
        esp = uc.reg_read(UC_X86_REG_ESP)
        lo, hi = struct.unpack('<ii', uc.mem_read(esp + 8, 8))
        captured_output = (hi << 32) | (lo & 0xFFFFFFFF)

uc.hook_add(unicorn.UC_HOOK_CODE, hook_code)

# Emulate output calculation
def emu_test_output(base_out: int, throughput: int, level: int) -> int:
    global captured_output
    captured_output = None
    esp = STACK_BASE + 0x80000
    prod_type_ptr = HEAP_BASE + 0x100
    market_pool_ptr = HEAP_BASE + 0x500
    factory_pool_ptr = HEAP_BASE + 0x1000
    
    uc.mem_write(prod_type_ptr + 0x20, struct.pack('<q', base_out))
    uc.mem_write(prod_type_ptr + 0x30, struct.pack('<q', throughput))
    
    # 0 input goods so it bypasses input loop cleanly to the end
    uc.mem_write(0x012587F4, struct.pack('<I', 0))
    
    ret_addr = 0x00401000
    uc.mem_write(esp, struct.pack('<I', ret_addr))
    uc.mem_write(esp + 4, struct.pack('<I', factory_pool_ptr))
    uc.mem_write(esp + 8, struct.pack('<I', market_pool_ptr))
    uc.mem_write(esp + 12, struct.pack('<I', 0))
    uc.mem_write(esp + 16, struct.pack('<I', level))
    uc.mem_write(esp + 20, struct.pack('<q', 32768))
    
    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_EAX, prod_type_ptr)
    
    uc.emu_start(0x004DD470, ret_addr)
    return captured_output

# Emulate input consumption
def emu_test_input(base_out: int, throughput: int, level: int, input_base: int, eff_mult: int) -> int:
    esp = STACK_BASE + 0x80000
    prod_type_ptr = HEAP_BASE + 0x100
    market_pool_ptr = HEAP_BASE + 0x500
    factory_pool_ptr = HEAP_BASE + 0x1000
    input_req_vec = HEAP_BASE + 0x2000
    factory_inv_vec = HEAP_BASE + 0x3000
    
    uc.mem_write(prod_type_ptr + 0x20, struct.pack('<q', base_out))
    uc.mem_write(prod_type_ptr + 0x30, struct.pack('<q', throughput))
    
    uc.mem_write(0x012587F4, struct.pack('<I', 1))
    uc.mem_write(factory_pool_ptr + 0x98, b'\x00')
    uc.mem_write(factory_pool_ptr + 0xD8, struct.pack('<I', input_req_vec))
    uc.mem_write(input_req_vec, struct.pack('<q', input_base))
    
    uc.mem_write(market_pool_ptr + 8, b'\x01')
    uc.mem_write(market_pool_ptr + 0x48, struct.pack('<I', factory_inv_vec))
    uc.mem_write(factory_inv_vec + 8, struct.pack('<q', 0))
    
    ret_addr = 0x00401000
    uc.mem_write(esp, struct.pack('<I', ret_addr))
    uc.mem_write(esp + 4, struct.pack('<I', factory_pool_ptr))
    uc.mem_write(esp + 8, struct.pack('<I', market_pool_ptr))
    uc.mem_write(esp + 12, struct.pack('<I', 0))
    uc.mem_write(esp + 16, struct.pack('<I', level))
    uc.mem_write(esp + 20, struct.pack('<q', eff_mult))
    
    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_EAX, prod_type_ptr)
    
    uc.emu_start(0x004DD470, 0x004DD597)
    return struct.unpack('<q', uc.mem_read(factory_inv_vec + 8, 8))[0]

# Generate fixtures
fixtures = []
for bo in [1000, 16384, 32768, 65536, 100000]:
    for tp in [16384, 32768, 40000, 65536]:
        for lvl in [1, 2, 3, 5, 10]:
            fixtures.append((bo, tp, lvl, 16384, 32768))

random.seed(12345)
for _ in range(50):
    fixtures.append((
        random.randint(1000, 200000),
        random.randint(10000, 80000),
        random.randint(1, 20),
        random.randint(1000, 50000),
        random.randint(10000, 60000),
    ))

mismatches = 0
for bo, tp, lvl, ib, ef in fixtures:
    exp_out, exp_inp = compute_factory_production(bo, tp, lvl, ib, ef)
    act_out = emu_test_output(bo, tp, lvl)
    act_inp = emu_test_input(bo, tp, lvl, ib, ef)
    
    if act_out != exp_out:
        mismatches += 1
        print(f"Output mismatch: bo={bo}, tp={tp}, lvl={lvl} -> act={act_out}, exp={exp_out}")
    if act_inp != exp_inp:
        mismatches += 1
        print(f"Input mismatch: ib={ib}, ef={ef} -> act={act_inp}, exp={exp_inp}")

assert mismatches == 0, f"{mismatches} mismatches found during factory production emulation"

# Record receipts in evidence/generated/factory-production/
out = ROOT / 'evidence/generated/factory-production'
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
ledger.record(report, session='factory-production')
ledger.save()

print(f"Factory production: {verified_count} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Factory production emulation: {len(fixtures)} fixtures executed, 0 mismatches against factory_production_model.")
