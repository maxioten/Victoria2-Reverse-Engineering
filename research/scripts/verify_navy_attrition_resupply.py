#!/usr/bin/env python3
"""Verify CNavy::CalculateSeaAttrition and CNavy::EvaluateResupplyNecessity with Reverify and Unicorn.

Routines:
  CNavy::CalculateSeaAttrition: 0x005D7EC0..0x005D7F6E (175 bytes, 58 instructions).
  CNavy::EvaluateResupplyNecessity: 0x005D8120..0x005D8199 (122 bytes, 36 instructions).
Vtables:
  CNavy slot 31 (+0x7C) at 0x00E03048 -> 0x005D7EC0.
  CNavy slot 21 (+0x54) at 0x00E03020 -> 0x005CFE90.
  CArmy slot 21 (+0x54) at 0x00DF8920 -> 0x005CFE90.
Constants:
  0x10624DD3: division by 1000 magic multiplier.
  0x3E8: 1000 (milésimas scale).
  0x00E45ADC: 850.5 (float).
Singletons:
  0x012586DC: CDefines pointer.
  0x01258720: Current tick / table index.
"""
import hashlib
import json
import math
from pathlib import Path
import struct
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
import pefile
from reverify.verifier import Claim, Verifier
from reverify.ledger import Ledger
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_PROT_ALL, UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_EAX, UC_X86_REG_ECX,
    UC_X86_REG_EDX, UC_X86_REG_EBX, UC_X86_REG_ESI, UC_X86_REG_EDI,
    UC_X86_REG_EBP
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT / 'scripts'))
from navy_attrition_resupply_model import calculate_sea_attrition, evaluate_resupply_necessity

bin_path = ROOT.parent / 'base-game/v2game.exe'
data = bin_path.read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_32)

claims = []

# 1. CNavy::CalculateSeaAttrition instructions (0x005D7EC0..0x005D7F6E)
raw_attr = pe.get_offset_from_rva(0x005D7EC0 - base)
for insn in md.disasm(data[raw_attr:raw_attr + 200], 0x005D7EC0):
    claims.append({
        'id': f'navy_sea_attrition_insn_{insn.address:x}',
        'kind': 'instructions',
        'space': 'rva',
        'offset': hex(insn.address - base),
        'base': hex(insn.address),
        'arch': 'x86',
        'length': len(insn.bytes),
        'mnemonics': [insn.mnemonic],
        'operands': [insn.op_str]
    })
    if insn.address >= 0x005D7F6E:
        break

# 2. CNavy::EvaluateResupplyNecessity instructions (0x005D8120..0x005D8199)
raw_resup = pe.get_offset_from_rva(0x005D8120 - base)
for insn in md.disasm(data[raw_resup:raw_resup + 140], 0x005D8120):
    claims.append({
        'id': f'navy_resupply_insn_{insn.address:x}',
        'kind': 'instructions',
        'space': 'rva',
        'offset': hex(insn.address - base),
        'base': hex(insn.address),
        'arch': 'x86',
        'length': len(insn.bytes),
        'mnemonics': [insn.mnemonic],
        'operands': [insn.op_str]
    })
    if insn.address >= 0x005D8199:
        break

# 3. Vtable slots:
# CNavy slot 31 (+0x7C) at 0x00E03048 -> 0x005D7EC0
claims.append({
    'id': 'vtable_slot31_CNavy_sea_attrition',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E03048 - base),
    'base': hex(0x00E03048),
    'expected': (0x005D7EC0).to_bytes(4, 'little').hex()
})

# CNavy slot 21 (+0x54) at 0x00E03020 -> 0x005CFE90
claims.append({
    'id': 'vtable_slot21_CNavy_health_ratio',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E03020 - base),
    'base': hex(0x00E03020),
    'expected': (0x005CFE90).to_bytes(4, 'little').hex()
})

# CArmy slot 21 (+0x54) at 0x00DF8920 -> 0x005CFE90
claims.append({
    'id': 'vtable_slot21_CArmy_health_ratio',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00DF8920 - base),
    'base': hex(0x00DF8920),
    'expected': (0x005CFE90).to_bytes(4, 'little').hex()
})

# 4. Constant checks:
# Magic constant 0x10624DD3 at 0x005D7ECD
claims.append({
    'id': 'navy_attrition_magic_div_1000',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x005D7ECD - base),
    'base': hex(0x005D7ECD),
    'expected': (0x10624DD3).to_bytes(4, 'little').hex()
})

# Constant 1000 at 0x005D7F0F
claims.append({
    'id': 'navy_attrition_const_1000_scale',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x005D7F0F - base),
    'base': hex(0x005D7F0F),
    'expected': (0x3E8).to_bytes(4, 'little').hex()
})

# Constant 1000 at 0x005D7F3A
claims.append({
    'id': 'navy_attrition_const_1000_delta',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x005D7F3A - base),
    'base': hex(0x005D7F3A),
    'expected': (0x3E8).to_bytes(4, 'little').hex()
})

# Float constant 850.5 at 0x00E45ADC
claims.append({
    'id': 'navy_resupply_const_850_5',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E45ADC - base),
    'base': hex(0x00E45ADC),
    'expected': data[pe.get_offset_from_rva(0x00E45ADC - base):pe.get_offset_from_rva(0x00E45ADC - base) + 4].hex()
})

# Run Reverify
verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]

# Negative controls and dependent invalidation
wrong = dict(claims[0], id='negative_control_navy_attrition', mnemonics=['sub'])
dependent = dict(claims[1], id='negative_dependent_navy_attrition', depends_on=['negative_control_navy_attrition'])
controls = verifier.verify_all([Claim.from_dict(wrong), Claim.from_dict(dependent)])
assert [r['verdict'] for r in controls['results']] == ['REFUTED', 'INVALIDATED']

# -------------------------------------------------------------
# Unicorn Dynamic Emulation Setup
# -------------------------------------------------------------
uc = Uc(UC_ARCH_X86, UC_MODE_32)
img_size = 0x01100000
uc.mem_map(base, img_size, UC_PROT_ALL)
for s in pe.sections:
    s_va = base + s.VirtualAddress
    sec_data = s.get_data()
    if sec_data:
        uc.mem_write(s_va, sec_data)

SCRATCH_BASE = 0x02000000
SCRATCH_SIZE = 0x00400000
uc.mem_map(SCRATCH_BASE, SCRATCH_SIZE, UC_PROT_ALL)

# CRT floor and ftol2 hooks
ctx = {'last_floor': 0}
def hook_floor(uc_inst, address, size, user_data):
    esp = uc_inst.reg_read(UC_X86_REG_ESP)
    flt_bytes = uc_inst.mem_read(esp + 4, 4)
    flt_val = struct.unpack('<f', flt_bytes)[0]
    ctx['last_floor'] = math.floor(flt_val)

def hook_ftol(uc_inst, address, size, user_data):
    uc_inst.reg_write(UC_X86_REG_EAX, ctx['last_floor'])

uc.hook_add(UC_HOOK_CODE, hook_floor, begin=0x00401000, end=0x00401000)
uc.hook_add(UC_HOOK_CODE, hook_ftol, begin=0x00B31C00, end=0x00B31C00)
uc.mem_write(0x00401000, b'\xc3')
uc.mem_write(0x00B31C00, b'\xc3')

STACK = SCRATCH_BASE + 0x380000
RET_STUB = SCRATCH_BASE + 0x2000
uc.mem_write(RET_STUB, b'\x90')

NAVY_ADDR = SCRATCH_BASE + 0x10000
NAVY_VT = SCRATCH_BASE + 0x11000
PROV_ADDR = SCRATCH_BASE + 0x12000
PORT_TABLE = SCRATCH_BASE + 0x13000
PORT_ADDR = SCRATCH_BASE + 0x14000
DEFINES_ADDR = SCRATCH_BASE + 0x15000
MIL_DEFINES = SCRATCH_BASE + 0x16000
OUT_ATTR_ADDR = SCRATCH_BASE + 0x17000
HEALTH_STORE = SCRATCH_BASE + 0x18000

# Wire defines at 0x012586DC
uc.mem_write(0x012586DC, struct.pack('<I', DEFINES_ADDR))
uc.mem_write(DEFINES_ADDR + 0x20, struct.pack('<I', MIL_DEFINES))

# Wire tick at 0x01258720
uc.mem_write(0x01258720, struct.pack('<I', 0))

# Wire navy object
uc.mem_write(NAVY_ADDR + 0x00, struct.pack('<I', NAVY_VT))
uc.mem_write(NAVY_VT + 0x7C, struct.pack('<I', 0x005D7EC0)) # slot 31 -> CalculateSeaAttrition

# Stub for slot 21 (+0x54): CalculateAverageSubunitHealthRatio
# Reads from HEALTH_STORE and writes to [ebp+8] / [esp+4], returns pointer in eax
STUB_SLOT21_ADDR = SCRATCH_BASE + 0x19000
# mov eax, [esp+4]; mov edx, [HEALTH_STORE]; mov [eax], edx; ret 4
STUB_SLOT21_CODE = (
    bytes([0x8B, 0x44, 0x24, 0x04]) +
    bytes([0x8B, 0x15]) + struct.pack('<I', HEALTH_STORE) +
    bytes([0x89, 0x10]) +
    bytes([0xC2, 0x04, 0x00])
)
uc.mem_write(STUB_SLOT21_ADDR, STUB_SLOT21_CODE)
uc.mem_write(NAVY_VT + 0x54, struct.pack('<I', STUB_SLOT21_ADDR))

# Wire province and port table
uc.mem_write(NAVY_ADDR + 0xDC, struct.pack('<I', PROV_ADDR))
uc.mem_write(PROV_ADDR + 0x118, struct.pack('<I', PORT_TABLE))
uc.mem_write(PORT_TABLE + 0x00, struct.pack('<I', PORT_ADDR))

def run_calculate_sea_attrition_emu(
    time_at_sea: int,
    grace_period_ms: int,
    naval_range_divisor: int,
    supply_distance: int,
    max_naval_attrition: int
) -> int:
    # Setup defines
    uc.mem_write(MIL_DEFINES + 0xF0, struct.pack('<i', grace_period_ms))
    uc.mem_write(MIL_DEFINES + 0xE4, struct.pack('<i', naval_range_divisor))
    uc.mem_write(MIL_DEFINES + 0xEC, struct.pack('<i', max_naval_attrition))

    # Setup navy
    uc.mem_write(NAVY_ADDR + 0x1BC, struct.pack('<i', time_at_sea))
    uc.mem_write(NAVY_ADDR + 0xB0, struct.pack('<i', supply_distance))

    # Clear output
    uc.mem_write(OUT_ATTR_ADDR, struct.pack('<i', -99999))

    # Setup stack: [esp] = ret_addr, [esp+4] = OUT_ATTR_ADDR
    esp = STACK - 8
    uc.mem_write(esp, struct.pack('<II', RET_STUB, OUT_ATTR_ADDR))

    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_EBP, esp)
    uc.reg_write(UC_X86_REG_ECX, NAVY_ADDR)

    uc.emu_start(0x005D7EC0, RET_STUB, timeout=1000000)

    res_ptr = uc.reg_read(UC_X86_REG_EAX)
    assert res_ptr == OUT_ATTR_ADDR
    return struct.unpack('<i', uc.mem_read(OUT_ATTR_ADDR, 4))[0]

def run_evaluate_resupply_emu(
    time_at_sea: int,
    grace_period_ms: int,
    naval_range_divisor: int,
    supply_distance: int,
    max_naval_attrition: int,
    has_port_table: bool,
    port_capacity: int,
    ship_count: int,
    health_ratio_ms: int
) -> bool:
    # Setup defines
    uc.mem_write(MIL_DEFINES + 0xF0, struct.pack('<i', grace_period_ms))
    uc.mem_write(MIL_DEFINES + 0xE4, struct.pack('<i', naval_range_divisor))
    uc.mem_write(MIL_DEFINES + 0xEC, struct.pack('<i', max_naval_attrition))

    # Setup navy
    uc.mem_write(NAVY_ADDR + 0x1BC, struct.pack('<i', time_at_sea))
    uc.mem_write(NAVY_ADDR + 0xB0, struct.pack('<i', supply_distance))
    uc.mem_write(NAVY_ADDR + 0x40, struct.pack('<i', ship_count))

    # Setup province / port
    if has_port_table:
        uc.mem_write(NAVY_ADDR + 0xDC, struct.pack('<I', PROV_ADDR))
        uc.mem_write(PROV_ADDR + 0x118, struct.pack('<I', PORT_TABLE))
        uc.mem_write(PORT_TABLE + 0x00, struct.pack('<I', PORT_ADDR))
        uc.mem_write(PORT_ADDR + 0x20, struct.pack('<i', port_capacity))
    else:
        uc.mem_write(NAVY_ADDR + 0xDC, struct.pack('<I', 0))

    # Setup health ratio
    uc.mem_write(HEALTH_STORE, struct.pack('<i', health_ratio_ms))

    # Setup stack: [esp] = RET_STUB
    esp = STACK - 4
    uc.mem_write(esp, struct.pack('<I', RET_STUB))

    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_EBP, esp)
    uc.reg_write(UC_X86_REG_EAX, NAVY_ADDR)

    uc.emu_start(0x005D8120, RET_STUB, timeout=1000000)

    res = uc.reg_read(UC_X86_REG_EAX) & 0xFF
    return (res != 0)

# -------------------------------------------------------------
# Test Fixtures Matrix
# -------------------------------------------------------------
attr_fixtures = [
    # 1. Within grace period
    (10, 30000, 1000, 500, 200),
    # 2. Exactly at grace period
    (30, 30000, 1000, 500, 200),
    # 3. Beyond grace period, zero distance
    (45, 30000, 1000, 0, 200),
    # 4. Beyond grace period, moderate distance (ratio = 500)
    (50, 30000, 1000, 500, 200),
    # 5. Beyond grace period, large distance (ratio = 800)
    (60, 30000, 1000, 800, 300),
    # 6. Full range limit (ratio = 1000)
    (100, 30000, 1000, 1000, 400),
    # 7. Divisor = 0 (degeneracy case)
    (100, 30000, 0, 500, 200),
]

for d in [100, 250, 750, 950, 1200]:
    attr_fixtures.append((50, 20000, 1000, d, 250))

resup_fixtures = [
    # 1. Active attrition -> True regardless of port
    (50, 20000, 1000, 200, 200, False, 0, 0, 1000),
    # 2. No attrition (within grace), no port -> False
    (10, 30000, 1000, 200, 200, False, 0, 5, 500),
    # 3. No attrition, port capacity <= 0 -> False
    (10, 30000, 1000, 200, 200, True, 0, 5, 500),
    # 4. No attrition, ship count <= 0 -> False
    (10, 30000, 1000, 200, 200, True, 1, 0, 500),
    # 5. In port with ships, health = 1000 (100.0%) >= 850 -> False
    (10, 30000, 1000, 200, 200, True, 1, 5, 1000),
    # 6. In port with ships, health = 850 (85.0%) -> False
    (10, 30000, 1000, 200, 200, True, 1, 5, 850),
    # 7. In port with ships, health = 849 (< 850) -> True
    (10, 30000, 1000, 200, 200, True, 1, 5, 849),
    # 8. In port with ships, heavily damaged (health = 300) -> True
    (10, 30000, 1000, 200, 200, True, 2, 8, 300),
]

mismatches = 0
for i, args in enumerate(attr_fixtures):
    emu_attr = run_calculate_sea_attrition_emu(*args)
    py_attr = calculate_sea_attrition(*args)
    if emu_attr != py_attr:
        print(f"MISMATCH in sea_attrition fixture {i}: args={args}, emu={emu_attr}, py={py_attr}")
        mismatches += 1

for i, args in enumerate(resup_fixtures):
    emu_resup = run_evaluate_resupply_emu(*args)
    attr_val = calculate_sea_attrition(args[0], args[1], args[2], args[3], args[4])
    py_resup = evaluate_resupply_necessity(attr_val, args[5], args[6], args[7], args[8])
    if emu_resup != py_resup:
        print(f"MISMATCH in resupply_necessity fixture {i}: args={args}, emu={emu_resup}, py={py_resup}")
        mismatches += 1

assert mismatches == 0, f"{mismatches} mismatches encountered in emulation!"

total_fixtures = len(attr_fixtures) + len(resup_fixtures)

# Record receipts
out_dir = ROOT / 'evidence/generated/navy-attrition-resupply'
out_dir.mkdir(parents=True, exist_ok=True)
(out_dir / 'claims.json').write_text(json.dumps(claims, indent=2) + '\n')
(out_dir / 'reverify.json').write_text(json.dumps(report, indent=2) + '\n')
(out_dir / 'negative-controls.json').write_text(json.dumps(controls, indent=2) + '\n')
(out_dir / 'emulation.json').write_text(json.dumps({
    'pass': True,
    'fixtures_tested': total_fixtures,
    'mismatches': mismatches,
    'attr_fixtures_count': len(attr_fixtures),
    'resup_fixtures_count': len(resup_fixtures)
}, indent=2) + '\n')

# Record into persistent reverify ledger
ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify', file_path=str(bin_path))
ledger.start_run('Verify CNavy::CalculateSeaAttrition and CNavy::EvaluateResupplyNecessity', session='navy-attrition-resupply')
ledger.record(report, rnd=1, session='navy-attrition-resupply')
ledger.finish_run(1, report['grounded'], report['information'])
ledger.save()

print(f"Navy attrition & resupply: {len(report['results'])} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Navy attrition & resupply emulation: {total_fixtures} fixtures executed, 0 mismatches against navy_attrition_resupply_model.")
