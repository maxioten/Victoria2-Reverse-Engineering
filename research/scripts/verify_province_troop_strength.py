#!/usr/bin/env python3
"""Verify CProvince::CalculateFriendlyTroopStrength and CProvince::CalculateTotalTroopStrength with Reverify and Unicorn.

Routines:
  CProvince::CalculateFriendlyTroopStrength: 0x005DC200..0x005DC297 (149 bytes, 47 instructions).
  CProvince::CalculateTotalTroopStrength: 0x005DC2A0..0x005DC322 (128 bytes, 39 instructions).
Callers:
  0x005D6442 and 0x005D644F in CArmy::CalculateSupplyLimit (0x005D63E0).
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
    UC_X86_REG_EDX, UC_X86_REG_EBX, UC_X86_REG_ESI, UC_X86_REG_EDI
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT / 'scripts'))
from province_troop_strength_model import ArmyInput, friendly_troop_strength, total_troop_strength

bin_path = ROOT.parent / 'base-game/v2game.exe'
data = bin_path.read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_32)

claims = []

# 1. CProvince::CalculateFriendlyTroopStrength instructions (0x005DC200..0x005DC297)
raw_start = pe.get_offset_from_rva(0x005DC200 - base)
for insn in md.disasm(data[raw_start:raw_start + 180], 0x005DC200):
    claims.append({
        'id': f'friendly_troop_strength_insn_{insn.address:x}',
        'kind': 'instructions',
        'space': 'rva',
        'offset': hex(insn.address - base),
        'base': hex(insn.address),
        'arch': 'x86',
        'length': len(insn.bytes),
        'mnemonics': [insn.mnemonic],
        'operands': [insn.op_str]
    })
    if insn.address >= 0x005DC294:
        break

# 2. CProvince::CalculateTotalTroopStrength instructions (0x005DC2A0..0x005DC322)
raw_total = pe.get_offset_from_rva(0x005DC2A0 - base)
for insn in md.disasm(data[raw_total:raw_total + 150], 0x005DC2A0):
    claims.append({
        'id': f'total_troop_strength_insn_{insn.address:x}',
        'kind': 'instructions',
        'space': 'rva',
        'offset': hex(insn.address - base),
        'base': hex(insn.address),
        'arch': 'x86',
        'length': len(insn.bytes),
        'mnemonics': [insn.mnemonic],
        'operands': [insn.op_str]
    })
    if insn.address >= 0x005DC31F:
        break

# 3. Call points in CArmy::CalculateSupplyLimit
call1_offset = pe.get_offset_from_rva(0x005D6442 - base)
claims.append({
    'id': 'call_friendly_troop_strength_at_0x005D6442',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x005D6442 - base),
    'base': hex(0x005D6442),
    'expected': data[call1_offset:call1_offset + 5].hex()
})

call2_offset = pe.get_offset_from_rva(0x005D644F - base)
claims.append({
    'id': 'call_total_troop_strength_at_0x005D644F',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x005D644F - base),
    'base': hex(0x005D644F),
    'expected': data[call2_offset:call2_offset + 5].hex()
})

# 4. Floating-point constants at 0x00E45840 (0.0005) and 0x00E45660 (1000.0)
c1_raw = pe.get_offset_from_rva(0x00E45840 - base)
claims.append({
    'id': 'const_double_init_0x00E45840',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E45840 - base),
    'base': hex(0x00E45840),
    'expected': data[c1_raw:c1_raw + 8].hex()
})

c2_raw = pe.get_offset_from_rva(0x00E45660 - base)
claims.append({
    'id': 'const_double_thousand_0x00E45660',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E45660 - base),
    'base': hex(0x00E45660),
    'expected': data[c2_raw:c2_raw + 8].hex()
})

# Run Reverify
verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]

# Negative controls and dependent invalidation
wrong = dict(claims[0], id='negative_control_province_troop_strength', mnemonics=['nop'])
dependent = dict(claims[1], id='negative_dependent_province_troop_strength', depends_on=['negative_control_province_troop_strength'])
controls = verifier.verify_all([Claim.from_dict(wrong), Claim.from_dict(dependent)])
assert [r['verdict'] for r in controls['results']] == ['REFUTED', 'INVALIDATED']

# Unicorn dynamic emulation
uc = Uc(UC_ARCH_X86, UC_MODE_32)
img_size = 0x01100000
uc.mem_map(base, img_size, UC_PROT_ALL)
for s in pe.sections:
    s_va = base + s.VirtualAddress
    sec_data = s.get_data()
    if sec_data:
        uc.mem_write(s_va, sec_data)

SCRATCH_BASE = 0x02000000
SCRATCH_SIZE = 0x00300000
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

STACK = SCRATCH_BASE + 0x280000
RET_STUB = SCRATCH_BASE + 0x4000
uc.mem_write(RET_STUB, b'\x90')

ARMY_VT = SCRATCH_BASE + 0x5000
ACTIVE_STUB = SCRATCH_BASE + 0x5100
# Stub: mov al, byte ptr [ecx + 0x48]; ret
uc.mem_write(ACTIVE_STUB, bytes([0x8A, 0x41, 0x48, 0xC3]))
uc.mem_write(ARMY_VT + 0x38, struct.pack('<I', ACTIVE_STUB))

OUT_ADDR = SCRATCH_BASE + 0x6000
COUNTRY_REF = SCRATCH_BASE + 0x7000
HEAD_PTR_ADDR = SCRATCH_BASE + 0x8000

POOL_NODE_ARMY = SCRATCH_BASE + 0x10000
POOL_ARMY = SCRATCH_BASE + 0x30000
POOL_NODE_REG = SCRATCH_BASE + 0x60000
POOL_REG = SCRATCH_BASE + 0xA0000

# Fixtures generator
test_fixtures = [
    # (target_country, armies)
    (1, []),
    (1, [ArmyInput(is_active=False, country_id=1, regiments=[1000, 2000])]),
    (1, [ArmyInput(is_active=True, country_id=1, regiments=[])]),
    (1, [ArmyInput(is_active=True, country_id=1, regiments=[0])]),
    (1, [ArmyInput(is_active=True, country_id=1, regiments=[1000])]),
    (1, [ArmyInput(is_active=True, country_id=1, regiments=[3000])]),
    (1, [ArmyInput(is_active=True, country_id=2, regiments=[3000])]),
    (1, [ArmyInput(is_active=True, country_id=1, regiments=[1000, 2000])]),
    (1, [
        ArmyInput(is_active=True, country_id=1, regiments=[3000]),
        ArmyInput(is_active=True, country_id=2, regiments=[5000])
    ]),
    (1, [
        ArmyInput(is_active=True, country_id=2, regiments=[5000]),
        ArmyInput(is_active=True, country_id=3, regiments=[4000])
    ]),
    (2, [
        ArmyInput(is_active=True, country_id=2, regiments=[1500, 2500]),
        ArmyInput(is_active=False, country_id=2, regiments=[3000]),
        ArmyInput(is_active=True, country_id=5, regiments=[6000])
    ]),
    (3, [
        ArmyInput(is_active=True, country_id=3, regiments=[3000] * 5),
        ArmyInput(is_active=True, country_id=3, regiments=[1000] * 10),
        ArmyInput(is_active=True, country_id=7, regiments=[2500] * 8)
    ]),
    (4, [
        ArmyInput(is_active=True, country_id=4, regiments=[500, 1000, 1500, 2000, 2500, 3000]),
        ArmyInput(is_active=True, country_id=8, regiments=[3000, 3000]),
        ArmyInput(is_active=False, country_id=4, regiments=[3000, 3000])
    ]),
    (5, [
        ArmyInput(is_active=True, country_id=5, regiments=[3000] * 20),
        ArmyInput(is_active=True, country_id=6, regiments=[3000] * 15),
        ArmyInput(is_active=True, country_id=5, regiments=[1250] * 10)
    ]),
    (10, [
        ArmyInput(is_active=True, country_id=10, regiments=[100] * 50),
        ArmyInput(is_active=True, country_id=11, regiments=[200] * 50)
    ]),
    (12, [
        ArmyInput(is_active=False, country_id=12, regiments=[1000]),
        ArmyInput(is_active=False, country_id=13, regiments=[2000]),
        ArmyInput(is_active=False, country_id=14, regiments=[3000])
    ]),
    (1, [
        ArmyInput(is_active=True, country_id=1, regiments=[1]),
        ArmyInput(is_active=True, country_id=1, regiments=[2]),
        ArmyInput(is_active=True, country_id=1, regiments=[3])
    ]),
]

total_fixtures = 0
mismatches = 0

for fix_idx, (target_c, armies) in enumerate(test_fixtures):
    # Set target country in COUNTRY_REF
    uc.mem_write(COUNTRY_REF + 4, struct.pack('<I', target_c))
    
    # Build army linked list in memory
    if not armies:
        uc.mem_write(HEAD_PTR_ADDR, struct.pack('<I', 0))
    else:
        first_army_node = POOL_NODE_ARMY + fix_idx * 0x800
        reg_cursor_node = POOL_NODE_REG + fix_idx * 0x8000
        reg_cursor_obj = POOL_REG + fix_idx * 0x8000
        for a_idx, army in enumerate(armies):
            army_addr = POOL_ARMY + (fix_idx * 20 + a_idx) * 0x100
            army_node_addr = first_army_node + a_idx * 16
            next_army_node = (first_army_node + (a_idx + 1) * 16) if (a_idx + 1 < len(armies)) else 0
            
            # Setup army object
            uc.mem_write(army_addr, struct.pack('<I', ARMY_VT))
            uc.mem_write(army_addr + 0x48, b'\x01' if army.is_active else b'\x00')
            uc.mem_write(army_addr + 0xC4, struct.pack('<I', army.country_id))
            
            # Setup regiment linked list for this army
            if not army.regiments:
                uc.mem_write(army_addr + 0x38, struct.pack('<I', 0))
            else:
                first_reg_node = reg_cursor_node
                for r_idx, reg_str in enumerate(army.regiments):
                    reg_addr = reg_cursor_obj + r_idx * 64
                    node_addr = first_reg_node + r_idx * 16
                    next_node = (first_reg_node + (r_idx + 1) * 16) if (r_idx + 1 < len(army.regiments)) else 0
                    
                    uc.mem_write(reg_addr + 0x3C, struct.pack('<I', reg_str))
                    uc.mem_write(node_addr, struct.pack('<IIQ', reg_addr, 0, next_node))
                
                reg_cursor_node += len(army.regiments) * 16
                reg_cursor_obj += len(army.regiments) * 64
                uc.mem_write(army_addr + 0x38, struct.pack('<I', first_reg_node))
            
            uc.mem_write(army_node_addr, struct.pack('<IIQ', army_addr, 0, next_army_node))
        uc.mem_write(HEAD_PTR_ADDR, struct.pack('<I', first_army_node))
    
    # 1. Test Friendly routine (0x005DC200)
    total_fixtures += 1
    uc.mem_write(OUT_ADDR, struct.pack('<I', 0xDEADBEEF))
    uc.mem_write(STACK, struct.pack('<III', RET_STUB, HEAD_PTR_ADDR, OUT_ADDR))
    uc.reg_write(UC_X86_REG_ESP, STACK)
    uc.reg_write(UC_X86_REG_EAX, COUNTRY_REF)
    uc.reg_write(UC_X86_REG_EIP, 0x005DC200)
    
    uc.emu_start(0x005DC200, RET_STUB)
    
    res_ptr = uc.reg_read(UC_X86_REG_EAX)
    val = struct.unpack('<I', uc.mem_read(OUT_ADDR, 4))[0]
    expected_friendly = friendly_troop_strength(target_c, armies)
    
    if res_ptr != OUT_ADDR or val != expected_friendly:
        mismatches += 1
        print(f'MISMATCH Friendly case {fix_idx}: got ptr={res_ptr:x}, val={val}; expected {expected_friendly}')
    
    # 2. Test Total routine (0x005DC2A0)
    total_fixtures += 1
    uc.mem_write(OUT_ADDR, struct.pack('<I', 0xDEADBEEF))
    uc.mem_write(STACK, struct.pack('<III', RET_STUB, HEAD_PTR_ADDR, OUT_ADDR))
    uc.reg_write(UC_X86_REG_ESP, STACK)
    uc.reg_write(UC_X86_REG_EIP, 0x005DC2A0)
    
    uc.emu_start(0x005DC2A0, RET_STUB)
    
    res_ptr = uc.reg_read(UC_X86_REG_EAX)
    val = struct.unpack('<I', uc.mem_read(OUT_ADDR, 4))[0]
    expected_total = total_troop_strength(armies)
    
    if res_ptr != OUT_ADDR or val != expected_total:
        mismatches += 1
        print(f'MISMATCH Total case {fix_idx}: got ptr={res_ptr:x}, val={val}; expected {expected_total}')

assert mismatches == 0, f'{mismatches} mismatches encountered in emulation!'

# Record receipts
out_dir = ROOT / 'evidence/generated/province-troop-strength'
out_dir.mkdir(parents=True, exist_ok=True)
(out_dir / 'claims.json').write_text(json.dumps(claims, indent=2) + '\n')
(out_dir / 'reverify.json').write_text(json.dumps(report, indent=2) + '\n')
(out_dir / 'negative-controls.json').write_text(json.dumps(controls, indent=2) + '\n')
(out_dir / 'emulation.json').write_text(json.dumps({
    'pass': True,
    'fixtures_tested': total_fixtures,
    'mismatches': mismatches,
    'test_cases': len(test_fixtures)
}, indent=2) + '\n')

# Record into persistent reverify ledger
ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify', file_path=str(bin_path))
ledger.start_run('Verify CProvince friendly and total troop strength aggregation routines', session='province-troop-strength')
ledger.record(report, rnd=1, session='province-troop-strength')
ledger.finish_run(1, report['grounded'], report['information'])
ledger.save()

print(f'Province troop strength: {len(report["results"])} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.')
print(f'Province troop strength emulation: {total_fixtures} fixtures executed, 0 mismatches against province_troop_strength_model.')
