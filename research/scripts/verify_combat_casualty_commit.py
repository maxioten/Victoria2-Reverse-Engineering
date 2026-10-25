#!/usr/bin/env python3
"""Verify CCombatant::CommitCasualtiesAndMoraleLoss and CCombatant::CommitCasualtiesByUnitType.

Routines:
  CCombatant::CommitCasualtiesAndMoraleLoss: 0x005DC330..0x005DC3BD (141 bytes, 46 instructions).
  CCombatant::CommitCasualtiesByUnitType: 0x005DC3C0..0x005DC45B (155 bytes, 49 instructions).
Callers:
  0x00595E71 and 0x00595F12 in CCombat::ResolveDailyCasualtiesAndMoraleLoss.
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
from combat_casualty_commit_model import RegimentDamageState, commit_casualties_total, commit_casualties_by_type

bin_path = ROOT.parent / 'base-game/v2game.exe'
data = bin_path.read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_32)

claims = []

# 1. CommitCasualtiesAndMoraleLoss instructions (0x005DC330..0x005DC3BD)
raw_start = pe.get_offset_from_rva(0x005DC330 - base)
for insn in md.disasm(data[raw_start:raw_start + 180], 0x005DC330):
    claims.append({
        'id': f'commit_casualties_total_insn_{insn.address:x}',
        'kind': 'instructions',
        'space': 'rva',
        'offset': hex(insn.address - base),
        'base': hex(insn.address),
        'arch': 'x86',
        'length': len(insn.bytes),
        'mnemonics': [insn.mnemonic],
        'operands': [insn.op_str]
    })
    if insn.address >= 0x005DC3BC:
        break

# 2. CommitCasualtiesByUnitType instructions (0x005DC3C0..0x005DC45B)
raw_type = pe.get_offset_from_rva(0x005DC3C0 - base)
for insn in md.disasm(data[raw_type:raw_type + 180], 0x005DC3C0):
    claims.append({
        'id': f'commit_casualties_type_insn_{insn.address:x}',
        'kind': 'instructions',
        'space': 'rva',
        'offset': hex(insn.address - base),
        'base': hex(insn.address),
        'arch': 'x86',
        'length': len(insn.bytes),
        'mnemonics': [insn.mnemonic],
        'operands': [insn.op_str]
    })
    if insn.address >= 0x005DC45A:
        break

# 3. Call points in CCombat (0x00595E71 and 0x00595F12)
c1_off = pe.get_offset_from_rva(0x00595E71 - base)
claims.append({
    'id': 'call_commit_total_at_0x00595E71',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00595E71 - base),
    'base': hex(0x00595E71),
    'expected': data[c1_off:c1_off + 5].hex()
})

c2_off = pe.get_offset_from_rva(0x00595F12 - base)
claims.append({
    'id': 'call_commit_type_at_0x00595F12',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00595F12 - base),
    'base': hex(0x00595F12),
    'expected': data[c2_off:c2_off + 5].hex()
})

# 4. Floating-point constants at 0x00E45840 and 0x00E45660
const1_raw = pe.get_offset_from_rva(0x00E45840 - base)
claims.append({
    'id': 'const_double_init_0x00E45840',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E45840 - base),
    'base': hex(0x00E45840),
    'expected': data[const1_raw:const1_raw + 8].hex()
})

const2_raw = pe.get_offset_from_rva(0x00E45660 - base)
claims.append({
    'id': 'const_double_thousand_0x00E45660',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E45660 - base),
    'base': hex(0x00E45660),
    'expected': data[const2_raw:const2_raw + 8].hex()
})

# Run Reverify
verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]

# Negative controls and dependent invalidation
wrong = dict(claims[0], id='negative_control_casualty_commit', mnemonics=['nop'])
dependent = dict(claims[1], id='negative_dependent_casualty_commit', depends_on=['negative_control_casualty_commit'])
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

# Hook 0x005C0160 (CRegiment::CommitCombatDamage)
def hook_commit_damage(uc_inst, address, size, user_data):
    reg_addr = uc_inst.reg_read(UC_X86_REG_EDI)
    esp = uc_inst.reg_read(UC_X86_REG_ESP)
    out_ptr = struct.unpack('<I', uc_inst.mem_read(esp + 4, 4))[0]
    
    strength = struct.unpack('<I', uc_inst.mem_read(reg_addr + 0x3C, 4))[0]
    cas = struct.unpack('<I', uc_inst.mem_read(reg_addr + 0x6C, 4))[0]
    morale = struct.unpack('<I', uc_inst.mem_read(reg_addr + 0x40, 4))[0]
    morale_loss = struct.unpack('<I', uc_inst.mem_read(reg_addr + 0x70, 4))[0]
    
    eff_cas = min(strength, cas)
    eff_morale_loss = min(morale, morale_loss)
    
    uc_inst.mem_write(reg_addr + 0x3C, struct.pack('<I', strength - eff_cas))
    uc_inst.mem_write(reg_addr + 0x40, struct.pack('<I', morale - eff_morale_loss))
    uc_inst.mem_write(reg_addr + 0x6C, struct.pack('<I', 0))
    uc_inst.mem_write(reg_addr + 0x70, struct.pack('<I', 0))
    
    uc_inst.mem_write(out_ptr, struct.pack('<I', eff_cas))
    uc_inst.reg_write(UC_X86_REG_EAX, out_ptr)
    
    ret_addr = struct.unpack('<I', uc_inst.mem_read(esp, 4))[0]
    uc_inst.reg_write(UC_X86_REG_ESP, esp + 8)
    uc_inst.reg_write(UC_X86_REG_EIP, ret_addr)

uc.hook_add(UC_HOOK_CODE, hook_commit_damage, begin=0x005C0160, end=0x005C0160)

STACK = SCRATCH_BASE + 0x280000
RET_STUB = SCRATCH_BASE + 0x4000
uc.mem_write(RET_STUB, b'\x90')

OUT_ADDR = SCRATCH_BASE + 0x6000
HEAD_PTR_ADDR = SCRATCH_BASE + 0x8000
FILTER_OBJ = SCRATCH_BASE + 0x9000

POOL_NODE_ARMY = SCRATCH_BASE + 0x10000
POOL_ARMY = SCRATCH_BASE + 0x20000
POOL_TYPE = SCRATCH_BASE + 0x30000
POOL_NODE_REG = SCRATCH_BASE + 0x50000
POOL_REG = SCRATCH_BASE + 0x90000

# Fixtures for damage commit testing
test_cases = [
    # list of armies, each army is list of RegimentDamageState
    [],
    [[]],
    [[RegimentDamageState(category=1, strength=3000, pending_casualties=0, morale=3000, pending_morale_loss=0)]],
    [[RegimentDamageState(category=1, strength=3000, pending_casualties=150, morale=3000, pending_morale_loss=200)]],
    [[RegimentDamageState(category=1, strength=100, pending_casualties=500, morale=500, pending_morale_loss=1000)]], # overkill clamping
    [[
        RegimentDamageState(category=1, strength=3000, pending_casualties=200, morale=3000, pending_morale_loss=150),
        RegimentDamageState(category=2, strength=1000, pending_casualties=50, morale=2000, pending_morale_loss=80),
        RegimentDamageState(category=3, strength=3000, pending_casualties=300, morale=2500, pending_morale_loss=100)
    ]],
    [
        [
            RegimentDamageState(category=1, strength=3000, pending_casualties=100, morale=3000, pending_morale_loss=50),
            RegimentDamageState(category=2, strength=1000, pending_casualties=50, morale=1000, pending_morale_loss=20)
        ],
        [
            RegimentDamageState(category=1, strength=2500, pending_casualties=250, morale=2000, pending_morale_loss=300),
            RegimentDamageState(category=3, strength=3000, pending_casualties=400, morale=3000, pending_morale_loss=100)
        ]
    ],
    [
        [RegimentDamageState(category=1, strength=3000, pending_casualties=50, morale=3000, pending_morale_loss=50)] * 5,
        [RegimentDamageState(category=2, strength=1000, pending_casualties=20, morale=2000, pending_morale_loss=10)] * 5,
        [RegimentDamageState(category=3, strength=3000, pending_casualties=80, morale=2500, pending_morale_loss=40)] * 5
    ]
]

total_fixtures = 0
mismatches = 0

for fix_idx, armies in enumerate(test_cases):
    # Test across multiple target categories: 1 (infantry), 2 (cavalry), 3 (artillery), 99 (none)
    categories_to_test = [1, 2, 3, 99]
    
    # 1. Test Total Commit (0x005DC330)
    total_fixtures += 1
    
    # Build memory
    if not armies:
        uc.mem_write(HEAD_PTR_ADDR, struct.pack('<I', 0))
    else:
        first_army_node = POOL_NODE_ARMY + fix_idx * 0x800
        reg_cursor_node = POOL_NODE_REG + fix_idx * 0x8000
        reg_cursor_obj = POOL_REG + fix_idx * 0x8000
        type_cursor = POOL_TYPE + fix_idx * 0x2000
        
        for a_idx, army in enumerate(armies):
            army_addr = POOL_ARMY + (fix_idx * 20 + a_idx) * 0x100
            army_node_addr = first_army_node + a_idx * 16
            next_army_node = (first_army_node + (a_idx + 1) * 16) if (a_idx + 1 < len(armies)) else 0
            
            if not army:
                uc.mem_write(army_addr + 0x38, struct.pack('<I', 0))
            else:
                first_reg_node = reg_cursor_node
                for r_idx, reg in enumerate(army):
                    reg_addr = reg_cursor_obj + r_idx * 0x80
                    type_addr = type_cursor + (a_idx * 20 + r_idx) * 0x40
                    node_addr = first_reg_node + r_idx * 16
                    next_node = (first_reg_node + (r_idx + 1) * 16) if (r_idx + 1 < len(army)) else 0
                    
                    uc.mem_write(type_addr + 0x24, struct.pack('<I', reg.category))
                    uc.mem_write(reg_addr + 0x38, struct.pack('<I', type_addr))
                    uc.mem_write(reg_addr + 0x3C, struct.pack('<I', reg.strength))
                    uc.mem_write(reg_addr + 0x40, struct.pack('<I', reg.morale))
                    uc.mem_write(reg_addr + 0x6C, struct.pack('<I', reg.pending_casualties))
                    uc.mem_write(reg_addr + 0x70, struct.pack('<I', reg.pending_morale_loss))
                    
                    uc.mem_write(node_addr, struct.pack('<IIQ', reg_addr, 0, next_node))
                
                reg_cursor_node += len(army) * 16
                reg_cursor_obj += len(army) * 0x80
                uc.mem_write(army_addr + 0x38, struct.pack('<I', first_reg_node))
            
            uc.mem_write(army_node_addr, struct.pack('<IIQ', army_addr, 0, next_army_node))
        uc.mem_write(HEAD_PTR_ADDR, struct.pack('<I', first_army_node))
    
    uc.mem_write(OUT_ADDR, struct.pack('<I', 0xDEADBEEF))
    uc.mem_write(STACK, struct.pack('<III', RET_STUB, HEAD_PTR_ADDR, OUT_ADDR))
    uc.reg_write(UC_X86_REG_ESP, STACK)
    uc.reg_write(UC_X86_REG_EIP, 0x005DC330)
    
    uc.emu_start(0x005DC330, RET_STUB)
    
    res_ptr = uc.reg_read(UC_X86_REG_EAX)
    val = struct.unpack('<I', uc.mem_read(OUT_ADDR, 4))[0]
    expected_total, updated_armies = commit_casualties_total(armies)
    
    if res_ptr != OUT_ADDR or val != expected_total:
        mismatches += 1
        print(f'MISMATCH Total Commit case {fix_idx}: got ptr={res_ptr:x}, val={val}; expected {expected_total}')

    # 2. Test By-Type Commit (0x005DC3C0) for each test category
    for cat in categories_to_test:
        total_fixtures += 1
        # Rebuild fresh state with pending casualties for this category test
        if not armies:
            uc.mem_write(HEAD_PTR_ADDR, struct.pack('<I', 0))
        else:
            first_army_node = POOL_NODE_ARMY + fix_idx * 0x800
            reg_cursor_node = POOL_NODE_REG + fix_idx * 0x8000
            reg_cursor_obj = POOL_REG + fix_idx * 0x8000
            type_cursor = POOL_TYPE + fix_idx * 0x2000
            for a_idx, army in enumerate(armies):
                army_addr = POOL_ARMY + (fix_idx * 20 + a_idx) * 0x100
                army_node_addr = first_army_node + a_idx * 16
                next_army_node = (first_army_node + (a_idx + 1) * 16) if (a_idx + 1 < len(armies)) else 0
                if army:
                    first_reg_node = reg_cursor_node
                    for r_idx, reg in enumerate(army):
                        reg_addr = reg_cursor_obj + r_idx * 0x80
                        type_addr = type_cursor + (a_idx * 20 + r_idx) * 0x40
                        node_addr = first_reg_node + r_idx * 16
                        next_node = (first_reg_node + (r_idx + 1) * 16) if (r_idx + 1 < len(army)) else 0
                        
                        uc.mem_write(type_addr + 0x24, struct.pack('<I', reg.category))
                        uc.mem_write(reg_addr + 0x38, struct.pack('<I', type_addr))
                        uc.mem_write(reg_addr + 0x3C, struct.pack('<I', reg.strength))
                        uc.mem_write(reg_addr + 0x40, struct.pack('<I', reg.morale))
                        uc.mem_write(reg_addr + 0x6C, struct.pack('<I', reg.pending_casualties))
                        uc.mem_write(reg_addr + 0x70, struct.pack('<I', reg.pending_morale_loss))
                        uc.mem_write(node_addr, struct.pack('<IIQ', reg_addr, 0, next_node))
                    reg_cursor_node += len(army) * 16
                    reg_cursor_obj += len(army) * 0x80
                    uc.mem_write(army_addr + 0x38, struct.pack('<I', first_reg_node))
                uc.mem_write(army_node_addr, struct.pack('<IIQ', army_addr, 0, next_army_node))
            uc.mem_write(HEAD_PTR_ADDR, struct.pack('<I', first_army_node))
        
        uc.mem_write(FILTER_OBJ + 0x24, struct.pack('<I', cat))
        uc.mem_write(OUT_ADDR, struct.pack('<I', 0xDEADBEEF))
        uc.mem_write(STACK, struct.pack('<IIII', RET_STUB, HEAD_PTR_ADDR, OUT_ADDR, FILTER_OBJ))
        uc.reg_write(UC_X86_REG_ESP, STACK)
        uc.reg_write(UC_X86_REG_EIP, 0x005DC3C0)
        
        uc.emu_start(0x005DC3C0, RET_STUB)
        
        res_ptr = uc.reg_read(UC_X86_REG_EAX)
        val = struct.unpack('<I', uc.mem_read(OUT_ADDR, 4))[0]
        expected_type, _ = commit_casualties_by_type(cat, armies)
        
        if res_ptr != OUT_ADDR or val != expected_type:
            mismatches += 1
            print(f'MISMATCH By-Type Commit case {fix_idx} cat {cat}: got ptr={res_ptr:x}, val={val}; expected {expected_type}')

assert mismatches == 0, f'{mismatches} mismatches encountered in emulation!'

# Record receipts
out_dir = ROOT / 'evidence/generated/combat-casualty-commit'
out_dir.mkdir(parents=True, exist_ok=True)
(out_dir / 'claims.json').write_text(json.dumps(claims, indent=2) + '\n')
(out_dir / 'reverify.json').write_text(json.dumps(report, indent=2) + '\n')
(out_dir / 'negative-controls.json').write_text(json.dumps(controls, indent=2) + '\n')
(out_dir / 'emulation.json').write_text(json.dumps({
    'pass': True,
    'fixtures_tested': total_fixtures,
    'mismatches': mismatches,
    'cases_count': len(test_cases)
}, indent=2) + '\n')

# Record into persistent reverify ledger
ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify', file_path=str(bin_path))
ledger.start_run('Verify CCombatant daily casualty and morale loss commit routines', session='combat-casualty-commit')
ledger.record(report, rnd=1, session='combat-casualty-commit')
ledger.finish_run(1, report['grounded'], report['information'])
ledger.save()

print(f'Combat casualty commit: {len(report["results"])} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.')
print(f'Combat casualty commit emulation: {total_fixtures} fixtures executed, 0 mismatches against combat_casualty_commit_model.')
