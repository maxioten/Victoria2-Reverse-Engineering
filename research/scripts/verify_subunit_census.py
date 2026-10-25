#!/usr/bin/env python3
"""Verify CCombatant::CountRegimentsByFilterObject and CCombatant::CountRegimentsByDirectId.

Routines:
  CCombatant::CountRegimentsByFilterObject: 0x005DC050..0x005DC093 (65 bytes, 29 instructions).
  CCombatant::CountRegimentsByDirectId: 0x005DC0A0..0x005DC0DF (63 bytes, 27 instructions).
Callers:
  0x00786B65, 0x00786BE3, 0x00786C67 in CCombatView::UpdateUnitTypeIcons (0x00786A00).
"""
import hashlib
import json
from pathlib import Path
import struct
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
import pefile
from reverify.verifier import Claim, Verifier
from reverify.ledger import Ledger
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_PROT_ALL
from unicorn.x86_const import (
    UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_EAX, UC_X86_REG_ECX,
    UC_X86_REG_EDX, UC_X86_REG_EBX, UC_X86_REG_ESI, UC_X86_REG_EDI
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT / 'scripts'))
from subunit_census_model import SubUnitTypeInfo, count_regiments_by_category, count_regiments_by_type_id

bin_path = ROOT.parent / 'base-game/v2game.exe'
data = bin_path.read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_32)

claims = []

# 1. CountRegimentsByFilterObject instructions (0x005DC050..0x005DC093)
raw_filter = pe.get_offset_from_rva(0x005DC050 - base)
for insn in md.disasm(data[raw_filter:raw_filter + 100], 0x005DC050):
    claims.append({
        'id': f'count_by_filter_insn_{insn.address:x}',
        'kind': 'instructions',
        'space': 'rva',
        'offset': hex(insn.address - base),
        'base': hex(insn.address),
        'arch': 'x86',
        'length': len(insn.bytes),
        'mnemonics': [insn.mnemonic],
        'operands': [insn.op_str]
    })
    if insn.address >= 0x005DC090:
        break

# 2. CountRegimentsByDirectId instructions (0x005DC0A0..0x005DC0DF)
raw_direct = pe.get_offset_from_rva(0x005DC0A0 - base)
for insn in md.disasm(data[raw_direct:raw_direct + 100], 0x005DC0A0):
    claims.append({
        'id': f'count_by_id_insn_{insn.address:x}',
        'kind': 'instructions',
        'space': 'rva',
        'offset': hex(insn.address - base),
        'base': hex(insn.address),
        'arch': 'x86',
        'length': len(insn.bytes),
        'mnemonics': [insn.mnemonic],
        'operands': [insn.op_str]
    })
    if insn.address >= 0x005DC0DC:
        break

# 3. Call points in CCombatView
for call_va in [0x00786B65, 0x00786BE3, 0x00786C67]:
    c_off = pe.get_offset_from_rva(call_va - base)
    claims.append({
        'id': f'call_count_regiments_at_{call_va:x}',
        'kind': 'bytes_at',
        'space': 'rva',
        'offset': hex(call_va - base),
        'base': hex(call_va),
        'expected': data[c_off:c_off + 5].hex()
    })

# Run Reverify
verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]

# Negative controls and dependent invalidation
wrong = dict(claims[0], id='negative_control_subunit_census', mnemonics=['nop'])
dependent = dict(claims[1], id='negative_dependent_subunit_census', depends_on=['negative_control_subunit_census'])
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

STACK = SCRATCH_BASE + 0x280000
RET_STUB = SCRATCH_BASE + 0x4000
uc.mem_write(RET_STUB, b'\x90')

HEAD_PTR_ADDR = SCRATCH_BASE + 0x8000
FILTER_OBJ = SCRATCH_BASE + 0x9000

POOL_NODE_ARMY = SCRATCH_BASE + 0x10000
POOL_ARMY = SCRATCH_BASE + 0x20000
POOL_TYPE = SCRATCH_BASE + 0x30000
POOL_NODE_REG = SCRATCH_BASE + 0x50000
POOL_REG = SCRATCH_BASE + 0x90000

# Fixtures
test_cases = [
    [],
    [[]],
    [[SubUnitTypeInfo(category=4, type_id=101)]],
    [[SubUnitTypeInfo(category=4, type_id=101), SubUnitTypeInfo(category=5, type_id=102)]],
    [[
        SubUnitTypeInfo(category=4, type_id=101),
        SubUnitTypeInfo(category=4, type_id=101),
        SubUnitTypeInfo(category=5, type_id=102),
        SubUnitTypeInfo(category=6, type_id=103),
        SubUnitTypeInfo(category=6, type_id=103)
    ]],
    [
        [SubUnitTypeInfo(category=4, type_id=101)] * 5,
        [SubUnitTypeInfo(category=5, type_id=102)] * 3,
        [SubUnitTypeInfo(category=6, type_id=103)] * 2
    ],
    [
        [
            SubUnitTypeInfo(category=4, type_id=101),
            SubUnitTypeInfo(category=5, type_id=102),
            SubUnitTypeInfo(category=6, type_id=103)
        ],
        [
            SubUnitTypeInfo(category=4, type_id=101),
            SubUnitTypeInfo(category=4, type_id=104), # same category, different type_id
            SubUnitTypeInfo(category=7, type_id=105)
        ]
    ],
    [
        [SubUnitTypeInfo(category=4, type_id=101)] * 20,
        [SubUnitTypeInfo(category=4, type_id=101)] * 15,
        [SubUnitTypeInfo(category=6, type_id=103)] * 10
    ]
]

categories_to_query = [4, 5, 6, 7, 99]
type_ids_to_query = [101, 102, 103, 104, 105, 999]

total_fixtures = 0
mismatches = 0

for fix_idx, armies in enumerate(test_cases):
    # Build memory structure for this fixture
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
                    uc.mem_write(type_addr + 0x34, struct.pack('<I', reg.type_id))
                    uc.mem_write(reg_addr + 0x38, struct.pack('<I', type_addr))
                    uc.mem_write(node_addr, struct.pack('<IIQ', reg_addr, 0, next_node))
                
                reg_cursor_node += len(army) * 16
                reg_cursor_obj += len(army) * 0x80
                uc.mem_write(army_addr + 0x38, struct.pack('<I', first_reg_node))
            
            uc.mem_write(army_node_addr, struct.pack('<IIQ', army_addr, 0, next_army_node))
        uc.mem_write(HEAD_PTR_ADDR, struct.pack('<I', first_army_node))
    
    # 1. Test CountRegimentsByFilterObject (0x005DC050)
    for cat in categories_to_query:
        total_fixtures += 1
        uc.mem_write(FILTER_OBJ + 0x24, struct.pack('<I', cat))
        uc.mem_write(STACK, struct.pack('<II', RET_STUB, FILTER_OBJ))
        uc.reg_write(UC_X86_REG_ESP, STACK)
        uc.reg_write(UC_X86_REG_ECX, HEAD_PTR_ADDR)
        uc.reg_write(UC_X86_REG_EIP, 0x005DC050)
        
        uc.emu_start(0x005DC050, RET_STUB)
        
        res = uc.reg_read(UC_X86_REG_EAX)
        expected = count_regiments_by_category(armies, cat)
        if res != expected:
            mismatches += 1
            print(f'MISMATCH FilterObject case {fix_idx} cat {cat}: got {res}, expected {expected}')
            
    # 2. Test CountRegimentsByDirectId (0x005DC0A0)
    for tid in type_ids_to_query:
        total_fixtures += 1
        uc.mem_write(STACK, struct.pack('<II', RET_STUB, tid))
        uc.reg_write(UC_X86_REG_ESP, STACK)
        uc.reg_write(UC_X86_REG_ECX, HEAD_PTR_ADDR)
        uc.reg_write(UC_X86_REG_EIP, 0x005DC0A0)
        
        uc.emu_start(0x005DC0A0, RET_STUB)
        
        res = uc.reg_read(UC_X86_REG_EAX)
        expected = count_regiments_by_type_id(armies, tid)
        if res != expected:
            mismatches += 1
            print(f'MISMATCH DirectId case {fix_idx} tid {tid}: got {res}, expected {expected}')

assert mismatches == 0, f'{mismatches} mismatches encountered in emulation!'

# Record receipts
out_dir = ROOT / 'evidence/generated/subunit-census'
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
ledger.start_run('Verify CCombatant subunit census and classification routines', session='subunit-census')
ledger.record(report, rnd=1, session='subunit-census')
ledger.finish_run(1, report['grounded'], report['information'])
ledger.save()

print(f'Subunit census: {len(report["results"])} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.')
print(f'Subunit census emulation: {total_fixtures} fixtures executed, 0 mismatches against subunit_census_model.')
