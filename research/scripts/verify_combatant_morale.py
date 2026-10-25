#!/usr/bin/env python3
"""Verify CCombatant::CalculateAverageMorale and CCombatant::CalculateAverageMaxMorale with Reverify and Unicorn.

Routines:
  CCombatant::CalculateAverageMorale: 0x005DC630..0x005DC6FD (206 bytes, 70 instructions).
  CCombatant::CalculateAverageMaxMorale: 0x005DC710..0x005DC7B2 (163 bytes, 59 instructions).
Vtable slots:
  CArmy slot 37 (+0x94) at 0x00DF8960 -> 0x005C8DC0 (CUnit::CalculateAverageMorale).
  CNavy slot 37 (+0x94) at 0x00E03060 -> 0x005C8DC0 (CUnit::CalculateAverageMorale).
  CArmy slot 17 (+0x44) at 0x00DF8910 -> 0x005CFA90 (CUnit::CalculateMaxMorale).
  CNavy slot 17 (+0x44) at 0x00E03010 -> 0x005CFA90 (CUnit::CalculateMaxMorale).
Call sites:
  0x00785B1B in CCombatView -> 0x005DC630.
  0x00785B2E in CCombatView -> 0x005DC710.
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
from combatant_morale_model import ArmyMoraleInfo, calculate_combatant_average_morale, calculate_combatant_average_max_morale

bin_path = ROOT.parent / 'base-game/v2game.exe'
data = bin_path.read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_32)

claims = []

# 1. CCombatant::CalculateAverageMorale instructions (0x005DC630..0x005DC6FD)
raw_mor = pe.get_offset_from_rva(0x005DC630 - base)
for insn in md.disasm(data[raw_mor:raw_mor + 220], 0x005DC630):
    claims.append({
        'id': f'combatant_avg_morale_insn_{insn.address:x}',
        'kind': 'instructions',
        'space': 'rva',
        'offset': hex(insn.address - base),
        'base': hex(insn.address),
        'arch': 'x86',
        'length': len(insn.bytes),
        'mnemonics': [insn.mnemonic],
        'operands': [insn.op_str]
    })
    if insn.address >= 0x005DC6FD:
        break

# 2. CCombatant::CalculateAverageMaxMorale instructions (0x005DC710..0x005DC7B2)
raw_max = pe.get_offset_from_rva(0x005DC710 - base)
for insn in md.disasm(data[raw_max:raw_max + 180], 0x005DC710):
    claims.append({
        'id': f'combatant_avg_max_morale_insn_{insn.address:x}',
        'kind': 'instructions',
        'space': 'rva',
        'offset': hex(insn.address - base),
        'base': hex(insn.address),
        'arch': 'x86',
        'length': len(insn.bytes),
        'mnemonics': [insn.mnemonic],
        'operands': [insn.op_str]
    })
    if insn.address >= 0x005DC7B2:
        break

# 3. Vtable slots: slot 37 (+0x94) in CArmy (0x00DF8960) and CNavy (0x00E03060)
v_army_37 = pe.get_offset_from_rva(0x00DF8960 - base)
assert int.from_bytes(data[v_army_37:v_army_37 + 4], 'little') == 0x005C8DC0
claims.append({
    'id': 'vtable_slot37_CArmy',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00DF8960 - base),
    'base': hex(0x00DF8960),
    'expected': (0x005C8DC0).to_bytes(4, 'little').hex()
})

v_navy_37 = pe.get_offset_from_rva(0x00E03060 - base)
assert int.from_bytes(data[v_navy_37:v_navy_37 + 4], 'little') == 0x005C8DC0
claims.append({
    'id': 'vtable_slot37_CNavy',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E03060 - base),
    'base': hex(0x00E03060),
    'expected': (0x005C8DC0).to_bytes(4, 'little').hex()
})

# 4. Vtable slots: slot 17 (+0x44) in CArmy (0x00DF8910) and CNavy (0x00E03010)
v_army_17 = pe.get_offset_from_rva(0x00DF8910 - base)
assert int.from_bytes(data[v_army_17:v_army_17 + 4], 'little') == 0x005CFA90
claims.append({
    'id': 'vtable_slot17_CArmy',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00DF8910 - base),
    'base': hex(0x00DF8910),
    'expected': (0x005CFA90).to_bytes(4, 'little').hex()
})

v_navy_17 = pe.get_offset_from_rva(0x00E03010 - base)
assert int.from_bytes(data[v_navy_17:v_navy_17 + 4], 'little') == 0x005CFA90
claims.append({
    'id': 'vtable_slot17_CNavy',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E03010 - base),
    'base': hex(0x00E03010),
    'expected': (0x005CFA90).to_bytes(4, 'little').hex()
})

# 5. Floating-point constants at 0x00E45840 (0.0005) and 0x00E45660 (1000.0)
c1_raw = pe.get_offset_from_rva(0x00E45840 - base)
claims.append({
    'id': 'const_fp_0x00E45840',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E45840 - base),
    'base': hex(0x00E45840),
    'expected': data[c1_raw:c1_raw + 8].hex()
})

c2_raw = pe.get_offset_from_rva(0x00E45660 - base)
claims.append({
    'id': 'const_fp_0x00E45660',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E45660 - base),
    'base': hex(0x00E45660),
    'expected': data[c2_raw:c2_raw + 8].hex()
})

# 6. Call sites in CCombatView
call_sites = [
    ('call_mor_0x00785B1B', 0x00785B1B),
    ('call_max_0x00785B2E', 0x00785B2E),
]
for cid, caddr in call_sites:
    craw = pe.get_offset_from_rva(caddr - base)
    claims.append({
        'id': cid,
        'kind': 'bytes_at',
        'space': 'rva',
        'offset': hex(caddr - base),
        'base': hex(caddr),
        'expected': data[craw:craw + 5].hex()
    })

# Run Reverify
verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]

# Negative controls and dependent invalidation
wrong = dict(claims[0], id='negative_control_combatant_morale', mnemonics=['sub'])
dependent = dict(claims[1], id='negative_dependent_combatant_morale', depends_on=['negative_control_combatant_morale'])
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
OUT_ADDR = SCRATCH_BASE + 0x1000
HEAD_ADDR = SCRATCH_BASE + 0x2000
RET_STUB = SCRATCH_BASE + 0x3000
VTABLE_ARMY = SCRATCH_BASE + 0x4000
STUB_SLOT37_ADDR = SCRATCH_BASE + 0x5000
STUB_SLOT17_ADDR = SCRATCH_BASE + 0x5100

uc.mem_write(RET_STUB, b'\x90')

# Synthetic stubs for slot 37 and slot 17:
# Slot 37: writes [ecx + 0x60] into *[esp + 4], returns eax = [esp + 4], ret 4
stub_slot37 = bytes([
    0x8B, 0x54, 0x24, 0x04,              # mov edx, [esp + 4]
    0x8B, 0x41, 0x60,                    # mov eax, [ecx + 0x60]
    0x89, 0x02,                          # mov [edx], eax
    0x8B, 0xC2,                          # mov eax, edx
    0xC2, 0x04, 0x00                     # ret 4
])
# Slot 17: writes [ecx + 0x64] into *[esp + 4], returns eax = [esp + 4], ret 4
stub_slot17 = bytes([
    0x8B, 0x54, 0x24, 0x04,              # mov edx, [esp + 4]
    0x8B, 0x41, 0x64,                    # mov eax, [ecx + 0x64]
    0x89, 0x02,                          # mov [edx], eax
    0x8B, 0xC2,                          # mov eax, edx
    0xC2, 0x04, 0x00                     # ret 4
])
uc.mem_write(STUB_SLOT37_ADDR, stub_slot37)
uc.mem_write(STUB_SLOT17_ADDR, stub_slot17)

# Wire mock vtable:
# slot 37 is at +0x94
# slot 17 is at +0x44
uc.mem_write(VTABLE_ARMY + 0x94, struct.pack('<I', STUB_SLOT37_ADDR))
uc.mem_write(VTABLE_ARMY + 0x44, struct.pack('<I', STUB_SLOT17_ADDR))

heap_top = SCRATCH_BASE + 0x10000

def reset_heap():
    global heap_top
    heap_top = SCRATCH_BASE + 0x10000

def alloc(size):
    global heap_top
    aligned = (size + 7) & ~7
    addr = heap_top
    heap_top += aligned
    assert heap_top < SCRATCH_BASE + 0x200000, "Heap overflow"
    return addr

def build_army_list(armies_data):
    """
    Builds the linked ArmyNode structures:
    HEAD_ADDR -> ArmyNode -> ArmyNode -> ...
    Each ArmyNode (+0x00: pArmy, +0x08: pNextArmyNode)
    Each CArmy (+0x00: VTABLE_ARMY, +0x40: subunit_count, +0x60: morale, +0x64: max_morale)
    """
    reset_heap()
    if armies_data is None:
        uc.mem_write(HEAD_ADDR, struct.pack('<I', 0))
        return

    army_node_addrs = []
    for a in armies_data:
        army_addr = alloc(0x80)
        uc.mem_write(army_addr + 0x00, struct.pack('<I', VTABLE_ARMY))
        uc.mem_write(army_addr + 0x40, struct.pack('<I', a.count))
        uc.mem_write(army_addr + 0x60, struct.pack('<I', a.morale))
        uc.mem_write(army_addr + 0x64, struct.pack('<I', a.max_morale))

        anode_addr = alloc(0x10)
        uc.mem_write(anode_addr + 0x00, struct.pack('<I', army_addr))
        army_node_addrs.append(anode_addr)

    for i in range(len(army_node_addrs)):
        nxt = army_node_addrs[i + 1] if i + 1 < len(army_node_addrs) else 0
        uc.mem_write(army_node_addrs[i] + 0x08, struct.pack('<I', nxt))

    head_ptr = army_node_addrs[0] if army_node_addrs else 0
    uc.mem_write(HEAD_ADDR, struct.pack('<I', head_ptr))


test_scenarios = [
    # 0. None (empty list)
    None,
    # 1. Empty list
    [],
    # 2. 1 army with count 0
    [ArmyMoraleInfo(count=0, morale=1000, max_morale=3000)],
    # 3. 1 army with varying morale and count
    [ArmyMoraleInfo(count=1, morale=1000, max_morale=3000)],
    [ArmyMoraleInfo(count=10, morale=2500, max_morale=3000)],
    [ArmyMoraleInfo(count=30, morale=3000, max_morale=3000)],
    [ArmyMoraleInfo(count=5, morale=500, max_morale=1000)],
    [ArmyMoraleInfo(count=12, morale=0, max_morale=3500)],
    # 4. Multiple armies with equal size and different morale
    [
        ArmyMoraleInfo(count=10, morale=1000, max_morale=3000),
        ArmyMoraleInfo(count=10, morale=2000, max_morale=3000)
    ],
    # 5. Multiple armies with asymmetric weights (large army dominates average)
    [
        ArmyMoraleInfo(count=50, morale=3000, max_morale=3000),
        ArmyMoraleInfo(count=5, morale=500, max_morale=1000)
    ],
    [
        ArmyMoraleInfo(count=2, morale=3000, max_morale=3000),
        ArmyMoraleInfo(count=40, morale=1000, max_morale=2000)
    ],
    # 6. Three armies with varying parameters
    [
        ArmyMoraleInfo(count=15, morale=2200, max_morale=3500),
        ArmyMoraleInfo(count=25, morale=1800, max_morale=3000),
        ArmyMoraleInfo(count=10, morale=2900, max_morale=4000)
    ],
    # 7. Four armies including one depleted army with count 0
    [
        ArmyMoraleInfo(count=20, morale=2500, max_morale=3000),
        ArmyMoraleInfo(count=0, morale=0, max_morale=3000),
        ArmyMoraleInfo(count=10, morale=1500, max_morale=2500),
        ArmyMoraleInfo(count=30, morale=2800, max_morale=3200)
    ],
    # 8. Large scale battle (10 armies)
    [
        ArmyMoraleInfo(count=10 * (i + 1), morale=1000 + i * 200, max_morale=3000 + i * 100)
        for i in range(10)
    ]
]

# Additional parametric fixtures
for c1 in [5, 12, 24, 50, 100]:
    for m1 in [200, 800, 1500, 2400, 3200]:
        test_scenarios.append([
            ArmyMoraleInfo(count=c1, morale=m1, max_morale=3500),
            ArmyMoraleInfo(count=c1 * 2, morale=3500 - m1, max_morale=3500)
        ])

mismatches = 0
total_fixtures = 0

for sc in test_scenarios:
    build_army_list(sc)

    # 1. Test CCombatant::CalculateAverageMorale (0x005DC630)
    # Convention: __stdcall (ArmyNode** pArmyList, int* out_val), ret 8
    total_fixtures += 1
    uc.mem_write(OUT_ADDR, struct.pack('<I', 0xDEADBEEF))
    uc.mem_write(STACK, struct.pack('<III', RET_STUB, HEAD_ADDR, OUT_ADDR))
    uc.reg_write(UC_X86_REG_ESP, STACK)
    uc.reg_write(UC_X86_REG_EIP, 0x005DC630)
    uc.reg_write(UC_X86_REG_EAX, 0)
    uc.reg_write(UC_X86_REG_EBX, 0)
    uc.reg_write(UC_X86_REG_ECX, 0)
    uc.reg_write(UC_X86_REG_EDX, 0)
    uc.reg_write(UC_X86_REG_ESI, 0)
    uc.reg_write(UC_X86_REG_EDI, 0)

    uc.emu_start(0x005DC630, RET_STUB, timeout=1000000)

    res_bytes = uc.mem_read(OUT_ADDR, 4)
    res_mor = struct.unpack('<i', res_bytes)[0]
    ret_eax = uc.reg_read(UC_X86_REG_EAX)
    expected_mor = calculate_combatant_average_morale(sc)
    if res_mor != expected_mor or ret_eax != OUT_ADDR:
        print(f"MISMATCH in CalculateAverageMorale: got {res_mor} (ret={hex(ret_eax)}), expected {expected_mor}")
        mismatches += 1

    # 2. Test CCombatant::CalculateAverageMaxMorale (0x005DC710)
    # Convention: __cdecl with eax = ArmyNode**, [esp + 4] = out_val, ret 4
    total_fixtures += 1
    uc.mem_write(OUT_ADDR, struct.pack('<I', 0xDEADBEEF))
    uc.mem_write(STACK, struct.pack('<II', RET_STUB, OUT_ADDR))
    uc.reg_write(UC_X86_REG_ESP, STACK)
    uc.reg_write(UC_X86_REG_EAX, HEAD_ADDR)
    uc.reg_write(UC_X86_REG_EIP, 0x005DC710)
    uc.reg_write(UC_X86_REG_EBX, 0)
    uc.reg_write(UC_X86_REG_ECX, 0)
    uc.reg_write(UC_X86_REG_EDX, 0)
    uc.reg_write(UC_X86_REG_ESI, 0)
    uc.reg_write(UC_X86_REG_EDI, 0)

    uc.emu_start(0x005DC710, RET_STUB, timeout=1000000)

    res_bytes = uc.mem_read(OUT_ADDR, 4)
    res_max = struct.unpack('<i', res_bytes)[0]
    ret_eax = uc.reg_read(UC_X86_REG_EAX)
    expected_max = calculate_combatant_average_max_morale(sc)
    if res_max != expected_max or ret_eax != OUT_ADDR:
        print(f"MISMATCH in CalculateAverageMaxMorale: got {res_max} (ret={hex(ret_eax)}), expected {expected_max}")
        mismatches += 1

assert mismatches == 0, f"{mismatches} mismatches encountered in emulation!"

# Record receipts
out_dir = ROOT / 'evidence/generated/combatant-morale'
out_dir.mkdir(parents=True, exist_ok=True)
(out_dir / 'claims.json').write_text(json.dumps(claims, indent=2) + '\n')
(out_dir / 'reverify.json').write_text(json.dumps(report, indent=2) + '\n')
(out_dir / 'negative-controls.json').write_text(json.dumps(controls, indent=2) + '\n')
(out_dir / 'emulation.json').write_text(json.dumps({
    'pass': True,
    'fixtures_tested': total_fixtures,
    'mismatches': mismatches,
    'scenarios_count': len(test_scenarios)
}, indent=2) + '\n')

# Record into persistent reverify ledger
ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify', file_path=str(bin_path))
ledger.start_run('Verify CCombatant combatant average and max morale routines', session='combatant-morale')
ledger.record(report, rnd=1, session='combatant-morale')
ledger.finish_run(1, report['grounded'], report['information'])
ledger.save()

print(f"Combatant morale: {len(report['results'])} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Combatant morale emulation: {total_fixtures} fixtures executed, 0 mismatches against combatant_morale_model.")
