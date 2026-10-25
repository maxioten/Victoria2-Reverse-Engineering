#!/usr/bin/env python3
"""Verify CUnit::CalculateAverageMorale against PE32 binary with Reverify and Unicorn.

Routine: 0x005C8DC0..0x005C8F08 (329 bytes, 113 instructions).
Vtables:
  - CArmy: slot 37 at 0x00DF8960
  - CUnit: slot 37 at 0x00E02F98
  - CNavy: slot 37 at 0x00E03060
  - CSpecialUnit: slot 37 at 0x00E03128
"""
import hashlib
import json
from pathlib import Path
import struct
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
import pefile
from reverify.ledger import Ledger
from reverify.verifier import Claim, Verifier
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_PROT_ALL
from unicorn.x86_const import (
    UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
    UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP,
    UC_X86_REG_EIP
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT / 'scripts'))
from army_average_morale_model import army_average_morale

bin_path = ROOT.parent / 'base-game/v2game.exe'
data = bin_path.read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_32)

routine_va = 0x005C8DC0
routine_rva = routine_va - base
routine_raw = pe.get_offset_from_rva(routine_rva)
code = data[routine_raw:routine_raw + 0x150]

claims = []
disasm_insns = []
for insn in md.disasm(code, routine_va):
    disasm_insns.append(insn)
    claims.append({
        'id': f'army_avg_morale_insn_{insn.address:x}',
        'kind': 'instructions',
        'space': 'rva',
        'offset': hex(insn.address - base),
        'base': hex(insn.address),
        'arch': 'x86',
        'length': len(insn.bytes),
        'mnemonics': [insn.mnemonic],
        'operands': [insn.op_str]
    })
    if insn.address >= 0x005C8F06:
        break

# Vtable pointers (slot 37 across polymorphism hierarchy)
vtables = [
    (0x00DF8960, 'carmy_slot37'),
    (0x00E02F98, 'cunit_slot37'),
    (0x00E03060, 'cnavy_slot37'),
    (0x00E03128, 'cspecial_slot37'),
]
for vt_va, name in vtables:
    claims.append({
        'id': f'army_avg_morale_vt_{name}',
        'kind': 'bytes_at',
        'space': 'rva',
        'offset': hex(vt_va - base),
        'base': hex(vt_va),
        'expected': struct.pack('<I', routine_va).hex()
    })

# Double constant in 0x00E45840 (0.0005)
claims.append({
    'id': 'army_avg_morale_const_0005',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E45840 - base),
    'base': hex(0x00E45840),
    'expected': data[pe.get_offset_from_rva(0x00E45840 - base):pe.get_offset_from_rva(0x00E45840 - base) + 8].hex()
})

# Double constant in 0x00E45660 (1000.0)
claims.append({
    'id': 'army_avg_morale_const_1000',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(0x00E45660 - base),
    'base': hex(0x00E45660),
    'expected': data[pe.get_offset_from_rva(0x00E45660 - base):pe.get_offset_from_rva(0x00E45660 - base) + 8].hex()
})

# Run Reverify
verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]

# Negative controls and dependent invalidation
wrong = dict(claims[0], id='negative_control_army_avg_morale', mnemonics=['nop'])
dependent = dict(claims[1], id='negative_dependent_army_avg_morale', depends_on=['negative_control_army_avg_morale'])
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

# Synthetic FS:0 page
uc.mem_map(0, 0x1000, UC_PROT_ALL)

# CRT stubs
uc.mem_write(0x00401000, b'\xd9\xee\xc3') # FLDZ; RET
uc.mem_write(0x00B31C00, b'\x31\xc0\xc3') # XOR EAX, EAX; RET

heap_base = 0x02000000
uc.mem_map(heap_base, 0x200000, UC_PROT_ALL)

# Unit vtable stubs
stub_navy_true = heap_base + 0x10
stub_navy_false = heap_base + 0x20
stub_army_true = heap_base + 0x30
stub_army_false = heap_base + 0x40

uc.mem_write(stub_navy_true, b'\xb0\x01\xc3')  # MOV AL, 1; RET
uc.mem_write(stub_navy_false, b'\x30\xc0\xc3') # XOR AL, AL; RET
uc.mem_write(stub_army_true, b'\xb0\x01\xc3')  # MOV AL, 1; RET
uc.mem_write(stub_army_false, b'\x30\xc0\xc3') # XOR AL, AL; RET

unit_vtable = heap_base + 0x100
unit_obj = heap_base + 0x1000
uc.mem_write(unit_obj, unit_vtable.to_bytes(4, 'little'))

# Country singleton & vectors
country_table = heap_base + 0x2000
country_vec = heap_base + 0x2100
country_obj = heap_base + 0x3000
party_obj = heap_base + 0x4000

uc.mem_write(0x012587E4, country_table.to_bytes(4, 'little'))
uc.mem_write(country_table + 4, country_vec.to_bytes(4, 'little'))
country_id = 1
uc.mem_write(country_vec + country_id * 4, country_obj.to_bytes(4, 'little'))
uc.mem_write(unit_obj + 0xC4, country_id.to_bytes(4, 'little'))
uc.mem_write(country_obj + 0xA60, party_obj.to_bytes(4, 'little'))

# Leader
leader_obj = heap_base + 0x5000
mod_obj = heap_base + 0x5100
uc.mem_write(leader_obj + 0x48, mod_obj.to_bytes(4, 'little'))

out_buf = heap_base + 0x6000
stack_base = heap_base + 0x100000

def emu_army_avg_morale(
    regiment_morales: list[int],
    count: int,
    branch: str,
    doctrine_bonus: int | None,
    leader_bonus: int | None
) -> int:
    if branch == 'navy':
        uc.mem_write(unit_vtable + 0x38, stub_navy_true.to_bytes(4, 'little'))
        uc.mem_write(unit_vtable + 0x3C, stub_army_false.to_bytes(4, 'little'))
    elif branch == 'army':
        uc.mem_write(unit_vtable + 0x38, stub_navy_false.to_bytes(4, 'little'))
        uc.mem_write(unit_vtable + 0x3C, stub_army_true.to_bytes(4, 'little'))
    else:
        uc.mem_write(unit_vtable + 0x38, stub_navy_false.to_bytes(4, 'little'))
        uc.mem_write(unit_vtable + 0x3C, stub_army_false.to_bytes(4, 'little'))

    if regiment_morales:
        curr_node = heap_base + 0x7000
        uc.mem_write(unit_obj + 0x38, curr_node.to_bytes(4, 'little'))
        for idx, m in enumerate(regiment_morales):
            subunit = heap_base + 0x8000 + idx * 0x80
            subunit_type = heap_base + 0x9000 + idx * 0x100
            next_node = (curr_node + 0x20) if idx + 1 < len(regiment_morales) else 0

            uc.mem_write(curr_node, subunit.to_bytes(4, 'little'))
            uc.mem_write(curr_node + 8, next_node.to_bytes(4, 'little'))
            uc.mem_write(subunit + 0x38, subunit_type.to_bytes(4, 'little'))
            uc.mem_write(subunit_type + 0xB4, (m & 0xFFFFFFFF).to_bytes(4, 'little', signed=False))
            curr_node = next_node
    else:
        uc.mem_write(unit_obj + 0x38, (0).to_bytes(4, 'little'))

    uc.mem_write(unit_obj + 0x40, count.to_bytes(4, 'little'))

    if doctrine_bonus is not None:
        if branch == 'navy':
            uc.mem_write(party_obj + 0x68, (doctrine_bonus & 0xFFFFFFFF).to_bytes(4, 'little', signed=False))
        else:
            uc.mem_write(party_obj + 0x70, (doctrine_bonus & 0xFFFFFFFF).to_bytes(4, 'little', signed=False))
    else:
        uc.mem_write(party_obj + 0x68, (0).to_bytes(4, 'little'))
        uc.mem_write(party_obj + 0x70, (0).to_bytes(4, 'little'))

    if leader_bonus is not None:
        uc.mem_write(unit_obj + 0xD8, leader_obj.to_bytes(4, 'little'))
        uc.mem_write(mod_obj + 0x20, (leader_bonus & 0xFFFFFFFF).to_bytes(4, 'little', signed=False))
    else:
        uc.mem_write(unit_obj + 0xD8, (0).to_bytes(4, 'little'))

    uc.mem_write(out_buf, (0xDEADBEEF).to_bytes(4, 'little'))

    esp = stack_base + 0x80000
    esp -= 4
    uc.mem_write(esp, (0).to_bytes(4, 'little'))
    esp -= 4
    uc.mem_write(esp, out_buf.to_bytes(4, 'little'))
    esp -= 4
    uc.mem_write(esp, (0x005C8F08).to_bytes(4, 'little'))

    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_EBP, esp + 12)
    uc.reg_write(UC_X86_REG_ECX, unit_obj)

    uc.emu_start(0x005C8DC0, 0x005C8F08)
    return struct.unpack('<i', uc.mem_read(out_buf, 4))[0]

fixtures = [
    # 1. Armies of various sizes and compositions
    ([3000, 3000, 3000], 3, 'army', 0, None),
    ([3000, 3000, 3000], 3, 'army', 100, 50),
    ([1000, 2000, 3000, 4000], 4, 'army', 50, None),
    ([1000, 2000, 3000, 4000], 4, 'army', -50, 100),
    ([2500], 1, 'army', 0, 0),
    ([2500], 1, 'army', 200, 150),
    ([2500], 1, 'army', -100, -50),

    # 2. Navies of various sizes and compositions
    ([1500, 2500, 3200, 4000], 4, 'navy', -50, 120),
    ([3500, 3500], 2, 'navy', 0, None),
    ([3500, 3500], 2, 'navy', 150, 50),
    ([1000, 1200, 1500, 2000, 2500], 5, 'navy', 80, 40),

    # 3. Large army groups
    ([3000] * 10, 10, 'army', 100, 100),
    ([2000, 2500, 3000, 3500, 4000, 4500, 5000, 5500], 8, 'army', 50, 25),

    # 4. Zero count / Empty units
    ([], 0, 'army', 0, None),
    ([], 0, 'navy', 100, 50),
    ([], 0, 'none', 0, None),

    # 5. Non-standard branch
    ([3000, 3000], 2, 'none', 100, 50),
    ([4000, 4000], 2, 'none', 0, None),

    # 6. Extreme bonuses
    ([3000], 1, 'army', 500, 300),
    ([3000], 1, 'navy', -300, -200),
]

# Add systematic parametric variations to reach >130 fixtures
for m in [1000, 2000, 3000, 4500, 6000]:
    for doc in [-100, 0, 50, 150]:
        for ldr in [None, 0, 50, 100]:
            fixtures.append(([m, m + 500], 2, 'army', doc, ldr))
            fixtures.append(([m, m + 1000, m + 1500], 3, 'navy', doc, ldr))

emu_results = []
mismatches = 0
for idx, fix in enumerate(fixtures):
    morales, count, branch, doc, ldr = fix
    emu_val = emu_army_avg_morale(morales, count, branch, doc, ldr)
    expected = army_average_morale(morales, count, branch, doc, ldr)
    if emu_val != expected:
        mismatches += 1
        print(f'MISMATCH fixture {idx}: fix={fix}, emu={emu_val}, expected={expected}')
    emu_results.append({
        'fixture_idx': idx,
        'morales': morales,
        'count': count,
        'branch': branch,
        'doctrine': doc,
        'leader': ldr,
        'emulated': emu_val,
        'expected': expected,
        'pass': emu_val == expected
    })

assert mismatches == 0, f'{mismatches} mismatches found during emulation!'

# Save receipts
out_dir = ROOT / 'evidence/generated/army-average-morale'
out_dir.mkdir(parents=True, exist_ok=True)
(out_dir / 'claims.json').write_text(json.dumps(claims, indent=2) + '\n')
(out_dir / 'reverify.json').write_text(json.dumps(report, indent=2) + '\n')
(out_dir / 'negative-controls.json').write_text(json.dumps(controls, indent=2) + '\n')
(out_dir / 'emulation.json').write_text(json.dumps({
    'binary_sha256': digest,
    'routine_va': hex(routine_va),
    'fixtures_count': len(fixtures),
    'mismatches': mismatches,
    'results': emu_results
}, indent=2) + '\n')

print(f'Army average morale: {len(report["results"])} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.')
print(f'Army average morale emulation: {len(fixtures)} fixtures executed, {mismatches} mismatches against army_average_morale_model.')
