#!/usr/bin/env python3
"""
Verify CRegiment::CalculateMaxMorale routine (0x005BFFA0..0x005C010C, vtables at 0x00DF88B8, 0x00E02A20).
Validates base morale retrieval, ruling party doctrine, leader trait modifiers,
the rebel ("REB") budget exemption, and the 25%..100% military spending slider scaling.
"""

import hashlib
import json
import math
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
sys.path.insert(0, str(ROOT / 'scripts'))
from regiment_max_morale_model import compute_regiment_max_morale

data = (ROOT.parent / 'base-game/v2game.exe').read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = 0x400000
sec = [s for s in pe.sections if s.Name.startswith(b'.text')][0]
sec_data = sec.get_data()
offset = 0x005BFFA0 - base - sec.VirtualAddress
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
insns = list(md.disasm(sec_data[offset:offset+0x16D], 0x005BFFA0))

claims = []
for insn in insns:
    claims.append({
        'id': f'max_morale_{insn.address:x}', 'kind': 'instructions', 'space': 'rva',
        'offset': hex(insn.address - base), 'base': hex(insn.address), 'arch': 'x86',
        'length': insn.size, 'mnemonics': [insn.mnemonic], 'operands': [insn.op_str] if insn.op_str else []
    })

# Vtable slot claims
claims.append({
    'id': 'vtable_regiment_max_morale', 'kind': 'bytes_at', 'space': 'rva',
    'offset': hex(0x00DF88B8 - base), 'base': hex(0x00DF88B8),
    'expected': (0x005BFFA0).to_bytes(4, 'little').hex()
})
claims.append({
    'id': 'vtable_subunit_max_morale', 'kind': 'bytes_at', 'space': 'rva',
    'offset': hex(0x00E02A20 - base), 'base': hex(0x00E02A20),
    'expected': (0x005BFFA0).to_bytes(4, 'little').hex()
})

# Float constant claims (budget multipliers 750 and 250)
claims.append({
    'id': 'const_spending_mult_750', 'kind': 'bytes_at', 'space': 'rva',
    'offset': hex(0x00E45AC0 - base), 'base': hex(0x00E45AC0),
    'expected': struct.pack('<f', 750.5).hex()
})
claims.append({
    'id': 'const_spending_floor_250', 'kind': 'bytes_at', 'space': 'rva',
    'offset': hex(0x00E45A40 - base), 'base': hex(0x00E45A40),
    'expected': struct.pack('<f', 250.5).hex()
})

verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]
verified_count = len(claims)

# Negative controls
wrong = dict(claims[0], id='negative_control_max_morale', mnemonics=['nop'])
dependent = dict(claims[1], id='negative_dependent_max_morale', depends_on=['negative_control_max_morale'])
controls = verifier.verify_all([Claim.from_dict(wrong), Claim.from_dict(dependent)])
assert [r['verdict'] for r in controls['results']] == ['REFUTED', 'INVALIDATED']

# --- Unicorn Emulation ---
uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
uc.mem_map(0, 0x1000, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)

for s in pe.sections:
    name = s.Name.decode().strip(chr(0))
    va = pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress
    size = (s.Misc_VirtualSize + 0xFFF) & ~0xFFF
    prot = unicorn.UC_PROT_READ
    if s.Characteristics & 0x20000000:
        prot |= unicorn.UC_PROT_EXEC
    if s.Characteristics & 0x80000000:
        prot |= unicorn.UC_PROT_WRITE
    uc.mem_map(va, size, prot)
    uc.mem_write(va, s.get_data())

stack_base = 0x00100000
stack_size = 0x00020000
uc.mem_map(stack_base, stack_size, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)

heap_base = 0x00200000
heap_size = 0x00040000
uc.mem_map(heap_base, heap_size, unicorn.UC_PROT_ALL)

regiment = heap_base + 0x1000
reg_vtable = heap_base + 0x2000
reg_type = heap_base + 0x3000
country = heap_base + 0x4000
party = heap_base + 0x5000
country_list = heap_base + 0x6000
leader_obj = heap_base + 0x7000
trait_obj = heap_base + 0x7100
mod_obj = heap_base + 0x7200

# Virtual methods for IsNavy (+0x24) and IsArmy (+0x28)
stub_navy_true = heap_base + 0x2100
stub_navy_false = heap_base + 0x2108
stub_army_true = heap_base + 0x2110
stub_army_false = heap_base + 0x2118
uc.mem_write(stub_navy_true, b'\xb8\x01\x00\x00\x00\xc3')   # mov eax, 1; ret
uc.mem_write(stub_navy_false, b'\x31\xc0\xc3')             # xor eax, eax; ret
uc.mem_write(stub_army_true, b'\xb8\x01\x00\x00\x00\xc3')   # mov eax, 1; ret
uc.mem_write(stub_army_false, b'\x31\xc0\xc3')             # xor eax, eax; ret

uc.mem_write(regiment, reg_vtable.to_bytes(4, 'little'))
uc.mem_write(regiment + 0x38, reg_type.to_bytes(4, 'little'))
uc.mem_write(regiment + 0x64, (0).to_bytes(4, 'little')) # country index 0

# Setup 0x012587E4 pointer to country list
ptr_to_list = heap_base + 0x6100
uc.mem_write(country_list, country.to_bytes(4, 'little'))
uc.mem_write(ptr_to_list + 4, country_list.to_bytes(4, 'little'))
uc.mem_write(0x012587E4, ptr_to_list.to_bytes(4, 'little'))

# Leader hierarchy setup
uc.mem_write(leader_obj + 0xD8, trait_obj.to_bytes(4, 'little'))
uc.mem_write(trait_obj + 0x48, mod_obj.to_bytes(4, 'little'))

current_floor_val = 0

def hook_floorf(uc_inst, address, size, user_data):
    global current_floor_val
    esp = uc_inst.reg_read(UC_X86_REG_ESP)
    ret_addr = struct.unpack('<I', uc_inst.mem_read(esp, 4))[0]
    fl_arg = struct.unpack('<f', uc_inst.mem_read(esp + 4, 4))[0]
    current_floor_val = int(math.floor(fl_arg))
    uc_inst.reg_write(UC_X86_REG_ESP, esp + 4)
    uc_inst.reg_write(UC_X86_REG_EIP, ret_addr)

def hook_ftol(uc_inst, address, size, user_data):
    esp = uc_inst.reg_read(UC_X86_REG_ESP)
    ret_addr = struct.unpack('<I', uc_inst.mem_read(esp, 4))[0]
    uc_inst.reg_write(UC_X86_REG_EAX, current_floor_val)
    uc_inst.reg_write(UC_X86_REG_ESP, esp + 4)
    uc_inst.reg_write(UC_X86_REG_EIP, ret_addr)

uc.hook_add(unicorn.UC_HOOK_CODE, hook_floorf, None, 0x00401000, 0x00401000)
uc.hook_add(unicorn.UC_HOOK_CODE, hook_ftol, None, 0x00B31C00, 0x00B31C00)

out_buf = stack_base + 0x8000

def run_regiment_max_morale_emulation(
    base_morale: int,
    is_army: bool,
    doctrine_bonus: int,
    leader_bonus: int | None,
    is_rebel: bool,
    spending_slider: int
) -> int:
    # Set virtual methods
    if is_army:
        uc.mem_write(reg_vtable + 0x24, stub_navy_false.to_bytes(4, 'little'))
        uc.mem_write(reg_vtable + 0x28, stub_army_true.to_bytes(4, 'little'))
    else:
        uc.mem_write(reg_vtable + 0x24, stub_navy_true.to_bytes(4, 'little'))
        uc.mem_write(reg_vtable + 0x28, stub_army_false.to_bytes(4, 'little'))

    # Base morale
    uc.mem_write(reg_type + 0xB4, (base_morale & 0xFFFFFFFF).to_bytes(4, 'little', signed=False))

    # Party doctrine
    uc.mem_write(country + 0xA60, party.to_bytes(4, 'little'))
    if is_army:
        uc.mem_write(party + 0x70, (doctrine_bonus & 0xFFFFFFFF).to_bytes(4, 'little', signed=False))
    else:
        uc.mem_write(party + 0x68, (doctrine_bonus & 0xFFFFFFFF).to_bytes(4, 'little', signed=False))

    # Leader
    if leader_bonus is not None:
        uc.mem_write(regiment + 0x74, leader_obj.to_bytes(4, 'little'))
        uc.mem_write(mod_obj + 0x20, (leader_bonus & 0xFFFFFFFF).to_bytes(4, 'little', signed=False))
    else:
        uc.mem_write(regiment + 0x74, (0).to_bytes(4, 'little'))

    # Tag
    tag_bytes = b'REB\x00' if is_rebel else b'FRA\x00'
    uc.mem_write(regiment + 0x60, tag_bytes)

    # Spending slider in country (+0x1448 for navy, +0x1450 for army)
    slider_offset = 0x1450 if is_army else 0x1448
    uc.mem_write(country + slider_offset, (spending_slider & 0xFFFFFFFFFFFFFFFF).to_bytes(8, 'little', signed=False))

    # Initialize output buffer with canary
    uc.mem_write(out_buf, (0xDEADBEEF).to_bytes(4, 'little'))

    esp = stack_base + 0x10000
    esp -= 4
    uc.mem_write(esp, (0).to_bytes(4, 'little'))
    esp -= 4
    uc.mem_write(esp, out_buf.to_bytes(4, 'little'))
    esp -= 4
    uc.mem_write(esp, (0x005C010C).to_bytes(4, 'little'))

    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_EBP, esp + 12)
    uc.reg_write(UC_X86_REG_ECX, regiment)

    uc.emu_start(0x005BFFA0, 0x005C010C)
    return struct.unpack('<i', uc.mem_read(out_buf, 4))[0]


fixtures = [
    # (base_morale, is_army, doctrine_bonus, leader_bonus, is_rebel, spending_slider)
    # 1. Standard army at 100% spending, no leader
    (3000, True, 0, None, False, 0x01F40000),
    (3000, True, 100, None, False, 0x01F40000),
    # 2. Standard navy at 100% spending
    (3000, False, 0, None, False, 0x01F40000),
    (3000, False, 200, None, False, 0x01F40000),
    # 3. Army with leader
    (3000, True, 100, 50, False, 0x01F40000),
    (3000, True, 0, 150, False, 0x01F40000),
    (4500, True, 200, -50, False, 0x01F40000),
    # 4. Navy with admiral
    (4000, False, 100, 100, False, 0x01F40000),
    # 5. Rebel armies (ignore spending slider)
    (3000, True, 0, None, True, 0x01F40000),
    (3000, True, 100, None, True, 0),
    (3000, True, 100, 50, True, 0x00FA0000),
    # 6. Budget scaling: 0%, 50%, 100%
    (3000, True, 0, None, False, 0),
    (3000, True, 0, None, False, 0x00FA0000), # ~50%
    (3000, False, 0, None, False, 0),
    (3000, False, 0, None, False, 0x00FA0000),
    # 7. Low / high base morale
    (1000, True, 0, None, False, 0x01F40000),
    (6000, True, 300, 200, False, 0x01F40000),
]

# Random fixtures
random.seed(665544)
for _ in range(125):
    b_m = random.choice([1000, 1500, 2000, 2500, 3000, 3500, 4000, 5000, 6000])
    is_a = random.choice([True, False])
    doc = random.randint(-100, 400)
    lead = random.choice([None, random.randint(-100, 300)])
    reb = random.random() < 0.2
    spd = random.randint(0, 0x01F40000)
    fixtures.append((b_m, is_a, doc, lead, reb, spd))

fixture_count = 0
mismatches = 0

for fix in fixtures:
    exp = compute_regiment_max_morale(*fix)
    act = run_regiment_max_morale_emulation(*fix)
    fixture_count += 1
    if act != exp:
        mismatches += 1
        print(f"Mismatch at fix={fix}: act={act}, exp={exp}")

assert mismatches == 0, f"{mismatches} mismatches found during regiment max morale emulation"

out = ROOT / 'evidence/generated/regiment-max-morale'
out.mkdir(parents=True, exist_ok=True)
(out / 'claims.json').write_text(json.dumps(claims, indent=2) + '\n')
(out / 'reverify.json').write_text(json.dumps(report, indent=2) + '\n')
(out / 'negative-controls.json').write_text(json.dumps(controls, indent=2) + '\n')
(out / 'emulation.json').write_text(json.dumps({
    'target_digest': digest,
    'total_fixtures': fixture_count,
    'mismatches': mismatches,
    'status': 'PASS'
}, indent=2) + '\n')

ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify')
ledger.record(report, session='regiment-max-morale')
ledger.save()

print(f"Regiment max morale: {verified_count} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Regiment max morale emulation: {fixture_count} fixtures executed, 0 mismatches against regiment_max_morale_model.")
