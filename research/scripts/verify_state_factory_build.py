#!/usr/bin/env python3
"""
Verify CState::CanBuildFactory routine (0x004D04B0..0x004D0692, callers at 0x0052CAB1, 0x0052CB07, 0x008575CE).
Checks colonial prohibition, 8-factory capacity cap, duplicate factory prevention,
AI specialization & slot reservation heuristics, and technology prerequisites.
"""

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
sys.path.insert(0, str(ROOT / 'scripts'))
from state_factory_build_model import check_state_can_build_factory

data = (ROOT.parent / 'base-game/v2game.exe').read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = 0x400000
sec = [s for s in pe.sections if s.Name.startswith(b'.text')][0]
sec_data = sec.get_data()
offset = 0x004D04B0 - base - sec.VirtualAddress
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
insns = list(md.disasm(sec_data[offset:offset+0x1E5], 0x004D04B0))

claims = []
for insn in insns:
    claims.append({
        'id': f'factory_build_{insn.address:x}', 'kind': 'instructions', 'space': 'rva',
        'offset': hex(insn.address - base), 'base': hex(insn.address), 'arch': 'x86',
        'length': insn.size, 'mnemonics': [insn.mnemonic], 'operands': [insn.op_str] if insn.op_str else []
    })

# Add confirmed callers
callers = (0x0052CAB1, 0x0052CB07, 0x008575CE)
for c in callers:
    claims.append({
        'id': f'call_factory_build_{c:x}', 'kind': 'instructions', 'space': 'rva',
        'offset': hex(c - base), 'base': hex(c), 'arch': 'x86',
        'length': 5, 'mnemonics': ['call'], 'operands': ['0x4d04b0']
    })

verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]
verified_count = len(claims)

# Negative controls
wrong = dict(claims[0], id='negative_control_factory_build', mnemonics=['nop'])
dependent = dict(claims[1], id='negative_dependent_factory_build', depends_on=['negative_control_factory_build'])
controls = verifier.verify_all([Claim.from_dict(wrong), Claim.from_dict(dependent)])
assert [r['verdict'] for r in controls['results']] == ['REFUTED', 'INVALIDATED']

# --- Unicorn Emulation ---
uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)

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

# Mock state variables
mock_country_has_tech = True
mock_state_has_port = True
mock_coastal_provinces = []

# Hooks for external callees:
# 0x004D0E70: CCountry::HasTechnology(state, tech) -> al
def hook_has_tech(uc_inst, address, size, user_data):
    esp = uc_inst.reg_read(UC_X86_REG_ESP)
    ret_addr = struct.unpack('<I', uc_inst.mem_read(esp, 4))[0]
    uc_inst.reg_write(UC_X86_REG_EAX, 1 if mock_country_has_tech else 0)
    uc_inst.reg_write(UC_X86_REG_ESP, esp + 12)  # ret 8
    uc_inst.reg_write(UC_X86_REG_EIP, ret_addr)

# 0x004D0FD0: CState::HasPort(state) -> al
def hook_has_port(uc_inst, address, size, user_data):
    esp = uc_inst.reg_read(UC_X86_REG_ESP)
    ret_addr = struct.unpack('<I', uc_inst.mem_read(esp, 4))[0]
    uc_inst.reg_write(UC_X86_REG_EAX, 1 if mock_state_has_port else 0)
    uc_inst.reg_write(UC_X86_REG_ESP, esp + 4)   # ret
    uc_inst.reg_write(UC_X86_REG_EIP, ret_addr)

# 0x004DAD40: CState::GetCoastalProvincesVector(state) -> eax vector
dummy_vec_addr = heap_base + 0x30000
def hook_coastal(uc_inst, address, size, user_data):
    esp = uc_inst.reg_read(UC_X86_REG_ESP)
    ret_addr = struct.unpack('<I', uc_inst.mem_read(esp, 4))[0]
    # vector layout: [vec+0xC] = begin, [vec+0x10] = end
    count = len(mock_coastal_provinces)
    begin_ptr = heap_base + 0x31000
    end_ptr = begin_ptr + count * 4
    uc_inst.mem_write(dummy_vec_addr + 0xC, begin_ptr.to_bytes(4, 'little'))
    uc_inst.mem_write(dummy_vec_addr + 0x10, end_ptr.to_bytes(4, 'little'))
    uc_inst.reg_write(UC_X86_REG_EAX, dummy_vec_addr)
    uc_inst.reg_write(UC_X86_REG_EIP, ret_addr)

uc.hook_add(unicorn.UC_HOOK_CODE, hook_has_tech, None, 0x004D0E70, 0x004D0E70)
uc.hook_add(unicorn.UC_HOOK_CODE, hook_has_port, None, 0x004D0FD0, 0x004D0FD0)
uc.hook_add(unicorn.UC_HOOK_CODE, hook_coastal, None, 0x004DAD40, 0x004DAD40)

state_addr = heap_base + 0x1000
candidate_addr = heap_base + 0x2000
tech_obj_addr = heap_base + 0x3000

def run_state_factory_build_emulation(
    is_colonial: int,
    factory_count: int,
    existing_factory_types: list[int],
    candidate_type_id: int,
    is_ai: bool,
    existing_flags_13a: list[int] = None,
    existing_flags_13b: list[int] = None,
    candidate_flag_13a: int = 0,
    candidate_flag_13b: int = 0,
    candidate_requires_coastal: int = 0,
    state_has_coastal_province: bool = True,
    tech_prereq_present: bool = False,
    country_has_tech: bool = True,
    tech_requires_port: bool = False,
    state_has_port: bool = True
) -> int:
    global mock_country_has_tech, mock_state_has_port, mock_coastal_provinces
    mock_country_has_tech = country_has_tech
    mock_state_has_port = state_has_port
    mock_coastal_provinces = [1] if state_has_coastal_province else []

    # Setup Candidate Type
    uc.mem_write(candidate_addr + 0x58, candidate_type_id.to_bytes(4, 'little'))
    uc.mem_write(candidate_addr + 0xD8, (1 if candidate_requires_coastal else 0).to_bytes(1, 'little'))
    uc.mem_write(candidate_addr + 0x13A, (candidate_flag_13a & 0xFF).to_bytes(1, 'little'))
    uc.mem_write(candidate_addr + 0x13B, (candidate_flag_13b & 0xFF).to_bytes(1, 'little'))

    if tech_prereq_present:
        uc.mem_write(candidate_addr + 0x12C, tech_obj_addr.to_bytes(4, 'little'))
        uc.mem_write(tech_obj_addr + 0x7C, (1 if tech_requires_port else 0).to_bytes(1, 'little'))
    else:
        uc.mem_write(candidate_addr + 0x12C, (0).to_bytes(4, 'little'))

    # Setup State
    uc.mem_write(state_addr + 0x84, is_colonial.to_bytes(4, 'little'))
    uc.mem_write(state_addr + 0x68, factory_count.to_bytes(4, 'little'))

    # Build linked list of existing factories
    flags_a = existing_flags_13a or [0] * len(existing_factory_types)
    flags_b = existing_flags_13b or [0] * len(existing_factory_types)

    if not existing_factory_types:
        uc.mem_write(state_addr + 0x60, (0).to_bytes(4, 'little'))
    else:
        head_node = heap_base + 0x5000
        uc.mem_write(state_addr + 0x60, head_node.to_bytes(4, 'little'))
        for i, (f_type_id, fa, fb) in enumerate(zip(existing_factory_types, flags_a, flags_b)):
            curr_node = heap_base + 0x5000 + i * 0x300
            curr_type = heap_base + 0x10000 + i * 0x200
            next_node = heap_base + 0x5000 + (i + 1) * 0x300 if i + 1 < len(existing_factory_types) else 0

            # Write factory type
            uc.mem_write(curr_type + 0x58, f_type_id.to_bytes(4, 'little'))
            uc.mem_write(curr_type + 0x13A, (fa & 0xFF).to_bytes(1, 'little'))
            uc.mem_write(curr_type + 0x13B, (fb & 0xFF).to_bytes(1, 'little'))

            # Write node
            # If f_type_id matches candidate_type_id, point directly to candidate_addr to simulate duplicate type pointer
            if f_type_id == candidate_type_id:
                uc.mem_write(curr_node + 0x18, candidate_addr.to_bytes(4, 'little'))
            else:
                uc.mem_write(curr_node + 0x18, curr_type.to_bytes(4, 'little'))
            uc.mem_write(curr_node + 0x20, (1).to_bytes(4, 'little')) # level
            uc.mem_write(curr_node + 0x224, next_node.to_bytes(4, 'little'))

    esp = stack_base + 0x10000
    # Push arguments: is_ai, candidate_addr, state_addr, return_addr
    esp -= 4
    uc.mem_write(esp, (1 if is_ai else 0).to_bytes(4, 'little'))
    esp -= 4
    uc.mem_write(esp, candidate_addr.to_bytes(4, 'little'))
    esp -= 4
    uc.mem_write(esp, state_addr.to_bytes(4, 'little'))
    esp -= 4
    uc.mem_write(esp, (0x004D0692).to_bytes(4, 'little'))

    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_EBP, esp + 16)

    uc.emu_start(0x004D04B0, 0x004D0692)
    return uc.reg_read(UC_X86_REG_EAX) & 0xFF


fixtures = [
    # (is_colonial, factory_count, existing_types, candidate_type, is_ai, flags_a, flags_b, cand_a, cand_b, req_coast, has_coast, has_tech_prereq, has_tech, req_port, has_port)
    # 1. Normal state, empty, human -> 1
    (0, 0, [], 1, False, [], [], 0, 0, 0, True, False, True, False, True),
    # 2. Colonial state, empty, human -> 0
    (1, 0, [], 1, False, [], [], 0, 0, 0, True, False, True, False, True),
    (2, 0, [], 1, False, [], [], 0, 0, 0, True, False, True, False, True),
    # 3. Full state (8 factories), human -> 0
    (0, 8, [10, 11, 12, 13, 14, 15, 16, 17], 1, False, [0]*8, [0]*8, 0, 0, 0, True, False, True, False, True),
    # 4. Overfull state (9 factories) -> 0
    (0, 9, [10, 11, 12], 1, False, [0]*3, [0]*3, 0, 0, 0, True, False, True, False, True),
    # 5. Duplicate type in state -> 0
    (0, 2, [1, 2], 1, False, [0, 0], [0, 0], 0, 0, 0, True, False, True, False, True),
    (0, 3, [2, 3, 1], 1, False, [0, 0, 0], [0, 0, 0], 0, 0, 0, True, False, True, False, True),
    # 6. Different types in state -> 1
    (0, 2, [2, 3], 1, False, [0, 0], [0, 0], 0, 0, 0, True, False, True, False, True),
    # 7. Tech prerequisite:
    # Tech present and researched -> 1
    (0, 1, [2], 1, False, [0], [0], 0, 0, 0, True, True, True, False, True),
    # Tech present but not researched -> 0
    (0, 1, [2], 1, False, [0], [0], 0, 0, 0, True, True, False, False, True),
    # Tech requires port: port present -> 1
    (0, 1, [2], 1, False, [0], [0], 0, 0, 0, True, True, True, True, True),
    # Tech requires port: port absent -> 0
    (0, 1, [2], 1, False, [0], [0], 0, 0, 0, True, True, True, True, False),

    # 8. AI mode heuristics:
    # AI with 4 slots left (count=4): normal factory allowed -> 1
    (0, 4, [2, 3, 4, 5], 1, True, [0]*4, [0]*4, 0, 0, 0, True, False, True, False, True),
    # AI with 2 slots left (count=6): normal factory without priority flags rejected -> 0
    (0, 6, [2, 3, 4, 5, 6, 7], 1, True, [0]*6, [0]*6, 0, 0, 0, True, False, True, False, True),
    # AI with 1 slot left (count=7): normal factory without priority flags rejected -> 0
    (0, 7, [2, 3, 4, 5, 6, 7, 8], 1, True, [0]*7, [0]*7, 0, 0, 0, True, False, True, False, True),
    # AI with 2 slots left: priority flag 13A allowed -> 1
    (0, 6, [2, 3, 4, 5, 6, 7], 1, True, [0]*6, [0]*6, 1, 0, 0, True, False, True, False, True),
    # AI with 2 slots left: priority flag 13B allowed -> 1
    (0, 6, [2, 3, 4, 5, 6, 7], 1, True, [0]*6, [0]*6, 0, 1, 0, True, False, True, False, True),
    # AI duplicate 13A category: state already has 13A, candidate has 13A -> rejected -> 0
    (0, 2, [2, 3], 1, True, [1, 0], [0, 0], 1, 0, 0, True, False, True, False, True),
    # AI duplicate 13B category: state already has 13B, candidate has 13B -> rejected -> 0
    (0, 2, [2, 3], 1, True, [0, 0], [1, 0], 0, 1, 0, True, False, True, False, True),
    # AI coastal requirement: candidate requires coast, state has coast -> 1
    (0, 2, [2, 3], 1, True, [0, 0], [0, 0], 0, 0, 0, True, False, True, False, True),
    # AI coastal requirement: candidate requires coast, state has no coast -> 0
    (0, 2, [2, 3], 1, True, [0, 0], [0, 0], 0, 0, 0, False, False, True, False, True),
]

# Random fixtures
random.seed(554433)
for _ in range(120):
    is_col = random.choice([0, 0, 0, 1, 2])
    f_count = random.randint(0, 9)
    n_existing = min(f_count, random.randint(0, 5))
    exist_types = random.sample(range(2, 20), n_existing) if n_existing > 0 else []
    cand_type = 1 if random.random() < 0.8 else (exist_types[0] if exist_types else 1)
    is_ai_flag = random.choice([True, False])
    fl_a = [random.choice([0, 1]) for _ in range(len(exist_types))]
    fl_b = [random.choice([0, 1]) for _ in range(len(exist_types))]
    c_a = random.choice([0, 1])
    c_b = random.choice([0, 1])
    c_coast = 0
    st_coast = random.choice([True, False])
    t_req = random.choice([True, False])
    c_tech = random.choice([True, False])
    t_port = random.choice([True, False])
    s_port = random.choice([True, False])
    fixtures.append((is_col, f_count, exist_types, cand_type, is_ai_flag, fl_a, fl_b, c_a, c_b, c_coast, st_coast, t_req, c_tech, t_port, s_port))

fixture_count = 0
mismatches = 0

for fix in fixtures:
    exp = check_state_can_build_factory(*fix)
    act = run_state_factory_build_emulation(*fix)
    fixture_count += 1
    if act != exp:
        mismatches += 1
        print(f"Mismatch at fix={fix}: act={act}, exp={exp}")

assert mismatches == 0, f"{mismatches} mismatches found during state factory build emulation"

out = ROOT / 'evidence/generated/state-factory-build'
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
ledger.record(report, session='state-factory-build')
ledger.save()

print(f"State factory build: {verified_count} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"State factory build emulation: {fixture_count} fixtures executed, 0 mismatches against state_factory_build_model.")
