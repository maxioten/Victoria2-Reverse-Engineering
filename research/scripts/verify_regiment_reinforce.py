#!/usr/bin/env python3
"""Verify CRegiment::CanReinforce against PE32 binary with Reverify and Unicorn.

Routine: 0x005CC4D0..0x005CC529 (90 bytes, 35 instructions).
Vtable slot 20 (+0x50): 0x00DF88D4 in CRegiment vtable (0x00DF8884).
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
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_PROT_ALL, UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_EAX, UC_X86_REG_ECX,
    UC_X86_REG_EDX, UC_X86_REG_EBX, UC_X86_REG_ESI, UC_X86_REG_EDI
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT / 'scripts'))
from regiment_reinforce_model import RegimentReinforceInput, can_regiment_reinforce

bin_path = ROOT.parent / 'base-game/v2game.exe'
data = bin_path.read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_32)

claims = []

# 1. Routine instructions (0x005CC4D0..0x005CC529)
raw_start = pe.get_offset_from_rva(0x005CC4D0 - base)
for insn in md.disasm(data[raw_start:raw_start + 120], 0x005CC4D0):
    claims.append({
        'id': f'regiment_reinforce_insn_{insn.address:x}',
        'kind': 'instructions',
        'space': 'rva',
        'offset': hex(insn.address - base),
        'base': hex(insn.address),
        'arch': 'x86',
        'length': len(insn.bytes),
        'mnemonics': [insn.mnemonic],
        'operands': [insn.op_str]
    })
    if insn.address >= 0x005CC529:
        break

# 2. Vtable slot 20 (+0x50) in CRegiment at 0x00DF88D4
vtable_va = 0x00DF88D4
v_raw = pe.get_offset_from_rva(vtable_va - base)
target_ptr = int.from_bytes(data[v_raw:v_raw + 4], 'little')
assert target_ptr == 0x005CC4D0
claims.append({
    'id': 'regiment_reinforce_vtable_CRegiment',
    'kind': 'bytes_at',
    'space': 'rva',
    'offset': hex(vtable_va - base),
    'base': hex(vtable_va),
    'expected': (0x005CC4D0).to_bytes(4, 'little').hex()
})

# Run Reverify
verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]

# Negative controls and dependent invalidation
wrong = dict(claims[0], id='negative_control_regiment_reinforce', mnemonics=['nop'])
dependent = dict(claims[1], id='negative_dependent_regiment_reinforce', depends_on=['negative_control_regiment_reinforce'])
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

# Allocate scratch memory for synthetic objects, vtables and stack
SCRATCH_BASE = 0x02000000
SCRATCH_SIZE = 0x00100000
uc.mem_map(SCRATCH_BASE, SCRATCH_SIZE, UC_PROT_ALL)

STACK_BASE = SCRATCH_BASE + 0x80000
REG_ADDR = SCRATCH_BASE + 0x1000
POP_ADDR = SCRATCH_BASE + 0x2000
POP_VTABLE = SCRATCH_BASE + 0x3000
POP_STUB_CODE = SCRATCH_BASE + 0x4000
POP_COUNTRY_VAR = SCRATCH_BASE + 0x5000
ACCESS_FLAG_VAR = SCRATCH_BASE + 0x5004

# Wire POP vtable slot 22 (+0x58) -> POP_STUB_CODE
uc.mem_write(POP_ADDR, struct.pack('<I', POP_VTABLE))
uc.mem_write(POP_VTABLE + 0x58, struct.pack('<I', POP_STUB_CODE))

# POP stub:
# mov edx, [esp + 4]
# mov dword ptr [edx], 100
# mov eax, [POP_COUNTRY_VAR]
# mov [edx + 4], eax
# ret 4
pop_stub_bytes = bytes([
    0x8B, 0x54, 0x24, 0x04,                     # mov edx, [esp + 4]
    0xC7, 0x02, 0x64, 0x00, 0x00, 0x00,         # mov dword ptr [edx], 100
    0xA1, *struct.pack('<I', POP_COUNTRY_VAR),  # mov eax, [POP_COUNTRY_VAR]
    0x89, 0x42, 0x04,                           # mov [edx + 4], eax
    0xC2, 0x04, 0x00                            # ret 4
])
uc.mem_write(POP_STUB_CODE, pop_stub_bytes)


def hook_access_check(uc_inst, address, size, user_data):
    if address == 0x005CC2E0:
        val = struct.unpack('<B', uc_inst.mem_read(ACCESS_FLAG_VAR, 1))[0]
        uc_inst.reg_write(UC_X86_REG_EAX, val)
        esp = uc_inst.reg_read(UC_X86_REG_ESP)
        ret = struct.unpack('<I', uc_inst.mem_read(esp, 4))[0]
        uc_inst.reg_write(UC_X86_REG_ESP, esp + 4)
        uc_inst.reg_write(UC_X86_REG_EIP, ret)


uc.hook_add(UC_HOOK_CODE, hook_access_check)


def run_regiment_reinforce_test(inp: RegimentReinforceInput) -> bool:
    # Setup regiment
    if inp.has_home_pop:
        uc.mem_write(REG_ADDR + 0x108, struct.pack('<I', POP_ADDR))
    else:
        uc.mem_write(REG_ADDR + 0x108, struct.pack('<I', 0))

    uc.mem_write(REG_ADDR + 0xC4, struct.pack('<i', inp.regiment_country_id))
    uc.mem_write(POP_COUNTRY_VAR, struct.pack('<i', inp.pop_country_id))
    uc.mem_write(ACCESS_FLAG_VAR, struct.pack('<B', 1 if inp.has_access_corridor else 0))

    ret_addr = SCRATCH_BASE + 0x70000
    uc.mem_write(STACK_BASE - 4, struct.pack('<I', ret_addr))
    uc.reg_write(UC_X86_REG_ESP, STACK_BASE - 4)
    uc.reg_write(UC_X86_REG_ECX, REG_ADDR)

    uc.emu_start(0x005CC4D0, ret_addr)

    res = bool(uc.reg_read(UC_X86_REG_EAX) & 0xFF)
    expected = can_regiment_reinforce(inp)
    assert res == expected, (
        f"Mismatch: inp={inp}, emu={res}, expected={expected}"
    )
    return res


fixtures_run = 0

# Case 1: No home POP (dissolved) -> False
c1 = RegimentReinforceInput(has_home_pop=False, regiment_country_id=1, pop_country_id=1)
assert not run_regiment_reinforce_test(c1)
fixtures_run += 1

# Case 2: Domestic home POP (country match) -> True
c2 = RegimentReinforceInput(has_home_pop=True, regiment_country_id=1, pop_country_id=1)
assert run_regiment_reinforce_test(c2)
fixtures_run += 1

# Case 3: Foreign/occupied province, access corridor open -> True
c3 = RegimentReinforceInput(has_home_pop=True, regiment_country_id=1, pop_country_id=2, has_access_corridor=True)
assert run_regiment_reinforce_test(c3)
fixtures_run += 1

# Case 4: Foreign/occupied province, access corridor blocked -> False
c4 = RegimentReinforceInput(has_home_pop=True, regiment_country_id=1, pop_country_id=2, has_access_corridor=False)
assert not run_regiment_reinforce_test(c4)
fixtures_run += 1

# Comprehensive parametric sweep
for r_cid in [1, 5, 20]:
    for p_cid in [1, 5, 30]:
        for has_pop in [True, False]:
            for acc in [True, False]:
                run_regiment_reinforce_test(RegimentReinforceInput(
                    has_home_pop=has_pop,
                    regiment_country_id=r_cid,
                    pop_country_id=p_cid,
                    has_access_corridor=acc,
                ))
                fixtures_run += 1

# Save receipts
out_dir = ROOT / 'evidence/generated/regiment-reinforce'
out_dir.mkdir(parents=True, exist_ok=True)
(out_dir / 'claims.json').write_text(json.dumps(claims, indent=2) + '\n')
(out_dir / 'reverify.json').write_text(json.dumps(report, indent=2) + '\n')
(out_dir / 'negative-controls.json').write_text(json.dumps(controls, indent=2) + '\n')
(out_dir / 'emulation.json').write_text(json.dumps({
    'binary_sha256': digest,
    'routine_va': hex(0x005CC4D0),
    'fixtures_count': fixtures_run,
    'mismatches': 0
}, indent=2) + '\n')

ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify', file_path=str(bin_path))
ledger.start_run('Verify CRegiment::CanReinforce routine and vtables', session='regiment-reinforce')
ledger.record(report, rnd=1, session='regiment-reinforce')
ledger.finish_run(1, report['grounded'], report['information'])
ledger.save()

print(f"Regiment reinforce: {len(report['results'])} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Regiment reinforce emulation: {fixtures_run} fixtures executed, 0 mismatches against regiment_reinforce_model.")
