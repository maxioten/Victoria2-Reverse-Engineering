#!/usr/bin/env python3
"""Inventory the full bounded normal-return CFG of the scheduled POP update.

Calls are opaque and may mutate any state. No exception edges or path constraints
are inferred, and a decoded memory operand is not a recovered C++ field.
"""
import hashlib
import json
from pathlib import Path

import capstone
import pefile
from reverify.ledger import Ledger
from reverify.verifier import Claim, Verifier

ROOT = Path(__file__).resolve().parents[1]
data = (ROOT.parent / 'base-game/v2game.exe').read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'
pe = pefile.PE(data=data)
base, entry, end = pe.OPTIONAL_HEADER.ImageBase, 0x957ea0, 0x958def
decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
decoder.detail = True
claims = []
for address, length, mnemonic, operand in (
    (0x957efc,5,'call','0x967f50'),
    (0x957fb1,5,'call','0x4e7db0'),
    (0x957fdf,5,'call','0x534810'),
    (0x958014,5,'call','0x534930'),
    (0x958394,5,'call','0x534810'),
    (0x9584c8,5,'call','0x955fd0'),
    (0x958563,5,'call','0xb31c36'),
    (0x958571,5,'call','0xb31c36'),
    (0x958cf5,5,'call','0x43a6a0'),
    (0x958d2f,5,'call','0x95a5b0'),
    (0x958d5c,5,'call','0x9666b0'),
    (0x958d99,5,'call','0x95dec0'),
    (0x9581e5,2,'call','edx'),
    (0x9583de,2,'call','eax'),
    (0x958c1a,2,'call','eax'),
    (0x957fc0,6,'jne','0x958dd6'),
    (0x957ff3,6,'jle','0x958dd6'),
    (0x95823f,5,'call','0xb31c00'),
    (0x958dd0,6,'add','dword ptr [edi + 0x158], ebx'),
    (0x958dec,3,'ret','8'),
    (0xb31c12,3,'fstp','qword ptr [esp]'),
    (0xb31c15,5,'cvttsd2si','eax, qword ptr [esp]'),
    (0xb31c45,4,'fistp','qword ptr [esp + 0x10]'),
):
    claims.append({'id':f'pop_update_{address:x}', 'kind':'instructions', 'space':'rva',
                   'offset':hex(address-base), 'base':hex(address), 'arch':'x86',
                   'length':length, 'mnemonics':[mnemonic], 'operands':[operand]})
report = Verifier(data).verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED']

nodes, pending, occupied = {}, [entry], {}
calls, writes, exits = [], [], []
while pending:
    address = pending.pop()
    if address in nodes:
        continue
    assert entry <= address < end, hex(address)
    ins = next(decoder.disasm(pe.get_data(address-base, 15), address, count=1))
    assert ins.address + ins.size <= end
    for byte in range(address, address + ins.size):
        assert byte not in occupied, (hex(address), hex(occupied.get(byte, 0)))
        occupied[byte] = address
    following, edges = address + ins.size, []
    if ins.group(capstone.CS_GRP_RET):
        exits.append(hex(address))
    elif ins.group(capstone.CS_GRP_JUMP):
        assert ins.operands[0].type == capstone.x86.X86_OP_IMM, hex(address)
        target = ins.operands[0].imm
        edges = [target] if ins.mnemonic == 'jmp' else [following, target]
    else:
        assert not ins.group(capstone.CS_GRP_INT), hex(address)
        edges = [following]
    if ins.group(capstone.CS_GRP_CALL):
        direct = ins.operands[0].type == capstone.x86.X86_OP_IMM
        calls.append({'site_va':hex(address), 'target_va':hex(ins.operands[0].imm) if direct else None,
                      'operand':ins.op_str, 'direct':direct})
    for operand in ins.operands:
        if operand.type == capstone.x86.X86_OP_MEM and operand.access & capstone.CS_AC_WRITE:
            writes.append({'site_va':hex(address), 'mnemonic':ins.mnemonic, 'operands':ins.op_str,
                           'base_register':ins.reg_name(operand.mem.base),
                           'index_register':ins.reg_name(operand.mem.index),
                           'displacement':operand.mem.disp, 'size':operand.size,
                           'scope':'Decoded operand only; no alias, object identity or callee effects inferred.'})
    nodes[address] = {'va':hex(address), 'rva':hex(address-base), 'bytes':ins.bytes.hex(),
                      'mnemonic':ins.mnemonic, 'operands':ins.op_str,
                      'successors':[hex(a) for a in edges]}
    pending.extend(edges)

assert exits == ['0x958dec'], exits
assert len(calls) == 71, len(calls)
assert all(int(c['site_va'],16) in nodes for c in calls)
call_by_address = {int(c['site_va'],16):c for c in calls}
assert call_by_address[0x95823f]['target_va'] == '0xb31c00'
assert sum(not c['direct'] for c in calls) == 6
out = ROOT / 'evidence/generated/pop-update'
out.mkdir(parents=True, exist_ok=True)
inventory = {
    'binary_sha256':digest, 'preferred_image_base':hex(base), 'entry_va':hex(entry),
    'exclusive_end_va':hex(end), 'instruction_count':len(nodes),
    'covered_bytes':len(occupied), 'normal_return_sites':exits,
    'call_sites':sorted(calls, key=lambda c:int(c['site_va'],16)),
    'memory_write_operands':sorted(writes, key=lambda c:int(c['site_va'],16)),
    'nodes':[nodes[a] for a in sorted(nodes)],
    'scope':'Complete bounded syntactic CFG from entry under opaque normal-return CALL model. '
            'Branches are not solved for feasibility; exceptions, callee effects, indirect call targets, '
            'runtime frequency, field identities and whole-function semantic equivalence are unproven. '
            'PUSH/implicit memory effects are not a complete memory-write inventory.',
}
for name, value in [('claims.json',claims),('reverify.json',report),('cfg.json',inventory)]:
    (out / name).write_text(json.dumps(value,indent=2) + '\n')
ledger = Ledger.for_bytes(data,directory=ROOT / '.reverify')
ledger.record(report,session='pop-update-normal-return-cfg')
ledger.save()
print(f'POP update CFG: {len(nodes)} instructions, {len(calls)} calls; '
      f'{sum(not c["direct"] for c in calls)} indirect; {len(claims)} instruction checks.')
