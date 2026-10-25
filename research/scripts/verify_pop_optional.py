#!/usr/bin/env python3
"""Check optional-resource instruction claims; dynamic behavior is in native-growth."""
import hashlib
import json
from pathlib import Path
import struct
from reverify.ledger import Ledger
from reverify.verifier import Claim,Verifier

ROOT=Path(__file__).resolve().parents[1]
data=(ROOT.parent/'base-game/v2game.exe').read_bytes()
assert hashlib.sha256(data).hexdigest()=='62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'
claims=[]
for address,length,mnemonic,operand in (
    (0x95493b,6,'mov','dword ptr [esi], 0xdfbddc'),
    (0x954953,5,'call','0xab6e30'),
    (0x954960,5,'call','0x423920'),
    (0x954995,5,'call','0xab6e30'),
    (0x9549a2,5,'call','0x423920'),
    (0x9549a7,6,'fld','qword ptr [0xe45830]'),
    (0x954a00,5,'call','0xb31c36'),
    (0x95535f,5,'call','0xaae9af'),
    (0x955373,5,'call','0x954910'),
    (0x95537c,6,'mov','dword ptr [edi + 0x1d4], eax'),
    (0x955d4e,5,'call','0xaae91b'),
    (0x955d70,5,'call','0xaae91b'),
    (0x955d82,5,'call','0xaae91b'),
    (0x955880,5,'call','0x954910'),
    (0x95588d,6,'mov','dword ptr [edi + 0x1d4], eax'),
    (0x9558a1,5,'call','0x47dbb0'),
    (0x95568c,6,'mov','dword ptr [edi + 0x1d4], esi'),
    (0x955857,6,'cmp','dword ptr [ebx + 0x1d4], esi'),
    (0x95585d,6,'je','0x9558a6'),
    (0x95585f,6,'cmp','dword ptr [edi + 0x1d4], esi'),
):
    claims.append(dict(id=f'pop_optional_{address:x}',kind='instructions',space='rva',offset=hex(address-0x400000),base=hex(address),arch='x86',length=length,mnemonics=[mnemonic],operands=[operand]))
claims.extend([
    dict(id='pop_optional_goods_pool_name',kind='bytes_at',space='rva',offset='0xb110c4',expected=b'.?AVCGoodsPool@@\0'.hex()),
    dict(id='pop_optional_goods_pool_locator',kind='bytes_at',space='rva',offset='0xa4c794',expected=struct.pack('<5I',0,0,0,0xf110bc,0xe4c7a8).hex()),
    dict(id='pop_optional_goods_pool_vtable_link',kind='u32_at',space='rva',offset='0x9fbdd8',expected=0xe4c794),
])
report=Verifier(data).verify_all([Claim.from_dict(c) for c in claims])
assert all(x['verdict']=='VERIFIED' for x in report['results']),report
out=ROOT/'evidence/generated/pop-optional';out.mkdir(parents=True,exist_ok=True)
for name,value in [('claims.json',claims),('reverify.json',report)]:
    (out/name).write_text(json.dumps(value,indent=2)+'\n')
ledger=Ledger.for_bytes(data,directory=ROOT/'.reverify');ledger.record(report,session='pop-optional-resource-instructions');ledger.save()
print(f'POP optional: {len(claims)} static checks; native lifecycle evidence is separate.')
