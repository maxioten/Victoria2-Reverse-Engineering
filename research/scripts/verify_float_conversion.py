#!/usr/bin/env python3
"""Verify static conversion dispatch and correction instructions; no x87 emulation claim."""
import hashlib
import json
from pathlib import Path
from reverify.ledger import Ledger
from reverify.verifier import Claim, Verifier

ROOT=Path(__file__).resolve().parents[1]
data=(ROOT.parent/'base-game/v2game.exe').read_bytes()
digest=hashlib.sha256(data).hexdigest()
assert digest=='62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'
claims=[]
for address,length,mnemonic,operand in (
    (0xb31c00,7,'cmp','dword ptr [0x13f3be0], 0'),
    (0xb31c07,2,'je','0xb31c36'),
    (0xb31c1c,7,'cmp','dword ptr [0x13f3be0], 0'),
    (0xb31c23,2,'je','0xb31c36'),
    (0xb31c28,3,'fnstcw','word ptr [esp]'),
    (0xb31c2c,4,'and','ax, 0x7f'),
    (0xb31c34,2,'je','0xb31c09'),
    (0xb31c3f,2,'fld','st(0)'),
    (0xb31c49,4,'fild','qword ptr [esp + 0x10]'),
    (0xb31c59,2,'fsubp','st(1)'),
    (0xb31c71,3,'adc','eax, 0'),
    (0xb31c78,3,'adc','edx, 0'),
    (0xb31c89,3,'sbb','eax, 0'),
    (0xb31c90,3,'sbb','edx, 0'),
    (0xb31caa,1,'ret',''),
    (0xb31c55,2,'test','eax, eax'),
    (0xb31c57,2,'je','0xb31c95'),
    (0xb31c95,4,'mov','edx, dword ptr [esp + 0x14]'),
    (0xb31c99,6,'test','edx, 0x7fffffff'),
    (0xb31c9f,2,'jne','0xb31c59'),
    (0xb31ca1,4,'fstp','dword ptr [esp + 0x18]'),
    (0xb31ca5,4,'fstp','dword ptr [esp + 0x18]'),
):
    claims.append({'id':f'float_conversion_{address:x}','kind':'instructions','space':'rva',
                   'offset':hex(address-0x400000),'base':hex(address),'arch':'x86','length':length,
                   'mnemonics':[mnemonic],'operands':[operand]})
report=Verifier(data).verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict']=='VERIFIED' for r in report['results']),[
    r for r in report['results'] if r['verdict']!='VERIFIED']
out=ROOT/'evidence/generated/float-conversion';out.mkdir(parents=True,exist_ok=True)
for name,value in [('claims.json',claims),('reverify.json',report)]:
    (out/name).write_text(json.dumps(value,indent=2)+'\n')
ledger=Ledger.for_bytes(data,directory=ROOT/'.reverify')
ledger.record(report,session='float-conversion-dispatch-and-integer-correction');ledger.save()
print('Float conversion: 22 static dispatch/correction checks; native receipt is separate.')
