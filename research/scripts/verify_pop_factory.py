#!/usr/bin/env python3
"""Check factory instructions/RTTI/vtable links; native lifecycles are separate."""
import hashlib
import json
from pathlib import Path
import struct
from reverify.ledger import Ledger
from reverify.verifier import Claim,Verifier

ROOT=Path(__file__).resolve().parents[1]
data=(ROOT.parent/'base-game/v2game.exe').read_bytes()
assert hashlib.sha256(data).hexdigest()=='62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'
base=0x400000;claims=[]
for address,length,mnemonic,operand in (
    (0x4b8c87,6,'mov','ecx, dword ptr [edi + 0x3d4]'),
    (0x4b8c92,2,'call','edx'),
    (0x4b8c96,2,'jne','0x4b8c9d'),
    (0x4b8c98,2,'mov','eax, edi'),
    (0x4b8d5c,5,'call','0x4b8c80'),
    (0x4b8d6e,5,'call','0x954a40'),
    (0x4b8d82,3,'mov','edi, dword ptr [esi + 0x28]'),
    (0x4b8d85,3,'shl','edi, 4'),
    (0x4b8d88,6,'add','edi, dword ptr [ebx + 0x194]'),
    (0x4b8d8e,5,'push','0x288'),
    (0x4b8d9a,5,'call','0xaae9af'),
    (0x4b8dba,5,'call','0x955450'),
    (0x4b8dc3,6,'mov','dword ptr [esi + 0x278], ecx'),
    (0x4b8dc9,10,'mov','dword ptr [esi + 0x27c], 0'),
    (0x4b8dd3,7,'mov','byte ptr [esi + 0x280], 0'),
    (0x4b8de4,3,'mov','dword ptr [edi + 4], esi'),
    (0x4b8de7,3,'mov','dword ptr [edi + 8], edx'),
    (0x4b8df2,6,'mov','dword ptr [eax + 0x27c], esi'),
    (0x4b8dfa,2,'mov','dword ptr [edi], esi'),
    (0x4b8e0c,5,'call','0x955ae0'),
    (0x4b8e23,5,'mov','eax, dword ptr [0xf09568]'),
    (0x4b8e2a,1,'inc','eax'),
    (0x4b8e2b,5,'mov','dword ptr [0xf09568], eax'),
    (0x4b8e39,4,'mov','dword ptr [esp + 0x1c], ecx'),
    (0x4b8e40,8,'mov','dword ptr [esp + 0x1c], 0x2e'),
    (0x4b8e48,2,'call','edx'),
    (0x4b8e4d,5,'call','0x955d90'),
    (0x4b8e53,5,'call','0x955f20'),
    (0x4b8e6e,3,'ret','8'),
    (0x954aca,5,'call','0x96bb70'),
    (0x96bb8b,5,'mov','eax, dword ptr [0x1258a2c]'),
    (0x96bb96,2,'jne','0x96bbd8'),
    (0x58cfd0,2,'xor','al, al'),
    (0x58cfd2,1,'ret',''),
):
    claims.append(dict(id=f'pop_factory_{address:x}',kind='instructions',space='rva',offset=hex(address-base),base=hex(address),arch='x86',length=length,mnemonics=[mnemonic],operands=[operand]))
for tag,name,td,col,hierarchy,vt in (
    ('null_type',b'.?AVCNullPopType@@\0',0xf1f2c8,0xe6723c,0xe67250,0xe36618),
    ('pop_type',b'.?AVCPopType@@\0',0xf1f2e4,0xe6728c,0xe672a0,0xe365f8),
):
    claims.extend([
        dict(id=f'pop_factory_{tag}_name',kind='bytes_at',space='rva',offset=hex(td+8-base),expected=name.hex()),
        dict(id=f'pop_factory_{tag}_locator',kind='bytes_at',space='rva',offset=hex(col-base),expected=struct.pack('<5I',0,0,0,td,hierarchy).hex()),
        dict(id=f'pop_factory_{tag}_vtable_link',kind='u32_at',space='rva',offset=hex(vt-4-base),expected=col),
    ])
for tag,address,value in (('cpop_registration_slot',0xe36440,0x9c1390),('null_type_predicate_slot',0xe36630,0x58cfd0),('pop_type_predicate_slot',0xe36610,0xa31490)):
    claims.append(dict(id='pop_factory_'+tag,kind='u32_at',space='rva',offset=hex(address-base),expected=value))
report=Verifier(data).verify_all([Claim.from_dict(c) for c in claims])
assert all(x['verdict']=='VERIFIED' for x in report['results']),report
out=ROOT/'evidence/generated/pop-factory';out.mkdir(parents=True,exist_ok=True)
for name,value in [('claims.json',claims),('reverify.json',report)]:
    (out/name).write_text(json.dumps(value,indent=2)+'\n')
ledger=Ledger.for_bytes(data,directory=ROOT/'.reverify');ledger.record(report,session='pop-factory-instructions-and-virtual-links');ledger.save()
print(f'POP factory: {len(claims)} instruction/RTTI/vtable checks; native lifecycle evidence separate.')
