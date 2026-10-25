#!/usr/bin/env python3
"""Ground selected consumer/log instructions; full native receipts are separate."""
import hashlib
import json
from pathlib import Path
import capstone
import pefile
from reverify.ledger import Ledger
from reverify.verifier import Claim, Verifier

ROOT=Path(__file__).resolve().parents[1]
data=(ROOT.parent/'base-game/v2game.exe').read_bytes()
digest=hashlib.sha256(data).hexdigest()
assert digest=='62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'
pe=pefile.PE(data=data);image=pe.get_memory_mapped_image();base=0x400000
cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
expected=(
    (0x4ba83a,'cmp','dword ptr [ebx + 0x58], 0'),
    (0x4ba83e,'jle','0x4bad00'),
    (0x4baaf0,'call','0x4b8d30'),
    (0x4baaf9,'call','0x955a00'),
    (0x4bab32,'call','0x955fd0'),
    (0x4bab46,'add','dword ptr [esi + eax*4 + 0x158], edi'),
    (0x4bab5b,'cmp','eax, edx'),
    (0x4bab5d,'jl','0x4bab73'),
    (0x4bab65,'mov','dword ptr [esi + 0x180], ecx'),
    (0x4bab6b,'mov','dword ptr [esi + 0x184], eax'),
    (0x4bab73,'mov','dword ptr [esi + 0x180], edx'),
    (0x4bab79,'mov','dword ptr [esi + 0x184], edx'),
    (0x4bac35,'call','0x444da0'),
    (0x4bac5a,'mov','dword ptr [edx + 0x354], ecx'),
    (0x4bacda,'mov','eax, dword ptr [ebx + 0x58]'),
    (0x4bacdd,'mov','dword ptr [ebx + 0x5c], eax'),
    (0x4bad49,'cmp','dword ptr [ebx + edx + 8], 0'),
    (0x4bad66,'mov','esi, dword ptr [esi + 0x27c]'),
    (0x4bad72,'call','0x4b9250'),
    (0x4bad95,'ret','4'),
    (0x444dab,'cmp','edi, 0xffff'),
    (0x444db1,'jle','0x444db8'),
    (0x444db3,'mov','edi, 0xffff'),
    (0x444dbf,'call','0x445260'),
    (0x444dc7,'call','0x4453b0'),
    (0x444dcf,'add','word ptr [eax], di'),
    (0x444dd2,'cmp','esi, dword ptr [ebp + 0x10]'),
    (0x444dd5,'je','0x444e8f'),
    (0x444e93,'ret','0xc'),
    (0x4452b0,'cmp','eax, dword ptr [edi + 0xc]'),
    (0x4452b3,'jge','0x44536f'),
    (0x4453eb,'cmp','eax, dword ptr [ebx + 0xc]'),
    (0x4453ee,'jge','0x44541c'),
    (0x44541e,'lea','eax, [ebx + 0x10]'),
)
claims=[]
for address,mnemonic,operand in expected:
    instruction=next(cs.disasm(image[address-base:address-base+16],address))
    # Expected meaning is declared above; decoder supplies instruction length only.
    claims.append(dict(id=f'consumer_{address:x}',kind='instructions',space='rva',
        offset=hex(address-base),base=hex(address),arch='x86',length=instruction.size,
        mnemonics=[mnemonic],operands=[operand]))
report=Verifier(data).verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict']=='VERIFIED' for r in report['results']),report
out=ROOT/'evidence/generated/pop-consumer';out.mkdir(parents=True,exist_ok=True)
for name,value in [('claims.json',claims),('reverify.json',report)]:
    (out/name).write_text(json.dumps(value,indent=2)+'\n')
ledger=Ledger.for_bytes(data,directory=ROOT/'.reverify')
ledger.record(report,session='pop-consumer-and-existing-movement-tree');ledger.save()
print(f'POP consumer: {len(claims)} instruction checks; full native evidence has separate scope.')
