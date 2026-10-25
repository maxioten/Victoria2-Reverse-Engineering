#!/usr/bin/env python3
"""Execute original transfer entry with actual size, arithmetic and region callees.

Only nonempty destinations and type flag +0x40=0 are tested. No callee stubs.
"""
import hashlib
import json
from pathlib import Path
import random
import struct
import pefile
import unicorn
from unicorn.x86_const import (
    UC_X86_REG_EAX,UC_X86_REG_EBX,UC_X86_REG_EBP,UC_X86_REG_EDI,
    UC_X86_REG_EIP,UC_X86_REG_ESI,UC_X86_REG_ESP,
)
from reverify.ledger import Ledger
from reverify.verifier import Claim,Verifier
from pop_transfer_model import transfer,MASK32

ROOT=Path(__file__).resolve().parents[1]
data=(ROOT.parent/'base-game/v2game.exe').read_bytes()
digest=hashlib.sha256(data).hexdigest()
assert digest=='62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'
pe=pefile.PE(data=data);base=pe.OPTIONAL_HEADER.ImageBase
claims=[]
for address,length,mnemonic,operand in (
    (0x5345b4,5,'call','0x955a00'),
    (0x5345bc,3,'cmp','dword ptr [ebp + 0x10], eax'),
    (0x5345c1,3,'mov','dword ptr [ebp + 0x10], eax'),
    (0x5345f5,4,'cmp','byte ptr [ebp + 0x14], 0'),
    (0x53460d,5,'call','0x955fd0'),
    (0x53461d,7,'add','dword ptr [esi + eax*4 + 0x158], ebx'),
    (0x53464a,5,'call','0xac02a0'),
    (0x53465f,5,'call','0xac9f20'),
    (0x534670,4,'shrd','eax, edx, 0xf'),
    (0x534674,3,'sar','edx, 0xf'),
    (0x534683,6,'mov','dword ptr [esi + 0x184], ebx'),
    (0x534689,6,'mov','dword ptr [esi + 0x180], ecx'),
    (0x5346ad,2,'sub','ecx, eax'),
    (0x5346af,2,'sbb','esi, edx'),
    (0x5346e0,5,'call','0x955fd0'),
    (0x5346f3,7,'add','dword ptr [edi + eax*4 + 0x158], ebx'),
    (0x5346fe,5,'call','0x955f20'),
    (0x534709,3,'ret','0x10'),
    (0x53483d,3,'add','edi, 0x34'),
    (0x53486b,6,'add','ebx, 0x278'),
    (0x5348de,5,'call','0x5345a0'),
    (0x534960,3,'add','edi, 0x44'),
    (0x534986,3,'cmp','dword ptr [ecx - 8], edx'),
    (0x53498d,3,'cmp','edx, dword ptr [ebx + 0x70]'),
    (0x534995,3,'cmp','edx, dword ptr [ebx + 0x6c]'),
    (0x534a0f,5,'call','0x5345a0'),
):
    claims.append({'id':f'pop_transfer_{address:x}','kind':'instructions','space':'rva',
                   'offset':hex(address-base),'base':hex(address),'arch':'x86','length':length,
                   'mnemonics':[mnemonic],'operands':[operand]})
report=Verifier(data).verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict']=='VERIFIED' for r in report['results']),[
    r for r in report['results'] if r['verdict']!='VERIFIED']
emu=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_32)
image_size=(pe.OPTIONAL_HEADER.SizeOfImage+4095)&~4095
emu.mem_map(base,image_size);emu.mem_write(base,pe.get_memory_mapped_image())
emu.mem_protect(base,image_size,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
arena,stack,sentinel=0x20000000,0x20100000,0x21000000
emu.mem_map(arena,0x10000,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
emu.mem_map(stack,0x10000,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
emu.mem_map(sentinel,0x1000,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
source,destination,country=arena,arena+0x1000,arena+0x2000
from_region,to_region,kind=arena+0x3000,arena+0x4000,arena+0x5000
calls=[]
def put(address,*values):emu.mem_write(address,struct.pack('<'+'I'*len(values),*[v&MASK32 for v in values]))
def qword(address,value):emu.mem_write(address,struct.pack('<Q',value))
def guard(uc,access,address,size,value,_):
    assert (arena<=address and address+size<=arena+0x10000) or (stack<=address and address+size<=stack+0x10000),hex(address)
def boundary(uc,address,size,_):
    assert address in (0x955fd0,0xac02a0,0xac9f20,0x955f20),hex(address)
    calls.append(hex(address))
emu.hook_add(unicorn.UC_HOOK_MEM_WRITE,guard)
for address in (0x955fd0,0xac02a0,0xac9f20,0x955f20,0x955a00,0x4c25b0,0x4d1020,0x4ee550):
    emu.hook_add(unicorn.UC_HOOK_CODE,boundary,begin=address,end=address)
preserved={UC_X86_REG_EBX:0x12345678,UC_X86_REG_ESI:0x23456789,
           UC_X86_REG_EDI:0x34567890,UC_X86_REG_EBP:0x45678901}
cases=[]
def run(s,d,a,sc,dc,context,old_region_choice,pending,flag):
    modeled=transfer(s,d,a,sc,dc)
    emu.mem_write(arena,bytes(0x10000));emu.mem_write(source,b'\xa5'*0x300);emu.mem_write(destination,b'\x5a'*0x300)
    source_region=0 if context==0 else from_region
    old_region=(0,from_region,to_region)[old_region_choice]
    put(country+0x20,77);put(from_region+0x12c,77 if context!=2 else 88);put(to_region+0x12c,99)
    put(source+0x58,s,0x12345678,s,source_region,kind)
    put(destination+0x58,d,0x23456789,d,old_region,kind)
    qword(source+0x180,sc);qword(destination+0x180,dc);put(destination+0x274,pending)
    put(source+0x158,*range(100,109));put(destination+0x158,*range(200,209))
    expected=bytearray(emu.mem_read(arena,0x10000))
    def expected_word(address,value):struct.pack_into('<I',expected,address-arena,value&MASK32)
    def expected_qword(address,value):struct.pack_into('<Q',expected,address-arena,value)
    expected_word(destination+0x58,modeled['destination_size'])
    expected_word(destination+0x5c,d);expected_word(destination+0x60,modeled['destination_size'])
    destination_index=2 if context==2 else 1
    source_index=6 if flag&0xff else (7 if context==2 else 8)
    expected_word(destination+0x158+destination_index*4,200+destination_index+modeled['destination_event_delta'])
    if s:
        expected_word(source+0x58,modeled['source_size']);expected_word(source+0x5c,s)
        expected_word(source+0x60,modeled['source_size'])
        expected_word(source+0x158+source_index*4,100+source_index+modeled['source_event_delta'])
    expected_qword(source+0x180,modeled['source_balance']);expected_qword(destination+0x180,modeled['destination_balance'])
    expected_word(destination+0x64,source_region)
    if pending and old_region and source_region:
        previous_id=99 if old_region==to_region else (77 if context!=2 else 88)
        if previous_id!=(77 if context!=2 else 88):expected_word(destination+0x274,0)
    initial_sp=stack+0xf000
    put(initial_sp,sentinel,country,destination,a,flag)
    emu.reg_write(UC_X86_REG_ESP,initial_sp);emu.reg_write(UC_X86_REG_EAX,source)
    for reg,value in preserved.items():emu.reg_write(reg,value)
    calls.clear();emu.emu_start(0x5345a0,sentinel,count=2000)
    assert emu.reg_read(UC_X86_REG_EIP)==sentinel and emu.reg_read(UC_X86_REG_ESP)==initial_sp+20
    assert all(emu.reg_read(reg)==value for reg,value in preserved.items())
    assert struct.unpack('<I',emu.mem_read(initial_sp+12,4))[0]==modeled['amount']&MASK32
    actual=bytes(emu.mem_read(arena,0x10000))
    assert actual==expected,(s,d,a,sc,dc,context,flag,[hex(i) for i,(x,y) in enumerate(zip(actual,expected)) if x!=y][:20])
    expected_calls=['0x955fd0']+(['0xac02a0','0xac9f20','0x955fd0'] if s else [])+['0x955f20']
    assert calls==expected_calls,(calls,expected_calls)
    cases.append({'source_size':s,'destination_size':d,'amount_bits':hex(a&MASK32),
                  'source_balance_bits':hex(sc),'destination_balance_bits':hex(dc),'context':context,
                  'old_region_choice':old_region_choice,'pending':pending,'flag_bits':hex(flag),
                  'modeled':modeled,'calls':list(calls),'post_arena_sha256':hashlib.sha256(actual).hexdigest()})

for s in (0,1,5,1000,2000000):
    for d in (1,10,1999999,2000000):
        for a in dict.fromkeys((0,1,s,s+1)):
            for context in (0,1,2):
                for flag in (0,1,0x100,0xff):run(s,d,a,1000000,300,context,2,1,flag)
for s in (5,1000,2000000):
    for a in dict.fromkeys((1,s//2,s)):
        for sc in (0,1,32768,10000000,(1<<48)-1,(1<<63)-1,1<<63,(1<<64)-1):
            for dc in (0,1,(1<<63)-1):run(s,10,a,sc,dc,2,1,0,1)
for s in (0,5,1000):
    for d in (1,1999999):
        for a in (-1,-1000,0x80000000):
            for context in (0,1,2):
                for flag in (0,1,0x100,0xff):run(s,d,a,1000000,500000,context,0,1,flag)
generator=random.Random(20261021)
for _ in range(256):
    run(generator.randrange(1,2000001),generator.randrange(1,2000001),generator.randrange(-10000,2010000),
        generator.getrandbits(64),generator.getrandbits(64),generator.randrange(3),generator.randrange(3),
        generator.randrange(2),generator.choice((0,1,0x100,0xff)))
out=ROOT/'evidence/generated/pop-transfer';out.mkdir(parents=True,exist_ok=True)
for name,value in [('claims.json',claims),('reverify.json',report),('emulation.json',{
    'binary_sha256':digest,'entry_va':'0x5345a0','engine':f'unicorn {unicorn.__version__}',
    'cases':cases,'mismatches':0,'scope':'Complete original core with actual integer arithmetic, size setters and '
    'region setter; distinct objects, source size 0..2000000, destination initially positive, both type flags +0x40=0. '
    'Full 64KiB arena comparison. Empty-destination initialization, wrapper searches/allocation, nonzero type flags, '
    'live game invariants, aliases, exceptions and concurrency excluded.',
})]:(out/name).write_text(json.dumps(value,indent=2)+'\n')
ledger=Ledger.for_bytes(data,directory=ROOT/'.reverify');ledger.record(report,session='pop-transfer-complete-bounded-core');ledger.save()
print(f'POP transfer: {len(cases)} complete core fixtures; actual arithmetic/size/region callees; no mismatches.')
