#!/usr/bin/env python3
"""Full original 964370 with real size, balance and integer callees, no stubs."""
import hashlib
import itertools
import json
from pathlib import Path
import struct
import pefile
import unicorn
from unicorn.x86_const import *
from reverify.ledger import Ledger
from reverify.verifier import Claim,Verifier
from pop_merge_model import merge
from integer_model import MASK

ROOT=Path(__file__).resolve().parents[1]
data=(ROOT.parent/'base-game/v2game.exe').read_bytes();digest=hashlib.sha256(data).hexdigest()
assert digest=='62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'
pe=pefile.PE(data=data);base=0x400000;claims=[]
for at,length,mnemonic,operand in (
    (0x964395,3,'add','eax, dword ptr [ebx + 0x58]'),
    (0x96439e,6,'je','0x96442b'),
    (0x9643bf,5,'call','0xac9f20'),
    (0x9643ca,5,'and','eax, 0xffff8000'),
    (0x9643ec,5,'call','0xac9f20'),
    (0x9643f5,5,'and','eax, 0xffff8000'),
    (0x96441e,5,'call','0xac02a0'),
    (0x964423,6,'mov','dword ptr [edi + 0x12c], edx'),
    (0x964435,6,'mov','dword ptr [edi + 0x128], eax'),
    (0x964483,5,'call','0x955fd0'),
    (0x964499,7,'add','dword ptr [edi + eax*4 + 0x158], ecx'),
    (0x9644b6,5,'mov','esi, 2'),
    (0x9644c1,5,'call','0x95a5f0'),
    (0x9644d6,3,'ret','8'),
    (0x95a617,6,'add','dword ptr [eax + 0x180], edx'),
    (0x95a637,10,'mov','dword ptr [eax + 0x180], 0xffffffff'),
    (0x95a641,10,'mov','dword ptr [eax + 0x184], 0x7fffffff'),
    (0x95a659,7,'add','dword ptr [eax + esi*8 + 0x1d8], edx'),
    (0x95a667,6,'add','dword ptr [eax + 0x218], edx'),
    (0x95a687,10,'mov','dword ptr [eax + 0x180], 0'),
):
    claims.append(dict(id=f'merge_{at:x}',kind='instructions',space='rva',offset=hex(at-base),base=hex(at),arch='x86',length=length,mnemonics=[mnemonic],operands=[operand]))
report=Verifier(data).verify_all([Claim.from_dict(c) for c in claims]);assert all(r['verdict']=='VERIFIED' for r in report['results']),report
u=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_32);size=(pe.OPTIONAL_HEADER.SizeOfImage+4095)&~4095
u.mem_map(base,size);u.mem_write(base,pe.get_memory_mapped_image());u.mem_protect(base,size,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
arena,stack,stop=0x20000000,0x20100000,0x21000000
u.mem_map(arena,65536);u.mem_map(stack,65536);u.mem_map(stop,4096);u.mem_map(0,4096)
src,dst,kind,region_a,region_b=[arena+i*0x1000 for i in range(5)]
def put(address,*values):u.mem_write(address,struct.pack('<'+'I'*len(values),*[v&0xffffffff for v in values]))
def qword(address,value):u.mem_write(address,struct.pack('<Q',value&MASK))
def guard(emu,access,address,length,value,_):
    assert arena<=address and address+length<=arena+65536 or stack<=address and address+length<=stack+65536 or address==0 and length==4,hex(address)
u.hook_add(unicorn.UC_HOOK_MEM_WRITE,guard)
allowed={0x964370,0xac02a0,0xac9f20,0x955fd0,0x95a5f0};calls=[]
def call(emu,address,length,_):assert address in allowed,hex(address);calls.append(hex(address))
for at in allowed|{0x4c25b0,0x4ee550,0x4d1020,0xaae9af,0xaae91b}:u.hook_add(unicorn.UC_HOOK_CODE,call,begin=at,end=at)
preserved={UC_X86_REG_EBX:0x12345678,UC_X86_REG_ESI:0x23456789,UC_X86_REG_EDI:dst,UC_X86_REG_EBP:0x456789ab}
attributes=[0,1,32768,MASK,0x7fffffffffffffff,0x8000000000000000]
sizes=[(0,0),(0,17),(1,0),(1,1),(1000,17),(2000000,1999999),(2000001,2000000)]
balances=[(0,0),(32768000,11),(MASK,7),(1,0x7fffffffffffffff),(0x8000000000000000,MASK)]
cases=[];wrapped_mean_counterexamples=0
for (s,d),sa,da,(sb,db),mode in itertools.product(sizes,attributes,attributes,balances,range(3)):
    u.mem_write(arena,bytes(65536));u.mem_write(stack,bytes(65536));put(0,0xcafebabe)
    for obj,n,reg,attr,balance in ((src,s,region_a,sa,sb),(dst,d,region_b,da,db)):
        put(obj+0x58,n,77,n,reg,kind);qword(obj+0x128,attr);qword(obj+0x180,balance)
        put(obj+0x158,*range(100,109));qword(obj+0x1e8,MASK-3);qword(obj+0x218,MASK-5)
    put(region_a+0x12c,1);put(region_b+0x12c,2 if mode==2 else 1)
    before=bytes(u.mem_read(arena,65536));expected=bytearray(before)
    result=merge(s,d,sa,da,sb,db,9 if mode==0 else (2 if mode==2 else 1))
    for off in (0x58,0x60):struct.pack_into('<I',expected,dst-arena+off,result['size'])
    struct.pack_into('<I',expected,dst-arena+0x5c,result['previous_size'])
    for off,value in ((0x128,result['attribute']),(0x180,result['balance']),(0x1e8,(MASK-3+sb)&MASK),(0x218,(MASK-5+sb)&MASK)):
        struct.pack_into('<Q',expected,dst-arena+off,value)
    if result['event']<9:struct.pack_into('<I',expected,dst-arena+0x158+4*result['event'],100+result['event']+s)
    sp=stack+0xf000;put(sp,stop,src,mode!=0)
    for reg,value in preserved.items():u.reg_write(reg,value)
    u.reg_write(UC_X86_REG_ESP,sp);calls.clear();u.emu_start(0x964370,stop,count=10000)
    assert u.reg_read(UC_X86_REG_EIP)==stop and u.reg_read(UC_X86_REG_ESP)==sp+12
    assert all(u.reg_read(reg)==value for reg,value in preserved.items())
    assert bytes(u.mem_read(0,4))==struct.pack('<I',0xcafebabe)
    actual=bytes(u.mem_read(arena,65536))
    assert actual==expected,(s,d,hex(sa),hex(da),hex(sb),hex(db),mode,[hex(i) for i,(a,b) in enumerate(zip(actual,expected)) if a!=b][:12])
    if s+d:
        from integer_model import signed,trunc_div
        naive=trunc_div(s*signed(sa)+d*signed(da),s+d)&MASK
        wrapped_mean_counterexamples+=naive!=result['attribute']
    cases.append(dict(source_size=s,destination_size=d,source_attribute=hex(sa),destination_attribute=hex(da),source_balance=hex(sb),destination_balance=hex(db),mode=mode,result=result,calls=list(calls),arena_sha256=hashlib.sha256(actual).hexdigest()))
assert wrapped_mean_counterexamples>0
out=ROOT/'evidence/generated/pop-merge';out.mkdir(parents=True,exist_ok=True)
for name,value in [('claims.json',claims),('reverify.json',report),('emulation.json',dict(binary_sha256=digest,cases=cases,mismatches=0,wrapped_mean_counterexamples=wrapped_mean_counterexamples,scope='Full original964370,actual955FD0/95A5F0/integer helpers;type40zero,nonnegative bounded sizes,null optional/global statistics. Full64KiB fixture,source unchanged,ABI/FS0 checked. Modular weighted mean and balance saturation/clamping/counters;not full consumer/live world.'))]:
    (out/name).write_text(json.dumps(value,indent=2)+'\n')
ledger=Ledger.for_bytes(data,directory=ROOT/'.reverify');ledger.record(report,session='pop-merge-complete-helper');ledger.save()
print(f'POP merge: {len(claims)} static checks,{len(cases)} complete helper fixtures;{wrapped_mean_counterexamples} counterexamples to naive weighted mean.')
