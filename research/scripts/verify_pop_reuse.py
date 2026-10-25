#!/usr/bin/env python3
"""Execute initialization and complete reuse/matching wrapper paths without heap allocation."""
import hashlib
import json
from pathlib import Path
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
data=(ROOT.parent/'base-game/v2game.exe').read_bytes();digest=hashlib.sha256(data).hexdigest()
assert digest=='62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'
pe=pefile.PE(data=data);base=pe.OPTIONAL_HEADER.ImageBase
claims=[]
for address,length,mnemonic,operand in (
    (0x955a03,3,'mov','dword ptr [esi + 0x58], ebx'),
    (0x955a06,3,'mov','dword ptr [esi + 0x5c], ebx'),
    (0x955a22,5,'call','0x43a750'),
    (0x955a34,5,'call','0x9beeb0'),
    (0x955a52,5,'call','0x43a750'),
    (0x955a64,5,'call','0x9beeb0'),
    (0x955a69,6,'mov','dword ptr [esi + 0x118], ebx'),
    (0x955a99,6,'mov','dword ptr [esi + 0x274], ebx'),
    (0x955ab1,5,'mov','eax, 0x8000'),
    (0x955ab6,6,'mov','dword ptr [esi + 0x130], eax'),
    (0x955ac2,6,'mov','dword ptr [esi + 0x138], eax'),
    (0x955ada,3,'mov','byte ptr [esi + 0x38], bl'),
    (0x534906,3,'mov','dword ptr [ebx + 0x68], eax'),
    (0x534912,10,'mov','dword ptr [ebx + 0x1d4], 0'),
    (0x53491f,3,'mov','edx, dword ptr [ebp + 8]'),
    (0x534a2e,6,'imul','esi, esi, 0x278'),
):
    claims.append({'id':f'pop_reuse_{address:x}','kind':'instructions','space':'rva','offset':hex(address-base),
                   'base':hex(address),'arch':'x86','length':length,'mnemonics':[mnemonic],'operands':[operand]})
report=Verifier(data).verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict']=='VERIFIED' for r in report['results']),[
    r for r in report['results'] if r['verdict']!='VERIFIED']
emu=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_32)
size=(pe.OPTIONAL_HEADER.SizeOfImage+4095)&~4095
emu.mem_map(base,size);emu.mem_write(base,pe.get_memory_mapped_image())
emu.mem_protect(base,size,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
arena,stack,sentinel=0x20000000,0x20100000,0x21000000
emu.mem_map(arena,0x10000,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
emu.mem_map(stack,0x10000,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
emu.mem_map(0,0x1000,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
emu.mem_map(sentinel,0x1000,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
source,destination,country,kind,other_kind,region=arena,arena+0x1000,arena+0x2000,arena+0x3000,arena+0x3800,arena+0x4000
other_region,source_buffers,destination_buffers,rows=arena+0x4800,arena+0x6000,arena+0x7000,arena+0x8000
vectors=(0x7c,0x8c,0xa4,0xb4)
calls=[]
allowed={0x955a00,0x5345a0,0x43a750,0x9beeb0,0x43ab30,0x7e72f0,0xaae480,
         0x955fd0,0x955f20,0xac02a0,0xac9f20}
def guard(uc,access,address,length,value,_):
    assert (arena<=address and address+length<=arena+0x10000) or (stack<=address and address+length<=stack+0x10000) or (address==0 and length==4),hex(address)
def boundary(uc,address,length,_):
    assert address in allowed,f'Excluded allocation/construction/resource path {address:#x}'
    calls.append(hex(address))
emu.hook_add(unicorn.UC_HOOK_MEM_WRITE,guard)
for address in allowed|{0xaae9af,0xaae91b,0x954f40,0x4beb50,0x955d40,0x4c25b0,0x4ee550,0x4d1020}:
    emu.hook_add(unicorn.UC_HOOK_CODE,boundary,begin=address,end=address)
def put(address,*values):emu.mem_write(address,struct.pack('<'+'I'*len(values),*[v&MASK32 for v in values]))
def get(buf,address):return struct.unpack_from('<I',buf,address-arena)[0]
def word(buf,address,value):struct.pack_into('<I',buf,address-arena,value&MASK32)
def qword(buf,address,value):struct.pack_into('<Q',buf,address-arena,value)
def setup(target,source_n,destination_n,initial_size,source_size,context):
    emu.mem_write(arena,bytes(0x10000));emu.mem_write(source,b'\xa5'*0x278);emu.mem_write(target,b'\x5a'*0x278)
    put(source+0x58,source_size,0x12345678,source_size,region,kind)
    put(target+0x58,initial_size,0x23456789,initial_size,other_region,other_kind)
    put(country+0x20,77);put(region+0x12c,77 if context==1 else 88);put(other_region+0x12c,99)
    put(source+0x6c,0x101,0x202);put(source+0x78,0x303);put(source+0xa0,0x404)
    put(source+0x128,0x505,0x606)
    put(source+0x180,32768000,0);put(target+0x180,300,0)
    put(target+0x1d4,0);put(target+0x274,1)
    put(source+0x158,*range(100,109));put(target+0x158,*range(200,209))
    for index,offset in enumerate(vectors):
        stride=8 if index%2==0 else 4
        n,m=source_n,destination_n
        capacity=max(n,m)+2
        sb,db=source_buffers+index*0x100,destination_buffers+index*0x100
        emu.mem_write(sb,bytes((i+index*17)&0xff for i in range(capacity*stride)))
        emu.mem_write(db,b'\xdd'*(capacity*stride))
        put(source+offset,sb,sb+n*stride,sb+capacity*stride)
        put(target+offset,db,db+m*stride,db+capacity*stride)
def initialize_expected(buf,target):
    for offset in (0x6c,0x70,0x78,0xa0,0x128,0x12c):word(buf,target+offset,get(buf,source+offset))
    for offset in vectors:
        begin,end=get(buf,source+offset),get(buf,source+offset+4)
        dest,capacity=get(buf,target+offset),get(buf,target+offset+8)
        assert end-begin<=capacity-dest
        buf[dest-arena:dest-arena+end-begin]=buf[begin-arena:end-arena]
        word(buf,target+offset+4,dest+end-begin)
    for offset in (0x58,0x5c,0x118,0x11c,0x120,0x124,0x274,0x1c8,0x1cc,0x134,0x13c,0x140,0x144,0x30,0x34):
        word(buf,target+offset,0)
    for offset in (0x130,0x138):word(buf,target+offset,0x8000)
    buf[target-arena+0x38]=0
def transfer_expected(buf,target,amount,flag,context):
    old=get(buf,target+0x58);s=get(buf,source+0x58)
    sc=struct.unpack_from('<Q',buf,source-arena+0x180)[0];dc=struct.unpack_from('<Q',buf,target-arena+0x180)[0]
    if old==0:initialize_expected(buf,target)
    model=transfer(s,old,amount,sc,dc)
    for offset in (0x58,0x60):word(buf,target+offset,model['destination_size'])
    word(buf,target+0x5c,old if old else model['destination_size'])
    di=2 if context==2 else 1;si=6 if flag else (7 if context==2 else 8)
    address=target+0x158+di*4;word(buf,address,get(buf,address)+model['amount'])
    if s:
        for offset in (0x58,0x60):word(buf,source+offset,model['source_size'])
        word(buf,source+0x5c,s)
        address=source+0x158+si*4;word(buf,address,get(buf,address)-model['amount'])
    qword(buf,source+0x180,model['source_balance']);qword(buf,target+0x180,model['destination_balance'])
    word(buf,target+0x64,region)
    if get(buf,target+0x274):word(buf,target+0x274,0)
    return model
preserved={UC_X86_REG_EBX:0x12345678,UC_X86_REG_EBP:0x23456789}
cases=[]
def execute(entry,target,expected,args,metadata):
    initial_sp=stack+0xf000
    put(initial_sp,sentinel,*args);put(0,0xcafebabe)
    emu.reg_write(UC_X86_REG_ESP,initial_sp)
    emu.reg_write(UC_X86_REG_EAX,source);emu.reg_write(UC_X86_REG_ESI,target);emu.reg_write(UC_X86_REG_EDI,source)
    for reg,value in preserved.items():emu.reg_write(reg,value)
    calls.clear();emu.emu_start(entry,sentinel,count=20000)
    assert emu.reg_read(UC_X86_REG_EIP)==sentinel
    assert emu.reg_read(UC_X86_REG_ESP)==initial_sp+4+4*len(args)
    assert emu.reg_read(UC_X86_REG_ESI)==target and emu.reg_read(UC_X86_REG_EDI)==source
    assert all(emu.reg_read(reg)==value for reg,value in preserved.items())
    assert bytes(emu.mem_read(0,4))==struct.pack('<I',0xcafebabe)
    actual=bytes(emu.mem_read(arena,0x10000))
    assert actual==expected,(hex(entry),metadata,[hex(i) for i,(x,y) in enumerate(zip(actual,expected)) if x!=y][:20])
    cases.append({'entry_va':hex(entry),**metadata,'calls':list(calls),'post_arena_sha256':hashlib.sha256(actual).hexdigest()})

for n in (0,1,2,7):
    for m in (0,1,5):
        for initial in (0,17):
            setup(destination,n,m,initial,1000,1)
            expected=bytearray(emu.mem_read(arena,0x10000));initialize_expected(expected,destination)
            execute(0x955a00,destination,expected,[],{'source_elements':n,'old_destination_elements':m,'old_size':initial})
            assert [c for c in calls if c in ('0x43a750','0x9beeb0')]==['0x43a750','0x9beeb0','0x43a750','0x9beeb0']
profiles=((0,0),(3,5),(5,1))
for s in (1,5,1000,2000000):
    for amount in dict.fromkeys((0,1,s,s+1)):
        for context in (0,1,2):
            for flag in (0,1):
                for n,m in profiles:
                    setup(destination,n,m,0,s,1 if context==0 else context)
                    if context==0:put(source+0x64,0)
                    expected=bytearray(emu.mem_read(arena,0x10000))
                    model=transfer_expected(expected,destination,amount,flag,context)
                    if context==0:word(expected,destination+0x64,0)
                    execute(0x5345a0,destination,expected,[country,destination,amount,flag],
                            {'source_size':s,'amount':amount,'context':context,'flag':flag,'source_elements':n,'old_destination_elements':m,'modeled':model})
for entry in (0x534810,0x534930):
    for selected in range(4):
        for old_size in ((0,) if entry==0x534810 else (0,10)):
            for s in (5,1000):
                for amount in (0,1,s):
                    for context in (1,2):
                        for n,m in profiles:
                            target=rows+selected*0x278
                            setup(target,n,m,old_size,s,context)
                            for i in range(4):
                                at=rows+i*0x278
                                if i==selected:continue
                                emu.mem_write(at,b'\x66'*0x278)
                                put(at+0x58,0 if i>selected else 5)
                                put(at+0x68,kind,0x101,0x202)
                                if i<selected:
                                    if i%3==0:put(at+0x68,other_kind)
                                    elif i%3==1:put(at+0x70,0x999)
                                    else:put(at+0x6c,0x999)
                            if entry==0x534930:put(target+0x68,kind,0x101,0x202)
                            begin=0x34 if entry==0x534810 else 0x44
                            put(country+begin,rows,rows+4*0x278,rows+4*0x278)
                            expected=bytearray(emu.mem_read(arena,0x10000))
                            if entry==0x534810:word(expected,target+0x68,kind)
                            model=transfer_expected(expected,target,amount,int(entry==0x534930),context)
                            execute(entry,target,expected,[country,source,amount],
                                    {'selected_index':selected,'old_size':old_size,'source_size':s,'amount':amount,'context':context,
                                     'source_elements':n,'old_destination_elements':m,'modeled':model})
                            assert calls.count('0x5345a0')==1
out=ROOT/'evidence/generated/pop-reuse';out.mkdir(parents=True,exist_ok=True)
for name,value in [('claims.json',claims),('reverify.json',report),('emulation.json',{
    'binary_sha256':digest,'engine':f'unicorn {unicorn.__version__}','cases':cases,'mismatches':0,
    'scope':'Complete original initializer, empty-destination core and reuse/matching wrapper paths with actual '
    'vector-copy/memmove/transfer callees; existing sufficient capacities, optional pointer null, type flags zero. '
    'All 64KiB fixture bytes and synthetic FS:0 restored. No heap allocation, wrapper append/growth, optional resource '
    'destruction, aliases, nonzero type flag, live-game state or exception unwinding tested.',
})]:(out/name).write_text(json.dumps(value,indent=2)+'\n')
ledger=Ledger.for_bytes(data,directory=ROOT/'.reverify');ledger.record(report,session='pop-initialization-and-wrapper-reuse');ledger.save()
print(f'POP reuse: {len(cases)} complete initializer/core/wrapper fixtures; original copy callees, no mismatches.')
