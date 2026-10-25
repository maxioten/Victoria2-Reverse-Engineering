#!/usr/bin/env python3
"""Execute CPop construction/copy and complete wrapper append with spare capacity.

Empty source distributions, no optional resource, pre-existing catalog/singletons.
No callee or allocator results are fabricated. Growth is rejected at its entry.
"""
import hashlib
import json
from pathlib import Path
import random
import struct

import pefile
import unicorn
from unicorn.x86_const import *
from reverify.ledger import Ledger
from reverify.verifier import Claim, Verifier
from pop_transfer_model import transfer

ROOT = Path(__file__).resolve().parents[1]
data = (ROOT.parent / 'base-game/v2game.exe').read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'
pe = pefile.PE(data=data)
base = pe.OPTIONAL_HEADER.ImageBase
claims = []
for address, length, mnemonic, operand in (
    (0x4beb71,2,'cmp','esi, ecx'),
    (0x4beb95,5,'call','0x4bede0'),
    (0x4beb9d,6,'imul','esi, esi, 0x278'),
    (0x4bebbb,5,'call','0x4bede0'),
    (0x4bebd6,5,'call','0x955450'),
    (0x4bebde,7,'add','dword ptr [edi + 4], 0x278'),
    (0x955474,7,'mov','dword ptr [edi + 4], 0x18d'),
    (0x955503,5,'call','0x955980'),
    (0x955602,6,'mov','edx, dword ptr [ebx + 0x180]'),
    (0x955815,6,'mov','dword ptr [edi + 0x158], esi'),
    (0x95584b,6,'mov','dword ptr [0xf20c04], ecx'),
    (0x955851,6,'mov','dword ptr [0xf20c08], edx'),
    (0x95595a,7,'mov','word ptr [edi + 0x1d0], ax'),
    (0x955976,3,'ret','8'),
    (0x954fcb,3,'mov','dword ptr [edi + 0x68], edx'),
    (0x955046,5,'call','0x4be4f0'),
    (0x955302,6,'fld','qword ptr [0xe457f0]'),
    (0x955308,5,'call','0xb31c36'),
    (0x955352,6,'cmp','byte ptr [eax + 0x39c], bl'),
    (0x955444,3,'ret','4'),
):
    claims.append(dict(id=f'pop_append_{address:x}',kind='instructions',space='rva',
        offset=hex(address-base),base=hex(address),arch='x86',length=length,
        mnemonics=[mnemonic],operands=[operand]))
report = Verifier(data).verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict']=='VERIFIED' for r in report['results']),report

uc = unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_32)
size = (pe.OPTIONAL_HEADER.SizeOfImage+4095)&~4095
uc.mem_map(base,size);uc.mem_write(base,pe.get_memory_mapped_image())
uc.mem_protect(base,size,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
# Fixture globals only. The original image on disk remains unchanged.
global_words = (0x1268fec,0x1268ff0,0x131bb34,0x12586dc,0x1258a48,0x1258a3c,0xf20c04,0xf20c08,0x12587ec,0x125880c,0x1258a94,0x1258a98)
for page in sorted({x&~4095 for x in global_words}):
    uc.mem_protect(page,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
arena,stack,stop = 0x20000000,0x20100000,0x21000000
uc.mem_map(arena,65536);uc.mem_map(stack,65536);uc.mem_map(0,4096);uc.mem_map(stop,4096)
source,dest,header,rows,catalog = arena,arena+0x1000,arena+0x2000,arena+0x3000,arena+0xd000
def put(address,*values):uc.mem_write(address,struct.pack('<'+'I'*len(values),*[x&0xffffffff for x in values]))
def word(buf,address,value):struct.pack_into('<I',buf,address-arena,value&0xffffffff)
def get(buf,address):return struct.unpack_from('<I',buf,address-arena)[0]
allowed = {0x955450,0x955980,0x43a750,0x9beeb0,0x409350,0x408ed0,0x4beb50,0x954f40,0x4be4f0,0xb31c36,
    0x955ae0,0x967f50,0x9c1650,0x955a00,0x5345a0,0x955fd0,0x955f20,0xac02a0,0xac9f20,0x534810,0x534930}
calls=[]
def boundary(emu,address,length,_):
    assert address in allowed,f'excluded heap/growth/resource path: {address:#x}'
    calls.append(hex(address))
for address in allowed|{0x4bede0,0xaae9af,0xaae91b,0x41a160,0x954910,0x47dbb0}:
    uc.hook_add(unicorn.UC_HOOK_CODE,boundary,begin=address,end=address)
def write_guard(emu,access,address,length,value,_):
    assert (arena<=address and address+length<=arena+65536) or (stack<=address and address+length<=stack+65536) or (address==0 and length==4) or (address in (0xf20c04,0xf20c08) and length==4),hex(address)
uc.hook_add(unicorn.UC_HOOK_MEM_WRITE,write_guard)

# Independent field model: explicit observed stores, not generated from instruction operands.
copied = tuple(range(0x58,0x74,4))+tuple(range(0x118,0x148,4))+(0x150,0x154,0x180,0x184,0x1c8,0x1cc,0x268,0x270,0x274)
zeroed = (0x30,0x34,0x3c,0x40,0x44,0x50,0x54,0x148,0x14c)+tuple(range(0x158,0x17c,4))+tuple(range(0x188,0x1ac,4))+tuple(range(0x1b0,0x1c8,4))+tuple(range(0x1d4,0x220,4))+(0x220,0x248,0x24c,0x250,0x254,0x258,0x260,0x264,0x26c)
def model(buf,target,src,key):
    # Snapshot makes the model independent of target/source overlap ordering.
    snapshot=bytes(buf[src-arena:src-arena+0x278])
    word(buf,target,0xe36428);word(buf,target+4,0x18d)
    word(buf,target+8,key[0]);word(buf,target+12,key[1])
    for off in (0x10,0x14,0x38):buf[target-arena+off]=0
    word(buf,target+0x24,0);word(buf,target+0x28,15)
    buf[target-arena+0x4c]=snapshot[0x4c]
    for off in copied:word(buf,target+off,struct.unpack_from('<I',snapshot,off)[0])
    for off in zeroed:word(buf,target+off,0)
    for off in (0x74,0x9c,0xc4,0xec):
        word(buf,target+off,0xdfd2cc)
        word(buf,target+off+4,struct.unpack_from('<I',snapshot,off+4)[0])
        for sub in (8,12,16,24,28,32):word(buf,target+off+sub,0)
    word(buf,target+0x224,key[0]);word(buf,target+0x228,key[1])
    buf[target-arena+0x22c]=0;word(buf,target+0x23c,0);word(buf,target+0x240,15)
    struct.pack_into('<H',buf,target-arena+0x1d0,0);buf[target-arena+0x1d2]=0

def constructor_model(buf,target,key):
    word(buf,target,0xe36428);word(buf,target+4,0x18d)
    word(buf,target+8,key[0]);word(buf,target+12,key[1])
    for off in (0x10,0x14,0x38,0x4c):buf[target-arena+off]=0
    word(buf,target+0x24,0);word(buf,target+0x28,15)
    for off in (*copied,*zeroed):word(buf,target+off,0)
    word(buf,target+0x68,catalog+0x400)
    word(buf,target+0x6c,catalog+0x800);word(buf,target+0x70,catalog+0x900)
    for off in (0x130,0x138):word(buf,target+off,0x8000)
    # Original finite binary64 constant 3277.300048828125 converted by B31C36.
    word(buf,target+0x128,3277)
    for off in (0x74,0x9c,0xc4,0xec):
        word(buf,target+off,0xdfd2cc);word(buf,target+off+4,0x18d)
        for sub in (8,12,16,24,28,32):word(buf,target+off+sub,0)
    word(buf,target+0x224,key[0]);word(buf,target+0x228,key[1])
    buf[target-arena+0x22c]=0;word(buf,target+0x23c,0);word(buf,target+0x240,15)
    struct.pack_into('<H',buf,target-arena+0x1d0,0);buf[target-arena+0x1d2]=0

def setup(seed,pattern):
    rng=random.Random(seed)
    uc.mem_write(arena,bytes([pattern])*65536)
    put(catalog,0,0,0,0,0,0,0,0)
    key=(rng.getrandbits(32),rng.getrandbits(32))
    for address,value in zip(global_words,(*key,catalog+0x100,catalog+0x200,catalog,catalog,0x11111111,0x22222222,catalog+0x800,catalog+0x900,0,0)):put(address,value)
    put(catalog+0x400+0x40,0)
    put(catalog+0x400+0x39c,0)
    return rng,key
def prepare_source(address,rng):
    uc.mem_write(address,bytes(rng.getrandbits(8) for _ in range(0x278)))
    for off in (0x74,0x9c,0xc4,0xec):
        for sub in (8,12,16,24,28,32):put(address+off+sub,0)
    put(address+0x1d4,0)
preserved={UC_X86_REG_EBX:0x12345678,UC_X86_REG_ESI:0x23456789,UC_X86_REG_EDI:0x3456789a,UC_X86_REG_EBP:0x456789ab}
cases=[]
def execute(entry,src,target,expected,args,meta):
    sp=stack+0xf000
    put(sp,stop,*args);put(0,0xcafebabe)
    for reg,value in preserved.items():uc.reg_write(reg,value)
    uc.reg_write(UC_X86_REG_ESP,sp);uc.reg_write(UC_X86_REG_ECX,src)
    uc.reg_write(UC_X86_REG_EDX,catalog+0x400)
    uc.reg_write(UC_X86_REG_FPCW,0x37f)
    if entry==0x4beb50:uc.reg_write(UC_X86_REG_EDI,header)
    calls.clear();uc.emu_start(entry,stop,count=30000)
    assert uc.reg_read(UC_X86_REG_EIP)==stop
    assert uc.reg_read(UC_X86_REG_ESP)==sp+4+len(args)*4
    for reg,value in preserved.items():assert uc.reg_read(reg)==(header if reg==UC_X86_REG_EDI and entry==0x4beb50 else value)
    assert bytes(uc.mem_read(0,4))==struct.pack('<I',0xcafebabe)
    actual=bytes(uc.mem_read(arena,65536))
    assert actual==expected,(meta,[hex(i) for i,(x,y) in enumerate(zip(actual,expected)) if x!=y][:40])
    if entry not in (0x534810,0x534930):assert uc.reg_read(UC_X86_REG_EAX)==target
    if entry==0x954f40:
        assert struct.unpack('<II',uc.mem_read(0xf20c04,8))==(0x11111111,0x22222222)
        assert calls.count('0x4be4f0')==4 and calls.count('0xb31c36')==1
    else:
        assert struct.unpack('<II',uc.mem_read(0xf20c04,8))==(catalog+0x100,catalog+0x200)
        assert calls.count('0x955450')==1 and calls.count('0x955980')==4
        if entry in (0x534810,0x534930):
            assert calls.count('0x954f40')==1 and calls.count('0x955ae0')==1 and calls.count('0x5345a0')==1
    cases.append(dict(entry_va=hex(entry),**meta,calls=list(calls),post_arena_sha256=hashlib.sha256(actual).hexdigest()))

for pattern in (0,0x5a,0xff):
    for seed in range(24):
        rng,key=setup(seed,pattern)
        expected=bytearray(uc.mem_read(arena,65536));constructor_model(expected,dest,key)
        execute(0x954f40,source,dest,expected,[dest],dict(seed=seed,pattern=pattern,mode='constructor'))
        rng,key=setup(seed,pattern);prepare_source(source,rng)
        expected=bytearray(uc.mem_read(arena,65536));model(expected,dest,source,key)
        execute(0x955450,source,dest,expected,[dest,source],dict(seed=seed,pattern=pattern,mode='direct'))
    for n in (0,1,2,5,8):
        for capacity_extra in (1,3):
            for index in (-1,*range(n)):
                rng,key=setup(100+n*10+index,pattern)
                src=source if index<0 else rows+index*0x278
                prepare_source(src,rng)
                put(header,rows,rows+n*0x278,rows+(n+capacity_extra)*0x278)
                target=rows+n*0x278
                expected=bytearray(uc.mem_read(arena,65536));model(expected,target,src,key)
                word(expected,header+4,target+0x278)
                execute(0x4beb50,src,target,expected,[],dict(pattern=pattern,mode='append',old_count=n,capacity_extra=capacity_extra,source_index=index))

def wrapper_model(buf,target,amount,flag,context):
    # The newly copied constructor payload has size zero, so the core initializes it.
    for off in (0x6c,0x70,0x78,0xa0,0x128,0x12c):word(buf,target+off,get(buf,source+off))
    for off in (0x58,0x5c,0x118,0x11c,0x120,0x124,0x274,0x1c8,0x1cc,0x134,0x13c,0x140,0x144,0x30,0x34):word(buf,target+off,0)
    for off in (0x130,0x138):word(buf,target+off,0x8000)
    buf[target-arena+0x38]=0
    s=get(buf,source+0x58)
    balance=struct.unpack_from('<Q',buf,source-arena+0x180)[0]
    result=transfer(s,0,amount,balance,0)
    for off in (0x58,0x5c,0x60):word(buf,target+off,result['destination_size'])
    for off in (0x58,0x60):word(buf,source+off,result['source_size'])
    word(buf,source+0x5c,s)
    di=1 if context==1 else 2;si=6 if flag else (8 if context==1 else 7)
    word(buf,target+0x158+di*4,result['amount'])
    at=source+0x158+si*4;word(buf,at,get(buf,at)-result['amount'])
    word(buf,target+0x64,get(buf,source+0x64))
    struct.pack_into('<Q',buf,target-arena+0x180,result['destination_balance'])
    struct.pack_into('<Q',buf,source-arena+0x180,result['source_balance'])

for pattern in (0,0x5a,0xff):
    for entry,offset in ((0x534810,0x34),(0x534930,0x44)):
        for n in (0,1,3):
            for s in (5,1000,2000000):
                for amount in (0,1,s):
                    for context in (1,2):
                        rng,key=setup(500+n+s+amount,pattern);prepare_source(source,rng)
                        put(source+0x58,s,99,s,catalog+0xa00,catalog+0x400)
                        put(source+0x180,32768000,0)
                        put(catalog+0xa00+0x12c,77 if context==1 else 88)
                        put(header+0x20,77)
                        put(header+offset,rows,rows+n*0x278,rows+(n+2)*0x278)
                        for i in range(n):
                            put(rows+i*0x278+0x58,17)
                            put(rows+i*0x278+0x68,0x11223344)
                        target=rows+n*0x278
                        expected=bytearray(uc.mem_read(arena,65536))
                        constructor_model(expected,target,key)
                        word(expected,header+offset+4,target+0x278)
                        wrapper_model(expected,target,amount,int(entry==0x534930),context)
                        execute(entry,source,target,expected,[header,source,amount],dict(pattern=pattern,mode='wrapper_append',old_count=n,source_size=s,amount=amount,context=context))

out=ROOT/'evidence/generated/pop-append';out.mkdir(parents=True,exist_ok=True)
for name,value in [('claims.json',claims),('reverify.json',report),('emulation.json',dict(binary_sha256=digest,engine=f'unicorn {unicorn.__version__}',cases=cases,mismatches=0,
    observed={'constructor':72,'copy_constructor':72,'direct_append':126,'wrapper_append':324},
    fixture_global_words=[hex(x) for x in global_words],
    scope='Complete constructor, copy construction, direct append and both full wrapper append paths with spare capacity; external source or aligned live source slot for direct append. Four empty distributions, pre-existing catalog/singletons, null optional resource; original destruction/transfer callees, full 64KiB fixture comparison, ABI and synthetic FS:0. Wrapper EAX is unspecified. No heap/growth, populated distribution/catalog, optional resource, exception unwinding, live-game or concurrency validation.'))]:
    (out/name).write_text(json.dumps(value,indent=2)+'\n')
ledger=Ledger.for_bytes(data,directory=ROOT/'.reverify');ledger.record(report,session='pop-copy-construction-and-spare-append');ledger.save()
print(f'POP append: {len(cases)} complete copy/append fixtures; no mismatches.')
