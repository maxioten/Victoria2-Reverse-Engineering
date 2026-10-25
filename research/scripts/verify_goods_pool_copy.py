#!/usr/bin/env python3
"""Execute original CGoodsPool assignment/resize with sufficient destination capacity."""
import hashlib
import json
from pathlib import Path
import random
import struct
import pefile
import unicorn
from unicorn.x86_const import *
from reverify.ledger import Ledger
from reverify.verifier import Claim,Verifier

ROOT=Path(__file__).resolve().parents[1]
data=(ROOT.parent/'base-game/v2game.exe').read_bytes();digest=hashlib.sha256(data).hexdigest()
assert digest=='62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'
pe=pefile.PE(data=data);base=pe.OPTIONAL_HEADER.ImageBase
claims=[]
for address,length,mnemonic,operand in (
    (0x47dbb4,5,'mov','eax, dword ptr [0x12587f4]'),
    (0x47dbcb,5,'call','0xab1550'),
    (0x47dbe1,5,'call','0x43a880'),
    (0x47dbe6,5,'mov','eax, 1'),
    (0x47dbeb,2,'cmp','esi, eax'),
    (0x47dbfc,3,'mov','dword ptr [edx + eax*8], edi'),
    (0x47dc03,4,'mov','dword ptr [edx + eax*8 + 4], ecx'),
    (0x47dc14,3,'ret','8'),
    (0x43ab6a,2,'mov','dword ptr [eax], edx'),
    (0x43ab6c,3,'mov','dword ptr [eax + 4], edx'),
    (0x43a8df,5,'call','0x43ab60'),
    (0x4237ad,2,'jbe','0x4237db'),
):
    claims.append(dict(id=f'goods_pool_copy_{address:x}',kind='instructions',space='rva',offset=hex(address-base),base=hex(address),arch='x86',length=length,mnemonics=[mnemonic],operands=[operand]))
report=Verifier(data).verify_all([Claim.from_dict(c) for c in claims])
assert all(x['verdict']=='VERIFIED' for x in report['results']),report
uc=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_32)
size=(pe.OPTIONAL_HEADER.SizeOfImage+4095)&~4095
uc.mem_map(base,size);uc.mem_write(base,pe.get_memory_mapped_image());uc.mem_protect(base,size,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
uc.mem_protect(0x1258000,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
arena,stack,stop=0x20000000,0x20100000,0x21000000
uc.mem_map(arena,65536);uc.mem_map(stack,65536);uc.mem_map(stop,4096)
source,target,sbuf,dbuf=arena,arena+0x1000,arena+0x2000,arena+0x3000
def put(at,*values):uc.mem_write(at,struct.pack('<'+'I'*len(values),*[v&0xffffffff for v in values]))
def word(buf,at,value):struct.pack_into('<I',buf,at-arena,value&0xffffffff)
def guard(emu,access,address,length,value,_):
    assert (arena<=address and address+length<=arena+65536) or (stack<=address and address+length<=stack+65536),hex(address)
uc.hook_add(unicorn.UC_HOOK_MEM_WRITE,guard)
allowed={0x47dbb0,0xab1550,0x43a880,0x423780,0x43ab60}
calls=[]
def boundary(emu,address,length,_):
    assert address in allowed,f'excluded allocation path {address:#x}'
    calls.append(hex(address))
for address in allowed|{0x4237e0,0x810880,0xaae9af,0xaae91b,0xaad3ad}:
    uc.hook_add(unicorn.UC_HOOK_CODE,boundary,begin=address,end=address)
preserved={UC_X86_REG_EBX:0x12345678,UC_X86_REG_ESI:0x23456789,UC_X86_REG_EDI:0x3456789a,UC_X86_REG_EBP:0x456789ab}
cases=[]
for profile in ('distinct','same_object'):
    for copied_bytes in (0,1,2,31,63,64):
        for n in (0,1,2,3,7,16):
            for m in ((n,) if profile=='same_object' else (0,1,3,9)):
                for pattern in (0,0x5a,0xff):
                    capacity=max(n,m)+2
                    rng=random.Random(0x47dbb0+n*100+m*10+copied_bytes)
                    uc.mem_write(arena,bytes([pattern])*65536)
                    uc.mem_write(source,bytes(rng.getrandbits(8) for _ in range(0x58)))
                    uc.mem_write(target,bytes(rng.getrandbits(8) for _ in range(0x58)))
                    put(source,0xdfbddc,0x18d);put(target,0xdfbddc,0x18d)
                    uc.mem_write(sbuf,bytes(rng.getrandbits(8) for _ in range(capacity*8)))
                    uc.mem_write(dbuf,bytes([pattern])*(capacity*8))
                    put(source+0x48,sbuf,sbuf+n*8,sbuf+capacity*8)
                    put(target+0x48,dbuf,dbuf+m*8,dbuf+capacity*8)
                    dst=source if profile=='same_object' else target
                    put(0x12587f4,copied_bytes)
                    expected=bytearray(uc.mem_read(arena,65536))
                    if profile=='distinct':
                        expected[dst-arena+8:dst-arena+8+copied_bytes]=expected[8:8+copied_bytes]
                        if n>m:expected[dbuf-arena+m*8:dbuf-arena+n*8]=bytes((n-m)*8)
                        if n>1:expected[dbuf-arena+8:dbuf-arena+n*8]=expected[sbuf-arena+8:sbuf-arena+n*8]
                        word(expected,dst+0x4c,dbuf+n*8)
                    sp=stack+0xf000;put(sp,stop,dst,source)
                    uc.reg_write(UC_X86_REG_ESP,sp)
                    for reg,value in preserved.items():uc.reg_write(reg,value)
                    calls.clear();uc.emu_start(0x47dbb0,stop,count=10000)
                    assert uc.reg_read(UC_X86_REG_EIP)==stop and uc.reg_read(UC_X86_REG_ESP)==sp+12
                    assert uc.reg_read(UC_X86_REG_EAX)==dst
                    assert all(uc.reg_read(reg)==value for reg,value in preserved.items())
                    actual=bytes(uc.mem_read(arena,65536))
                    assert actual==expected,(profile,copied_bytes,n,m,pattern,[hex(i) for i,(a,b) in enumerate(zip(actual,expected)) if a!=b][:20])
                    assert calls.count('0xab1550')==1 and calls.count('0x43a880')==1
                    assert ('0x43ab60' in calls)==(n>m)
                    first=None
                    if n:
                        destination_buffer=sbuf if profile=='same_object' else dbuf
                        first=dict(source_bits=hex(struct.unpack_from('<Q',actual,sbuf-arena)[0]),destination_bits=hex(struct.unpack_from('<Q',actual,destination_buffer-arena)[0]))
                    cases.append(dict(profile=profile,map_bytes=copied_bytes,source_count=n,old_destination_count=m,capacity=capacity,pattern=pattern,first_entry=first,calls=list(calls),post_arena_sha256=hashlib.sha256(actual).hexdigest()))
counterexamples=[c for c in cases if c['first_entry'] and c['first_entry']['source_bits']!=c['first_entry']['destination_bits']]
out=ROOT/'evidence/generated/goods-pool-copy';out.mkdir(parents=True,exist_ok=True)
for name,value in [('claims.json',claims),('reverify.json',report),('emulation.json',dict(binary_sha256=digest,engine=f'unicorn {unicorn.__version__}',cases=cases,mismatches=0,full_vector_copy_counterexamples=len(counterexamples),
    scope='Complete original 47DBB0 assignment and original copy/resize/zero-fill callees, no stubs. Sufficient nonnull destination capacity, map length global 0..64; same object or disjoint objects/buffers. Entire 64KiB fixture, ABI and return checked. No heap growth, partially overlapping objects/buffers, map length above64, live world or concurrency proof.'))]:
    (out/name).write_text(json.dumps(value,indent=2)+'\n')
ledger=Ledger.for_bytes(data,directory=ROOT/'.reverify');ledger.record(report,session='goods-pool-copy-and-resize');ledger.save()
print(f'Goods pool copy: {len(cases)} complete fixtures with real copy/resize/zero-fill callees; no mismatches.')
