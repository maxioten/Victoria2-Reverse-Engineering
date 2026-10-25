#!/usr/bin/env python3
"""Check growth instructions and execute capacity selection up to its call boundary.

Unlike the native receipt this bounded control-flow check does not allocate or
throw: it stops before reserve/length-error entry, never fabricates a return.
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
from reverify.verifier import Claim,Verifier

ROOT=Path(__file__).resolve().parents[1]
data=(ROOT.parent/'base-game/v2game.exe').read_bytes();digest=hashlib.sha256(data).hexdigest()
assert digest=='62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'
pe=pefile.PE(data=data);base=pe.OPTIONAL_HEADER.ImageBase
claims=[]
for address,length,mnemonic,operand in (
    (0x4bedfa,6,'cmp','esi, 0x67b239'),
    (0x4bee20,1,'inc','esi'),
    (0x4bee29,2,'shr','edx, 1'),
    (0x4bee46,2,'add','eax, edx'),
    (0x4bee4a,3,'cmovb','eax, esi'),
    (0x4bee4e,5,'call','0x4bf200'),
    (0x4bf226,6,'cmp','edi, 0x67b23a'),
    (0x4bf254,5,'call','0x4bf4c0'),
    (0x4bf26e,5,'call','0x4c0af0'),
    (0x4bf29d,5,'call','0x4be400'),
    (0x4bf2a5,5,'call','0xaae91b'),
    (0x4bf2c3,3,'mov','dword ptr [esi + 8], eax'),
    (0x4bf4d4,6,'imul','ecx, ecx, 0x278'),
    (0x4bf4db,5,'call','0xaae9af'),
    (0x4c0b33,5,'call','0x955450'),
    (0x4be40f,2,'call','edx'),
    (0x9558dc,3,'mov','edx, dword ptr [edx + 0x30]'),
    (0x9558e5,3,'mov','dword ptr [ebx + eax*4], edx'),
    (0x95592c,3,'mov','edx, dword ptr [edx + 8]'),
    (0x955935,3,'mov','dword ptr [ebx + eax*4], edx'),
    (0x9553af,3,'mov','edx, dword ptr [edx + 0x30]'),
    (0x9553b8,3,'mov','dword ptr [esi + eax*4], edx'),
    (0x9553fc,3,'mov','edx, dword ptr [edx + 8]'),
    (0x955405,3,'mov','dword ptr [esi + eax*4], edx'),
):
    claims.append(dict(id=f'pop_growth_{address:x}',kind='instructions',space='rva',offset=hex(address-base),base=hex(address),arch='x86',length=length,mnemonics=[mnemonic],operands=[operand]))
report=Verifier(data).verify_all([Claim.from_dict(c) for c in claims])
assert all(x['verdict']=='VERIFIED' for x in report['results']),report
uc=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_32)
size=(pe.OPTIONAL_HEADER.SizeOfImage+4095)&~4095
uc.mem_map(base,size);uc.mem_write(base,pe.get_memory_mapped_image());uc.mem_protect(base,size,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
arena,stack,stop=0x20000000,0x20100000,0x21000000
for at in (arena,stack,stop):uc.mem_map(at,4096)
def put(at,*values):uc.mem_write(at,struct.pack('<'+'I'*len(values),*[v&0xffffffff for v in values]))
def boundary(emu,address,length,_):emu.emu_stop()
for at in (0x4bf200,0xaad3ad):uc.hook_add(unicorn.UC_HOOK_CODE,boundary,begin=at,end=at)
def count_from_span(bits):
    signed=bits if bits<0x80000000 else bits-0x100000000
    q=abs(signed)//632
    return (q if signed>=0 else -q)&0xffffffff
def expected(begin,end,cap):
    n=count_from_span((end-begin)&0xffffffff)
    c=count_from_span((cap-begin)&0xffffffff)
    if n>0x67b239:return 'length_error_boundary',None
    required=n+1
    if required<=c:return 'return_without_reserve',None
    candidate=c+c//2
    return 'reserve_boundary',max(required,candidate if candidate<=0x67b23a else 0)
fixtures=[]
for n in (0,1,2,3,5,8,16,31,64,127,1024,65536,1000000,3000000,0x7fffffff//632):
    for c in (n,n+1,n+3,n*2):fixtures.append((0x10000000,n*632,c*632,'aligned_descriptor'))
# Deliberate synthetic boundary descriptors; no backing object arrays dereferenced.
for end in (0x7fffffff,0x80000000,0x80000278,0xffffffff):
    for cap in (end,0x7fffffff,0xffffffff):fixtures.append((0,end,cap,'synthetic_span_boundary'))
rng=random.Random(0x4bede0)
for _ in range(512):
    n=rng.randrange(0,100000);c=n+rng.randrange(0,1000)
    fixtures.append((rng.randrange(0,0x100000000),n*632,c*632,'wrapped_address_aligned_span'))
cases=[]
for begin,span,capacity_span,profile in fixtures:
    end=(begin+span)&0xffffffff;cap=(begin+capacity_span)&0xffffffff
    put(arena,begin,end,cap);put(stack+0xf00,stop)
    uc.reg_write(UC_X86_REG_ECX,arena);uc.reg_write(UC_X86_REG_ESP,stack+0xf00)
    uc.emu_start(0x4bede0,stop,count=100)
    pc=uc.reg_read(UC_X86_REG_EIP)
    actual={0x4bf200:'reserve_boundary',0xaad3ad:'length_error_boundary',stop:'return_without_reserve'}[pc]
    outcome,requested=expected(begin,end,cap)
    assert actual==outcome,(hex(begin),hex(end),hex(cap),actual,outcome)
    observed=None
    if actual=='reserve_boundary':
        sp=uc.reg_read(UC_X86_REG_ESP);observed=struct.unpack('<I',uc.mem_read(sp+4,4))[0]
        assert observed==requested,(observed,requested)
    assert bytes(uc.mem_read(arena,12))==struct.pack('<III',begin,end,cap)
    cases.append(dict(begin=hex(begin),end=hex(end),capacity_end=hex(cap),profile=profile,outcome=actual,requested_capacity=observed))
out=ROOT/'evidence/generated/pop-growth';out.mkdir(parents=True,exist_ok=True)
for name,value in [('claims.json',claims),('reverify.json',report),('capacity.json',dict(binary_sha256=digest,cases=cases,mismatches=0,
    scope='Original 4BEDE0 capacity-selection CFG up to reserve or length-error entry or normal return; no call result fabricated. Synthetic descriptor boundary/wrap cases do not prove valid allocation, exception delivery or live vector invariants. Actual native growth verified separately.'))]:
    (out/name).write_text(json.dumps(value,indent=2)+'\n')
ledger=Ledger.for_bytes(data,directory=ROOT/'.reverify');ledger.record(report,session='pop-vector-growth-capacity');ledger.save()
print(f'POP growth: {len(claims)} static checks, {len(cases)} original capacity-selection fixtures; native execution separate.')
