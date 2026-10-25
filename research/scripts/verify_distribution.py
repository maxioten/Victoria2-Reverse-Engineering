#!/usr/bin/env python3
"""Execute original distribution normalization and both real arithmetic helpers."""
import hashlib
import json
from pathlib import Path
import random
import struct
import pefile
import unicorn
from unicorn.x86_const import (
    UC_X86_REG_EBP, UC_X86_REG_EBX, UC_X86_REG_EDI, UC_X86_REG_EIP,
    UC_X86_REG_ESI, UC_X86_REG_ESP,
)
from reverify.ledger import Ledger
from reverify.verifier import Claim, Verifier
from distribution_model import normalize_distribution
from integer_model import MASK, signed

ROOT = Path(__file__).resolve().parents[1]
data = (ROOT.parent / 'base-game/v2game.exe').read_bytes()
digest = hashlib.sha256(data).hexdigest()
if digest != '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648':
    raise SystemExit('Binary profile mismatch')
claims = []
for address,length,mnemonic,operands in [
    (0x4be78e,3,'mov','esi, dword ptr [eax + 0xc]'),
    (0x4be791,3,'sub','esi, dword ptr [eax + 8]'),
    (0x4be7a2,5,'mov','ebx, 1'),
    (0x4be843,2,'js','0x4be8c3'),
    (0x4be845,2,'jg','0x4be84e'),
    (0x4be84c,2,'jbe','0x4be8c3'),
    (0x4be878,5,'push','0x320000'),
    (0x4be87f,5,'call','0xac9f20'),
    (0x4be887,4,'shrd','eax, edx, 0xf'),
    (0x4be88b,3,'sar','edx, 0xf'),
    (0x4be8a8,4,'shld','eax, edx, 0xf'),
    (0x4be8b2,5,'call','0xac02a0'),
    (0x4be8c9,3,'ret','4'),
]:
    claims.append({'id':f'distribution_{address:x}','kind':'instructions','space':'rva',
                   'offset':hex(address-0x400000),'base':hex(address),'arch':'x86','length':length,
                   'mnemonics':[mnemonic],'operands':[operands]})
for site in (0x4b99fe,0x4b9b42,0x4ba170,0x520c7f,0x520c8b,0x76e358,0x76e364,
             0x7c4a92,0x7c4a9e,0x883e78,0x8988eb,0x898e89,0x8abdd0,0x8ac537,
             0x95915b,0x9592cc,0x95952e,0x959786):
    claims.append({'id':f'distribution_caller_{site:x}','kind':'instructions','space':'rva',
                   'offset':hex(site-0x400000),'base':hex(site),'arch':'x86','length':5,
                   'mnemonics':['call'],'operands':['0x4be780']})
for address,length,mnemonic,operand in (
    (0x959154,6,'lea','eax, [edi + 0xc4]'),(0x95915a,1,'push','eax'),
    (0x9592c8,3,'lea','edx, [edi + 0x74]'),(0x9592cb,1,'push','edx'),
    (0x959527,6,'lea','ecx, [edi + 0xec]'),(0x95952d,1,'push','ecx'),
    (0x95977f,6,'lea','eax, [edi + 0x9c]'),(0x959785,1,'push','eax'),
):
    claims.append({'id':f'distribution_argument_{address:x}','kind':'instructions','space':'rva',
                   'offset':hex(address-0x400000),'base':hex(address),'arch':'x86','length':length,
                   'mnemonics':[mnemonic],'operands':[operand]})
verification = Verifier(data).verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict']=='VERIFIED' for r in verification['results']),verification
pe = pefile.PE(data=data)
base = pe.OPTIONAL_HEADER.ImageBase
emu = unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_32)
image_size = (pe.OPTIONAL_HEADER.SizeOfImage+4095)&~4095
emu.mem_map(base,image_size)
emu.mem_write(base,pe.get_memory_mapped_image())
emu.mem_protect(base,image_size,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
arena,descriptor,vector,stack,initial_sp,sentinel = 0x20000000,0x20000000,0x20001000,0x20010000,0x2001f000,0x21000000
emu.mem_map(arena,0x20000,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
emu.mem_map(sentinel,0x1000,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
writes,calls,current_length = [],[],0
def on_write(uc,access,address,size,value,_):
    if vector+8 <= address and address+size <= vector+current_length*8:
        writes.append({'offset':address-vector,'size':size,'value':value})
    else:
        assert stack <= address and address+size <= stack+0x10000,hex(address)
def on_call(uc,address,size,_):
    calls.append(hex(address))
emu.hook_add(unicorn.UC_HOOK_MEM_WRITE,on_write)
for address in (0xac9f20,0xac02a0):
    emu.hook_add(unicorn.UC_HOOK_CODE,on_call,begin=address,end=address)
preserved={UC_X86_REG_EBX:0x12345678,UC_X86_REG_ESI:0x23456789,UC_X86_REG_EDI:0x34567890,UC_X86_REG_EBP:0x45678901}
minimum=-(1<<63)
special=[[],[123],[999,0],[999,1],[999,1,1],[999,1,2,3],[999,-1,3],[999,-1,-2],
         [999,minimum,0,minimum+(1<<32)],[999,minimum,0,minimum+(1<<32)+1],
         [999,1<<50,1<<50],[999,(1<<63)-1,1],[999,32768,65536,98304]]
fixtures=[('special_'+str(i),row) for i,row in enumerate(special)]
generator=random.Random(20261021)
for i in range(256):
    length=generator.randrange(65)
    fixtures.append(('bounded_'+str(i),[generator.randrange(-1000*32768,1000*32768+1) for _ in range(length)]))
    fixtures.append(('bits_'+str(i),[signed(generator.getrandbits(64)) for _ in range(length)]))
results,normalized,counterexamples=[],0,[]
for name,values in fixtures:
    expected,info=normalize_distribution(values)
    current_length=len(values)
    raw=struct.pack('<'+'Q'*len(values),*(v&MASK for v in values))
    desc=struct.pack('<4I',0xdeadbeef,0xa5a5a5a5,vector,vector+len(raw))
    emu.mem_write(descriptor,desc)
    emu.mem_write(vector-8,b'CANARY01'+raw+b'CANARY02')
    emu.mem_write(initial_sp,struct.pack('<2I',sentinel,descriptor))
    emu.reg_write(UC_X86_REG_ESP,initial_sp)
    for reg,value in preserved.items(): emu.reg_write(reg,value)
    writes.clear(); calls.clear()
    emu.emu_start(0x4be780,sentinel,count=100000)
    assert emu.reg_read(UC_X86_REG_EIP)==sentinel,name
    assert emu.reg_read(UC_X86_REG_ESP)==initial_sp+8,name
    assert all(emu.reg_read(reg)==value for reg,value in preserved.items()),name
    actual=bytes(emu.mem_read(vector,len(raw)))
    assert actual==struct.pack('<'+'Q'*len(expected),*expected),(name,values,expected,actual.hex())
    assert bytes(emu.mem_read(descriptor,16))==desc
    assert bytes(emu.mem_read(vector-8,8))==b'CANARY01'
    assert bytes(emu.mem_read(vector+len(raw),8))==b'CANARY02'
    if info['normalized']:
        normalized+=1
        assert calls==['0xac9f20','0xac02a0']*(len(values)-1),name
        expected_writes=[]
        for index in range(1,len(values)):
            scaled=signed(((values[index]&MASK)*0x320000)&MASK)>>15
            for offset,value in ((index*8+4,(scaled&MASK)>>32),(index*8,scaled&0xffffffff),
                                 (index*8,expected[index]&0xffffffff),(index*8+4,expected[index]>>32)):
                expected_writes.append({'offset':offset,'size':4,'value':value})
        assert writes==expected_writes,name
    else:
        assert not writes and not calls,name
    if info.get('naive_positive_sum_guard') is not None and info['normalized']!=info['naive_positive_sum_guard']:
        counterexamples.append({'name':name,'input':values,'model':info,'actual_unchanged':actual==raw})
    if name.startswith('special_'):
        results.append({'name':name,'input':values,'output_bits':[hex(x) for x in expected],'model':info})
assert counterexamples,'Expected a signed-overflow guard counterexample'
out=ROOT/'evidence/generated/distribution'
out.mkdir(parents=True,exist_ok=True)
for name,value in [('claims.json',claims),('reverify.json',verification),('emulation.json',{
    'binary_sha256':digest,'engine':f'unicorn {unicorn.__version__}','entry_va':'0x4be780',
    'cases':len(fixtures),'normalized_cases':normalized,'mismatches':0,'special_cases':results,
    'naive_positive_guard_counterexamples':counterexamples,
    'scope':'Complete original routine and original 64-bit helpers; synthetic valid contiguous vectors. '
            'Slot zero, descriptor, canaries, nonvolatile registers and ordered 32-bit vector writes checked. '
            'No real game trace, invalid pointer/count test, concurrency proof or universal equivalence proof.',
})]: (out/name).write_text(json.dumps(value,indent=2)+'\n')
ledger=Ledger.for_bytes(data,directory=ROOT/'.reverify')
ledger.record(verification,session='distribution-normalization-int64')
ledger.save()
print(f'Distribution: {len(fixtures)} full cases; {normalized} normalized; guard counterexamples recorded; no mismatches.')
