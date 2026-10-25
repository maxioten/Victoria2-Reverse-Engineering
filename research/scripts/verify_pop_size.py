#!/usr/bin/env python3
"""Execute the original size-setting entry with actual bounded statistics callees.

The complete function is executed. Empty owners and existing single-node map
fixtures exclude heap allocation and erase paths; no callees are replaced by stubs.
"""
import hashlib
import json
from pathlib import Path
import struct

import pefile
import unicorn
from unicorn.x86_const import (
    UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_EBP, UC_X86_REG_EDI,
    UC_X86_REG_EIP, UC_X86_REG_ESI, UC_X86_REG_ESP,
)
from reverify.ledger import Ledger
from reverify.verifier import Claim, Verifier

ROOT = Path(__file__).resolve().parents[1]
data = (ROOT.parent / 'base-game/v2game.exe').read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'
pe = pefile.PE(data=data)
base = pe.OPTIONAL_HEADER.ImageBase
claims=[]
for address,length,mnemonic,operand in (
    (0x955fda,2,'test','edi, edi'),
    (0x955fde,2,'xor','edi, edi'),
    (0x955fe2,6,'cmp','edi, 0x1e8480'),
    (0x955fea,5,'mov','edi, 0x1e8480'),
    (0x955ff2,4,'cmp','byte ptr [eax + 0x40], 0'),
    (0x955ff8,3,'mov','dword ptr [esi + 0x60], edi'),
    (0x95600f,5,'call','0x4c25b0'),
    (0x956027,5,'call','0x4ee550'),
    (0x95603a,5,'call','0x4d1020'),
    (0x956042,3,'mov','dword ptr [esi + 0x5c], ecx'),
    (0x956045,3,'mov','dword ptr [esi + 0x58], edi'),
    (0x95604c,3,'mov','dword ptr [esi + 0x5c], edi'),
    (0x4ee5b4,3,'sub','dword ptr [ecx + 0x60], eax'),
    (0x4ee630,2,'add','dword ptr [eax], esi'),
    (0x4ee632,3,'add','dword ptr [ebx + 0x48], esi'),
    (0x4ee63e,3,'add','dword ptr [ecx + eax*4], esi'),
):
    claims.append({'id':f'pop_size_{address:x}','kind':'instructions','space':'rva',
                   'offset':hex(address-base),'base':hex(address),'arch':'x86','length':length,
                   'mnemonics':[mnemonic],'operands':[operand]})
report=Verifier(data).verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict']=='VERIFIED' for r in report['results']),[
    r for r in report['results'] if r['verdict']!='VERIFIED']

emu=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_32)
image_size=(pe.OPTIONAL_HEADER.SizeOfImage+4095)&~4095
emu.mem_map(base,image_size)
emu.mem_write(base,pe.get_memory_mapped_image())
emu.mem_protect(base,image_size,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
arena, stack, sentinel=0x20000000,0x20100000,0x21000000
emu.mem_map(arena,0x10000,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
emu.mem_map(stack,0x10000,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
emu.mem_map(sentinel,0x1000,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
pop,kind,province,owner=arena,arena+0x1000,arena+0x2000,arena+0x3000
singleton,array=arena+0x4000,arena+0x5000
row,tree_header,tree_node,type_totals=arena+0x7000,arena+0x7100,arena+0x7200,arena+0x7300
def put(address,*values):
    emu.mem_write(address,struct.pack('<'+'I'*len(values),*[v&0xffffffff for v in values]))
def signed(value): return value if value<0x80000000 else value-0x100000000
preserved={UC_X86_REG_EBX:0x12345678,UC_X86_REG_EDI:0x23456789,UC_X86_REG_EBP:0x34567890}
calls=[]
def write_guard(uc,access,address,size,value,_):
    assert (arena<=address and address+size<=arena+0x10000) or (stack<=address and address+size<=stack+0x10000),hex(address)
def boundary(uc,address,size,_):
    calls.append(hex(address))
    assert address in (0x4c25b0,0x4ee550,0x4d1020,0x4c8d10),hex(address)
emu.hook_add(unicorn.UC_HOOK_MEM_WRITE,write_guard)
for address in (0x4c25b0,0x4ee550,0x4d1020,0x4c8d10,0x4f2680,0x4f2760,0x4ca000,0xaae9af):
    emu.hook_add(unicorn.UC_HOOK_CODE,boundary,begin=address,end=address)
cases=[]
def run(old_size,assigned,requested,flag,province_index,populated):
    emu.mem_write(arena,bytes(0x10000))
    emu.mem_write(pop,b'\xa5'*0x300)
    put(pop+0x58,old_size,0x12345678,assigned,province,kind)
    emu.mem_write(kind+0x40,bytes([flag]));put(kind+0x28,2)
    put(province+0x58,province_index);put(province+0x188,owner)
    put(singleton,array);put(0x1258728,singleton)
    holder=array+province_index*0xb0+0x10
    if populated:
        put(holder+0x10,row,row+16,row+16)
        put(row+8,pop,assigned)
        put(holder+0x48,assigned);put(holder+0x50,tree_header);put(holder+0x5c,type_totals)
        put(tree_header+4,tree_node);emu.mem_write(tree_header+0x15,b'\1')
        put(tree_node,tree_header,tree_header,tree_header,pop,assigned)
        put(type_totals+8,assigned)
    expected=bytearray(emu.mem_read(arena,0x10000))
    target=max(0,min(2000000,signed(requested)))
    struct.pack_into('<2I',expected,0x58,target,target if old_size==0 else old_size)
    expected_calls=[]
    if not flag:
        struct.pack_into('<I',expected,0x60,target)
    elif target<signed(assigned):
        expected_calls=['0x4c25b0','0x4ee550']
        if populated:
            assert target>0 and assigned>=target
            for address in (pop+0x60,row+12,holder+0x48,tree_node+0x10,type_totals+8):
                struct.pack_into('<I',expected,address-arena,target)
            expected_calls.append('0x4c8d10')
        expected_calls.append('0x4d1020')
    initial_sp=stack+0xf000
    put(initial_sp,sentinel)
    emu.reg_write(UC_X86_REG_ESP,initial_sp);emu.reg_write(UC_X86_REG_ESI,pop)
    emu.reg_write(UC_X86_REG_EAX,requested)
    for reg,value in preserved.items():emu.reg_write(reg,value)
    calls.clear();emu.emu_start(0x955fd0,sentinel,count=2000)
    assert emu.reg_read(UC_X86_REG_EIP)==sentinel
    assert emu.reg_read(UC_X86_REG_ESP)==initial_sp+4 and emu.reg_read(UC_X86_REG_ESI)==pop
    assert all(emu.reg_read(reg)==value for reg,value in preserved.items())
    actual=bytes(emu.mem_read(arena,0x10000))
    assert actual==expected,(old_size,assigned,requested,flag,populated,[hex(i) for i,(a,b) in enumerate(zip(actual,expected)) if a!=b][:20])
    assert calls==expected_calls,(calls,expected_calls)
    cases.append({'old_size_bits':hex(old_size),'assigned_bits':hex(assigned),'requested_bits':hex(requested),
                  'flag':flag,'province_index':province_index,'populated_stats':populated,'target':target,
                  'calls':list(calls),'post_arena_sha256':hashlib.sha256(actual).hexdigest()})

for old_size in (0,1,1000,2000000,0xffffffff):
    for assigned in (0,5,1000,0x7fffffff):
        for requested in (0x80000000,0xffffffff,0,1,4,5,1000,1999999,2000000,2000001,0x7fffffff):
            for flag in (0,1,0xff):
                for province_index in (0,2):run(old_size,assigned,requested,flag,province_index,False)
for assigned in (5,1000,9999):
    for requested in (1,4,50,999,1000,9998,9999):
        for province_index in (0,2):run(10000,assigned,requested,1,province_index,True)
out=ROOT/'evidence/generated/pop-size';out.mkdir(parents=True,exist_ok=True)
for name,value in [('claims.json',claims),('reverify.json',report),('emulation.json',{
    'binary_sha256':digest,'entry_va':'0x955fd0','engine':f'unicorn {unicorn.__version__}',
    'cases':cases,'mismatches':0,'scope':'Complete original entry with actual callees, existing statistics singleton, '
    'empty owner root and either empty vectors or one existing positive-remainder map/vector row. '
    'All 65536 fixture bytes compared. No allocation, erase, nonempty owner hierarchy, exceptions, '
    'real-game invariants, global monthly-update equivalence or concurrent mutation tested.',
})]:(out/name).write_text(json.dumps(value,indent=2)+'\n')
ledger=Ledger.for_bytes(data,directory=ROOT/'.reverify')
ledger.record(report,session='pop-size-and-positive-remainder-stats');ledger.save()
print(f'POP size: {len(cases)} full original-entry fixtures, {sum(c["populated_stats"] for c in cases)} with existing statistics rows; no mismatches.')
