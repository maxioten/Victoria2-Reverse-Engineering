#!/usr/bin/env python3
"""Original post-search selector fragment; native complete consumers are separate."""
import hashlib
import itertools
import json
from pathlib import Path
import struct
import capstone
import pefile
import unicorn
from unicorn.x86_const import *
from reverify.ledger import Ledger
from reverify.verifier import Claim,Verifier
from pop_factory_selection_model import select_factory_type
from pop_transfer_model import signed32

ROOT=Path(__file__).resolve().parents[1]
data=(ROOT.parent/'base-game/v2game.exe').read_bytes();digest=hashlib.sha256(data).hexdigest()
assert digest=='62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'
pe=pefile.PE(data=data);image=pe.get_memory_mapped_image();base=0x400000;claims=[]
cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
for at,mnemonic,operand in (
    (0x4baa33,'mov','eax, dword ptr [ebx + 0x68]'),
    (0x4baa36,'cmp','byte ptr [eax + 0x3d8], 0'),
    (0x4baa41,'je','0x4baaeb'),
    (0x4baa49,'cmp','dword ptr [esp + 0x14], esi'),
    (0x4baa4d,'jle','0x4baaeb'),
    (0x4baa71,'mov','ecx, eax'),
    (0x4baa73,'mov','eax, dword ptr [edx + 0x18]'),
    (0x4baa76,'call','eax'),
    (0x4baa78,'test','al, al'),
    (0x4baa94,'cmp','byte ptr [eax + 0x3d9], 0'),
    (0x4baab5,'mov','edx, dword ptr [ebx + 0x68]'),
    (0x4baab8,'mov','eax, dword ptr [eax + 0x3c]'),
    (0x4baabb,'cmp','eax, dword ptr [edx + 0x3c]'),
    (0x4baabe,'jge','0x4baadc'),
    (0x4baad8,'mov','dword ptr [esp + 0x10], eax'),
    (0x4baadd,'cmp','esi, dword ptr [esp + 0x14]'),
    (0x4baae1,'jl','0x4baa57'),
    (0x4baae7,'mov','eax, dword ptr [esp + 0x10]'),
    (0xa31490,'mov','al, 1'),
    (0xa31492,'ret',''),
    (0x58cfd0,'xor','al, al'),
    (0x58cfd2,'ret',''),
):
    ins=next(cs.disasm(image[at-base:at-base+16],at))
    claims.append(dict(id=f'factory_selection_{at:x}',kind='instructions',space='rva',offset=hex(at-base),base=hex(at),arch='x86',length=ins.size,mnemonics=[mnemonic],operands=[operand]))
for table,target in ((0xe365f8,0xa31490),(0xe36618,0x58cfd0)):
    claims.append(dict(id=f'factory_selection_vtable_{table:x}',kind='u32_at',space='rva',offset=hex(table+0x18-base),expected=target))
report=Verifier(data).verify_all([Claim.from_dict(c) for c in claims]);assert all(r['verdict']=='VERIFIED' for r in report['results']),report
u=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_32);image_size=(pe.OPTIONAL_HEADER.SizeOfImage+4095)&~4095
u.mem_map(base,image_size);u.mem_write(base,image);u.mem_protect(base,image_size,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
arena,stack=0x20000000,0x20100000;u.mem_map(arena,16384);u.mem_map(stack,65536)
source,kind,array,header=arena,arena+0x1000,arena+0x2000,arena+0x2100
type_addresses=[arena+0x2400+i*0x400 for i in range(3)]
def put(at,*values):u.mem_write(at,struct.pack('<'+'I'*len(values),*[v&0xffffffff for v in values]))
def guard(emu,access,address,length,value,_):assert stack<=address and address+length<=stack+65536,hex(address)
u.hook_add(unicorn.UC_HOOK_MEM_WRITE,guard)
predicates=[]
def observe_predicate(emu,address,length,_):
    assert address in (0xa31490,0x58cfd0),f'excluded callee {address:#x}'
    predicates.append((type_addresses.index(emu.reg_read(UC_X86_REG_ECX)),address))
for at in (0xa31490,0x58cfd0,0x96bb70,0x4b8d30,0xaae9af):u.hook_add(unicorn.UC_HOOK_CODE,observe_predicate,begin=at,end=at)
level_sets=[(10,[5,1,7]),(0,[0x80000000,0xffffffff,0x7fffffff]),(0xffffffff,[0x80000000,0,0xffffffff]),(0x7fffffff,[0x7ffffffe,0x7fffffff,0])]
cases=[];lowest_counterexamples=0
for source_level,levels in level_sets:
    for order in itertools.permutations(levels):
        for pred_mask,flag_mask,count,special in itertools.product(range(8),range(8),range(4),(0,1,255)):
            entries=[dict(level=level,predicate=(pred_mask>>i)&1,flag3d9=(flag_mask>>i)&1) for i,level in enumerate(order)][:count]
            selected=select_factory_type(special,source_level,entries)
            u.mem_write(arena,bytes(16384));u.mem_write(stack,bytes(65536))
            put(source+0x68,kind);put(kind+0x3c,source_level);u.mem_write(kind+0x3d8,bytes([special]))
            put(header,array,array+4*count,array+12)
            for i,entry in enumerate(entries):
                at=type_addresses[i];put(array+4*i,at);put(at,0xe365f8 if entry['predicate'] else 0xe36618)
                put(at+0x3c,entry['level']);u.mem_write(at+0x3d9,bytes([entry['flag3d9']]))
            before=bytes(u.mem_read(arena,16384));sp=stack+0x8000;put(sp+0x14,count);put(sp+0x1c,header)
            u.reg_write(UC_X86_REG_ESP,sp);u.reg_write(UC_X86_REG_EBX,source);u.reg_write(UC_X86_REG_EBP,0x12345678)
            predicates.clear();u.emu_start(0x4baa33,0x4baaeb,count=1000)
            expected_calls=[(i,0xa31490 if e['predicate'] else 0x58cfd0) for i,e in enumerate(entries)] if special else []
            assert predicates==expected_calls and u.reg_read(UC_X86_REG_EIP)==0x4baaeb
            assert u.reg_read(UC_X86_REG_EAX)==(kind if selected<0 else type_addresses[selected])
            assert u.reg_read(UC_X86_REG_ESP)==sp and u.reg_read(UC_X86_REG_EBX)==source
            assert bytes(u.mem_read(arena,16384))==before
            eligible=[i for i,e in enumerate(entries) if e['predicate'] and not e['flag3d9'] and signed32(e['level'])<signed32(source_level)] if special else []
            lowest=min(eligible,key=lambda i:signed32(entries[i]['level'])) if eligible else -1
            lowest_counterexamples+=lowest!=selected
            cases.append(dict(source_level=source_level,entries=entries,special=special,selected_ordinal=selected,lowest_ordinal=lowest,predicate_trace=[[i,hex(a)] for i,a in predicates],arena_sha256=hashlib.sha256(before).hexdigest()))
assert len(cases)==18432 and lowest_counterexamples>0
out=ROOT/'evidence/generated/pop-factory-selection';out.mkdir(parents=True,exist_ok=True)
for name,value in [('claims.json',claims),('reverify.json',report),('emulation.json',dict(binary_sha256=digest,cases=cases,lowest_counterexamples=lowest_counterexamples,mismatches=0,scope='Original4BAA33..4BAAEB fragment,real CPopType/CNullPopType virtual predicates. EAX choice,exact predicate order/targets,read-only16KiB fixture,ESP/EBX checked. Stops before factory call preparation,not whole function or ABI/FS0 restoration. Valid catalog count0..3;no malformed count/lazy getter/live world. Complete native consumer evidence separate.'))]:
    (out/name).write_text(json.dumps(value,indent=2)+'\n')
ledger=Ledger.for_bytes(data,directory=ROOT/'.reverify');ledger.record(report,session='pop-post-search-factory-type-selection');ledger.save()
print(f'POP factory selection: {len(claims)} static checks,{len(cases)} original fragments;{lowest_counterexamples} counterexamples to minimum-level choice.')
