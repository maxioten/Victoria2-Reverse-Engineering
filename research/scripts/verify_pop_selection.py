#!/usr/bin/env python3
"""Full consumers with existing selected nodes; separate stopped no-match prefixes."""
from collections import Counter
import hashlib
import itertools
import json
from pathlib import Path
import random
import struct
import capstone
import pefile
import unicorn
from unicorn.x86_const import *
from reverify.ledger import Ledger
from reverify.verifier import Claim,Verifier
from pop_selection_model import select_destination
from pop_merge_model import merge
from integer_model import MASK

ROOT=Path(__file__).resolve().parents[1]
data=(ROOT.parent/'base-game/v2game.exe').read_bytes();digest=hashlib.sha256(data).hexdigest()
assert digest=='62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'
pe=pefile.PE(data=data);image=pe.get_memory_mapped_image();base=0x400000
cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32);claims=[]
for at,mnemonic,operand in (
    (0x4ba847,'cmp','byte ptr [ecx + 0x3d8], 0'),
    (0x4ba860,'cmp','edx, dword ptr [eax + 0x12c]'),
    (0x4ba866,'je','0x4ba8e7'),
    (0x4ba88c,'cmp','ecx, -1'),
    (0x4ba891,'cmp','dword ptr [eax + 0x58], ecx'),
    (0x4ba89b,'cmp','byte ptr [edi + 0x3d9], 0'),
    (0x4ba8ad,'jge','0x4ba876'),
    (0x4ba8b2,'cmp','ecx, dword ptr [ebx + 0x6c]'),
    (0x4ba8ba,'cmp','edx, dword ptr [ebx + 0x70]'),
    (0x4ba8c8,'call','0x964370'),
    (0x4ba909,'cmp','ecx, -1'),
    (0x4ba918,'cmp','edi, dword ptr [ebx + 0x68]'),
    (0x4ba920,'cmp','ecx, dword ptr [ebx + 0x6c]'),
    (0x4ba928,'cmp','ecx, dword ptr [ebx + 0x70]'),
    (0x4ba932,'call','0x964370'),
    (0x4ba97a,'cmp','byte ptr [edi + 0x3d9], 0'),
    (0x4ba989,'cmp','edi, dword ptr [ecx + 0x3c]'),
    (0x4ba991,'cmp','ecx, dword ptr [ebx + 0x6c]'),
    (0x4ba99b,'call','0x964370'),
    (0x4ba9e3,'cmp','byte ptr [edi + 0x3d9], 0'),
    (0x4ba9ec,'cmp','edi, dword ptr [ebx + 0x68]'),
    (0x4ba9f7,'mov','ecx, dword ptr [ecx + 0x50]'),
    (0x4ba9fa,'cmp','ecx, dword ptr [edx + 0x50]'),
    (0x4baa08,'call','0x964370'),
):
    ins=next(cs.disasm(image[at-base:at-base+16],at))
    claims.append(dict(id=f'selection_{at:x}',kind='instructions',space='rva',offset=hex(at-base),base=hex(at),arch='x86',length=ins.size,mnemonics=[mnemonic],operands=[operand]))
report=Verifier(data).verify_all([Claim.from_dict(c) for c in claims]);assert all(r['verdict']=='VERIFIED' for r in report['results']),report
u=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_32);image_size=(pe.OPTIONAL_HEADER.SizeOfImage+4095)&~4095
u.mem_map(base,image_size);u.mem_write(base,image);u.mem_protect(base,image_size,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
for page in (0x1258000,0x131b000):u.mem_protect(page,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
arena,stack,stop=0x20000000,0x20100000,0x21000000
u.mem_map(arena,0x20000);u.mem_map(stack,65536);u.mem_map(0,4096);u.mem_map(stop,4096)
owner,source_region,pending,nodes,types_at,cultures,world,log_header,log_row,outer_map,outer_head,outer_node,inner_head,inner_node,singleton,buckets,provinces,type_array=[arena+off for off in (0,0x1000,0x2000,0x3000,0x5000,0x8000,0x9000,0xa000,0xa100,0xa200,0xa300,0xa400,0xa500,0xa600,0xa700,0xa800,0xa900,0xaa00)]
def put(address,*values):u.mem_write(address,struct.pack('<'+'I'*len(values),*[x&0xffffffff for x in values]))
def qword(address,value):u.mem_write(address,struct.pack('<Q',value&MASK))
def setword(buf,address,value):struct.pack_into('<I',buf,address-arena,value&0xffffffff)
def getword(buf,address):return struct.unpack_from('<I',buf,address-arena)[0]
def setqword(buf,address,value):struct.pack_into('<Q',buf,address-arena,value&MASK)
def payload(at,pattern,size=0x288):
    u.mem_write(at,bytes([pattern])*size);put(at,0xe36428,0x18d)
    for off in (0x3c,0x7c,0x8c,0xa4,0xb4,0xcc,0xdc,0xf4,0x104):put(at+off,0,0,0)
    for off in (0x1d4,0x220):put(at+off,0)
    for off in (0x24,0x23c):put(at+off,0,15)
    u.mem_write(at+0x10,b'\0');u.mem_write(at+0x14,b'\0');u.mem_write(at+0x22c,b'\0')
def guard(emu,access,address,length,value,_):
    assert arena<=address and address+length<=arena+0x20000 or stack<=address and address+length<=stack+65536 or address==0 and length==4,hex(address)
u.hook_add(unicorn.UC_HOOK_MEM_WRITE,guard)
trace=[];calls=[];merge_targets=[];no_match=False
stage_entries={0x4ba87e:'lower',0x4ba8fb:'exact',0x4ba95d:'level',0x4ba9c6:'group'}
def observe_stage(emu,address,length,_):trace.append((stage_entries[address],(emu.reg_read(UC_X86_REG_ESI)-nodes)//0x288))
for at in stage_entries:u.hook_add(unicorn.UC_HOOK_CODE,observe_stage,begin=at,end=at)
allowed={0x964370,0xac9f20,0xac02a0,0x955fd0,0x95a5f0,0x68dea0,0x444f10,0x444da0,0x445260,0x4453b0}
def observe_call(emu,address,length,_):
    assert address in allowed,f'excluded original path {address:#x}'
    calls.append(hex(address))
    if address==0x964370:merge_targets.append(emu.reg_read(UC_X86_REG_EDI))
for at in allowed|{0x4b8d30,0x4b9250,0xaae9af,0xaae91b,0x445d30,0x445ac0,0x4449f0,0x4ee550,0x4d1020}:
    u.hook_add(unicorn.UC_HOOK_CODE,observe_call,begin=at,end=at)
def stop_no_match(emu,address,length,_):
    assert no_match,'unexpected no-match path'
    emu.emu_stop()
u.hook_add(unicorn.UC_HOOK_CODE,stop_no_match,begin=0x4baa33,end=0x4baa33)
preserved={UC_X86_REG_EBX:0x12345678,UC_X86_REG_ESI:0x23456789,UC_X86_REG_EDI:0x3456789a,UC_X86_REG_EBP:0x456789ab}
templates=[[(1,0,1,17),(0,0,0,17),(0,1,1,17)],[(4,0,1,17),(1,0,1,17),(0,1,0,17)],[(0,2,1,17),(0,1,1,17),(3,0,0,17)],[(2,0,0,17),(6,0,0,17),(0,0,0,17)],[(5,0,0,17),(5,0,1,1),(0,0,0,1)]]
fixtures=[]
for template in templates:
    for order in itertools.permutations(template):
        for special,other,blocked in itertools.product(range(2),repeat=3):fixtures.append((list(order),special,other,blocked))
rng=random.Random(20261021)
for _ in range(512):
    rows=[(rng.randrange(7),rng.randrange(3),rng.randrange(2),rng.choice((1,17))) for _ in range(rng.randrange(1,7))]
    fixtures.append((rows,rng.randrange(2),rng.randrange(2),rng.randrange(2)))
cases=[];counts=Counter();flagged_exact=0;per_node_counterexamples=0;lowest_level_counterexamples=0
for case_index,(rows,special,other,blocked) in enumerate(fixtures):
    types=[dict(level=level,limit=17 if i==5 or i==0 and case_index%3==0 else -1,flag3d9=bool(blocked) if i==0 else i==4) for i,level in enumerate((10,10,5,20,10,10,-1))]
    candidates=[dict(type=t,culture=c,religion=r,size=n) for t,c,r,n in rows]
    selected,stage,expected_trace=select_destination(types,candidates,[7,7,9],special,other)
    per_node_selected=None
    for j,c in enumerate(candidates):
        if select_destination(types,[c],[7,7,9],special,other)[0] is not None:per_node_selected=j;break
    per_node_counterexamples+=per_node_selected!=selected
    lowest_level_selected=selected
    if special and other:
        eligible=[j for j,c in enumerate(candidates) if select_destination(types,[c],[7,7,9],special,other)[0] is not None]
        if eligible:lowest_level_selected=min(eligible,key=lambda j:types[candidates[j]['type']]['level'])
        lowest_level_counterexamples+=lowest_level_selected!=selected
    no_match=selected is None
    u.mem_write(arena,bytes(0x20000));u.mem_write(stack,bytes(65536));put(0,0xcafebabe)
    put(0x131bb34,singleton);put(0x12588e8,world)
    put(singleton+0xc,type_array,type_array+4);put(type_array,types_at)
    put(owner+0x12c,1);put(source_region+0x12c,0 if other else 1)
    put(owner+0x194,buckets);put(owner+0x30c,pending,pending+3*0x278,pending+3*0x278)
    for i,t in enumerate(types):
        at=types_at+i*0x400;put(at,0xe365f8);put(at+0x30,t['limit']);put(at+0x3c,t['level'])
        u.mem_write(at+0x3d9,bytes([t['flag3d9']]))
    u.mem_write(types_at+0x3d8,bytes([special]))
    for i,group in enumerate((7,7,9)):put(cultures+i*0x100+0x50,group)
    for i in range(3):put(pending+i*0x278+0x58,0xffffffff if i%2 else 0,0x11220000+i,99)
    slot=case_index%3;source=pending+slot*0x278;payload(source,0xa5,0x278)
    s=2000001 if case_index%2 else 1000;sa=(0x7fffffffffffffff,32768,MASK)[case_index%3];sb=(0,32768000,MASK,0x8000000000000000)[case_index%4]
    put(source+0x58,s,77,88,source_region,types_at,cultures,0x101)
    qword(source+0x128,sa);qword(source+0x180,sb)
    for i,c in enumerate(candidates):
        at=nodes+i*0x288;payload(at,(case_index+i*31)%256)
        put(at+0x58,c['size'],77,c['size'],owner,types_at+c['type']*0x400,cultures+c['culture']*0x100,0x101+c['religion'])
        put(at+0x158,*[0xfffffff0+j for j in range(9)]);qword(at+0x128,65536);qword(at+0x180,0x7fffffffffffffff)
        qword(at+0x1e8,MASK-3);qword(at+0x218,MASK-5)
        put(at+0x278,nodes+(i-1)*0x288 if i else 0,nodes+(i+1)*0x288 if i+1<len(candidates) else 0)
    put(buckets,nodes,nodes+(len(candidates)-1)*0x288,len(candidates),0)
    put(world+0xacc,provinces);put(provinces,owner);put(world+0xc10,log_header);put(world+0xb0c,0x12345678)
    date_sentinel=struct.unpack('<I',u.mem_read(0x125a35c,4))[0]
    put(log_header,log_row,log_row+28,0,0,date_sentinel,0,0,0)
    put(log_row,outer_map);put(outer_map+4,outer_head,1)
    put(outer_head+4,outer_node);u.mem_write(outer_head+0x21,b'\1')
    put(outer_node,outer_head,outer_head,outer_head,0,0,inner_head,1)
    put(inner_head+4,inner_node);u.mem_write(inner_head+0x15,b'\1')
    put(inner_node,inner_head,inner_head,inner_head,0,0xabcdfff0)
    before=bytes(u.mem_read(arena,0x20000));expected=bytearray(before)
    if not no_match:
        target=nodes+selected*0x288;c=candidates[selected]
        result=merge(s,c['size'],sa,65536,sb,0x7fffffffffffffff,2 if other else 1)
        for off in (0x58,0x60):setword(expected,target+off,result['size'])
        setword(expected,target+0x5c,result['previous_size']);setqword(expected,target+0x128,result['attribute']);setqword(expected,target+0x180,result['balance'])
        setqword(expected,target+0x1e8,MASK-3+sb);setqword(expected,target+0x218,MASK-5+sb)
        at=target+0x158+4*result['event'];setword(expected,at,getword(expected,at)+s)
        for off,value in ((0x58,0),(0x5c,s),(0x60,0)):setword(expected,source+off,value)
        setqword(expected,source+0x180,0);setword(expected,owner+0x354,0x12345678);setword(expected,log_header+0x10,0x12345678)
        setword(expected,inner_node+0x10,0xabcd0000|((0xfff0+min(s,65535))&0xffff))
    sp=stack+0xf000;put(sp,stop,owner)
    for reg,value in preserved.items():u.reg_write(reg,value)
    u.reg_write(UC_X86_REG_ESP,sp);trace.clear();calls.clear();merge_targets.clear()
    u.emu_start(0x4ba780,stop,count=50000)
    assert trace==expected_trace,(case_index,trace,expected_trace)
    if no_match:
        assert u.reg_read(UC_X86_REG_EIP)==0x4baa33 and not calls and not merge_targets
        counts['no_match_prefix']+=1
    else:
        assert u.reg_read(UC_X86_REG_EIP)==stop and u.reg_read(UC_X86_REG_ESP)==sp+8
        assert all(u.reg_read(reg)==value for reg,value in preserved.items()) and bytes(u.mem_read(0,4))==struct.pack('<I',0xcafebabe)
        assert merge_targets==[nodes+selected*0x288]
        counts[stage]+=1;flagged_exact+=stage=='exact' and blocked
    actual=bytes(u.mem_read(arena,0x20000));assert actual==expected,(case_index,stage,[hex(i) for i,(a,b) in enumerate(zip(actual,expected)) if a!=b][:12])
    cases.append(dict(index=case_index,types=types,candidates=candidates,special=special,other_region=other,source_flag3d9=blocked,selected=selected,per_node_selected=per_node_selected,lowest_level_selected=lowest_level_selected,source_size=s,source_slot=slot,source_attribute=hex(sa),source_balance=hex(sb),stage=stage,trace=[list(x) for x in trace],execution='stopped_original_no_match_prefix' if no_match else 'complete_original_consumer',calls=list(calls),arena_sha256=hashlib.sha256(actual).hexdigest()))
assert all(counts[x]>0 for x in ('exact','level','group','lower','no_match_prefix')) and flagged_exact>0 and per_node_counterexamples>0 and lowest_level_counterexamples>0
out=ROOT/'evidence/generated/pop-selection';out.mkdir(parents=True,exist_ok=True)
for name,value in [('claims.json',claims),('reverify.json',report),('emulation.json',dict(binary_sha256=digest,cases=cases,counts=dict(counts),exact_flag3d9_nonzero_cases=flagged_exact,per_node_counterexamples=per_node_counterexamples,lowest_level_counterexamples=lowest_level_counterexamples,mismatches=0,scope='Full original4BA780 consumers for matched existing nodes with actual merge/size/balance/log/tree callees;no-match paths stop at4BAA33 before factory-selection body. Exact ordered search trace,whole128KiB fixture and selected target checked;ABI/FS0 only for full returns. Type40zero,positive candidate sizes,null optional,existing same-key movement trees. No stubs,no heap. Synthetic alternate-type/culture layouts do not prove real-world invariants;no complete no-match consumer,alternate factory selector,live tick/concurrency.'))]:
    (out/name).write_text(json.dumps(value,indent=2)+'\n')
ledger=Ledger.for_bytes(data,directory=ROOT/'.reverify');ledger.record(report,session='pop-existing-destination-selection');ledger.save()
print(f'POP selection: {len(claims)} static checks,{dict(counts)};{flagged_exact} exact matches despite source/type3d9 flag;{per_node_counterexamples} per-node strategy and{lowest_level_counterexamples} lowest-level counterexamples.')
