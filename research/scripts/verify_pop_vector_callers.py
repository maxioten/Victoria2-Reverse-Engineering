#!/usr/bin/env python3
"""Check direct callers/context routing and execute the third transfer wrapper.

Whole 4BA430 reuse path, with type+3d9 one skipping the separate recursive
preprocessing branch. Monthly prefix is a separately declared original fragment.
"""
import csv
import hashlib
import json
from pathlib import Path
import struct
import pefile
import unicorn
from unicorn.x86_const import *
from reverify.ledger import Ledger
from reverify.verifier import Claim,Verifier
from pop_transfer_model import transfer

ROOT=Path(__file__).resolve().parents[1]
data=(ROOT.parent/'base-game/v2game.exe').read_bytes();digest=hashlib.sha256(data).hexdigest()
assert digest=='62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'
pe=pefile.PE(data=data);base=pe.OPTIONAL_HEADER.ImageBase
snapshot=ROOT/'evidence/generated/ghidra-converged/calls.csv'
rows=list(csv.DictReader(snapshot.open()))
expected_sites={0x4beb50:{0x4ba6aa,0x534892,0x5349c3},0x534810:{0x957fdf,0x958394},0x534930:{0x958014},0x4ba430:{0x4ba61c,0x4ba62f,0x509a78,0x509acd,0x509ed8,0x509f24}}
claims=[]
for target,sites in expected_sites.items():
    found={int(r['site_va'],16) for r in rows if r['target_va'].lower()==f'{target:08x}'}
    assert found==sites,(hex(target),found)
    for site in sorted(sites):claims.append(dict(id=f'pop_vector_call_{site:x}',kind='instructions',space='rva',offset=hex(site-base),base=hex(site),arch='x86',length=5,mnemonics=['call'],operands=[hex(target)]))
for address,length,mnemonic,operand in (
    (0x957ebe,6,'mov','edx, dword ptr [0x12587e4]'),
    (0x957ec9,3,'mov','eax, dword ptr [edi + 0x64]'),
    (0x957ed2,6,'mov','eax, dword ptr [eax + 0x12c]'),
    (0x957edb,3,'mov','ecx, dword ptr [edx + 4]'),
    (0x957ede,3,'mov','edx, dword ptr [ecx + eax*4]'),
    (0x957eea,3,'mov','dword ptr [ebp - 0x1c], edx'),
    (0x4ba468,6,'jne','0x4ba63e'),
    (0x4ba63e,6,'mov','ebx, dword ptr [esi + 0x30c]'),
    (0x4ba644,6,'mov','ecx, dword ptr [esi + 0x310]'),
    (0x4ba670,4,'cmp','dword ptr [ebx + 0x58], 0'),
    (0x4ba737,3,'mov','dword ptr [ebx + 0x68], ecx'),
    (0x4ba762,6,'mov','esi, dword ptr [esi + 0x12c]'),
    (0x4ba76f,3,'mov','edx, dword ptr [ecx + 4]'),
    (0x4ba772,3,'mov','eax, dword ptr [edx + esi*4]'),
    (0x4ba70f,5,'call','0x5345a0'),
    (0x4ba728,3,'ret','8'),
    (0x4f6a39,6,'mov','dword ptr [ebx], 0xdffacc'),
    (0x4f6a67,3,'mov','dword ptr [ebx + 0x20], edx'),
    (0x4f6a6a,3,'mov','dword ptr [ebx + 0x34], esi'),
    (0x4f6a6d,3,'mov','dword ptr [ebx + 0x38], esi'),
    (0x4f6a70,3,'mov','dword ptr [ebx + 0x3c], esi'),
    (0x4f6a73,3,'mov','dword ptr [ebx + 0x44], esi'),
    (0x4f6a76,3,'mov','dword ptr [ebx + 0x48], esi'),
    (0x4f6a79,3,'mov','dword ptr [ebx + 0x4c], esi'),
    (0x4a84fa,6,'mov','dword ptr [esi], 0xdfd280'),
    (0x4a8736,6,'mov','dword ptr [esi + 0x30c], ebx'),
    (0x4a873c,6,'mov','dword ptr [esi + 0x310], ebx'),
    (0x4a8742,6,'mov','dword ptr [esi + 0x314], ebx'),
    (0x4ba79f,3,'mov','ebx, dword ptr [ebp + 8]'),
    (0x4ba7eb,6,'mov','ecx, dword ptr [ebx + 0x30c]'),
    (0x4ba7f1,6,'mov','edx, dword ptr [ebx + 0x310]'),
    (0x685f53,5,'call','0x4ba780'),
    (0x4bac60,3,'mov','edx, dword ptr [ebx + 0x68]'),
    (0x4bac63,2,'xor','edi, edi'),
    (0x4bac65,4,'cmp','byte ptr [edx + 0x40], 0'),
    (0x4bac69,2,'jne','0x4bac70'),
    (0x4bac6b,3,'mov','dword ptr [ebx + 0x60], edi'),
    (0x4bacda,3,'mov','eax, dword ptr [ebx + 0x58]'),
    (0x4bacdd,3,'mov','dword ptr [ebx + 0x5c], eax'),
    (0x4bace0,3,'mov','dword ptr [ebx + 0x58], edi'),
    (0x4bacf2,2,'xor','eax, eax'),
    (0x4bacf4,6,'mov','dword ptr [ebx + 0x180], eax'),
    (0x4bacfa,6,'mov','dword ptr [ebx + 0x184], eax'),
    (0x4baaf0,5,'call','0x4b8d30'),
    (0x4baaf9,5,'call','0x955a00'),
    (0x4bab32,5,'call','0x955fd0'),
    (0x957fb9,7,'cmp','byte ptr [ecx + 0x3d9], 0'),
    (0x957fc0,6,'jne','0x958dd6'),
):
    claims.append(dict(id=f'pop_vector_route_{address:x}',kind='instructions',space='rva',offset=hex(address-base),base=hex(address),arch='x86',length=length,mnemonics=[mnemonic],operands=[operand]))
for tag,td,col,hierarchy,table in (('country',0xf11ad8,0xe4dfdc,0xe4dff0,0xdffacc),('province',0xf11484,0xe4d164,0xe4d178,0xdfd280)):
    name=b'.?AVCCountry@@\0' if tag=='country' else b'.?AVCProvince@@\0'
    claims.extend([
        dict(id=f'pop_vector_{tag}_rtti_name',kind='bytes_at',space='rva',offset=hex(td+8-base),expected=name.hex()),
        dict(id=f'pop_vector_{tag}_rtti_locator',kind='bytes_at',space='rva',offset=hex(col-base),expected=struct.pack('<5I',0,0,0,td,hierarchy).hex()),
        dict(id=f'pop_vector_{tag}_rtti_link',kind='u32_at',space='rva',offset=hex(table-4-base),expected=col),
    ])
report=Verifier(data).verify_all([Claim.from_dict(c) for c in claims])
assert all(x['verdict']=='VERIFIED' for x in report['results']),report
uc=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_32)
image_size=(pe.OPTIONAL_HEADER.SizeOfImage+4095)&~4095
uc.mem_map(base,image_size);uc.mem_write(base,pe.get_memory_mapped_image());uc.mem_protect(base,image_size,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
uc.mem_protect(0x1258000,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
arena,stack,stop=0x20000000,0x20100000,0x21000000
uc.mem_map(arena,65536);uc.mem_map(stack,65536);uc.mem_map(0,4096);uc.mem_map(stop,4096)
source,owner,region,kind,other_kind,manager,array,contexts,slots=(arena,arena+0x1000,arena+0x2000,arena+0x3000,arena+0x3400,arena+0x4000,arena+0x4100,arena+0x5000,arena+0x7000)
def put(at,*values):uc.mem_write(at,struct.pack('<'+'I'*len(values),*[v&0xffffffff for v in values]))
def word(buf,at,value):struct.pack_into('<I',buf,at-arena,value&0xffffffff)
def get(buf,at):return struct.unpack_from('<I',buf,at-arena)[0]
vectors=(0x3c,0x7c,0x8c,0xa4,0xb4,0xcc,0xdc,0xf4,0x104)
def payload(at,pattern):
    uc.mem_write(at,bytes([pattern])*0x278);put(at,0xe36428,0x18d)
    for off in vectors:put(at+off,0,0,0)
    put(at+0x1d4,0)
def initialize_model(buf,target):
    for off in (0x6c,0x70,0x78,0xa0,0x128,0x12c):word(buf,target+off,get(buf,source+off))
    for off in (0x58,0x5c,0x118,0x11c,0x120,0x124,0x274,0x1c8,0x1cc,0x134,0x13c,0x140,0x144,0x30,0x34):word(buf,target+off,0)
    for off in (0x130,0x138):word(buf,target+off,0x8000)
    buf[target-arena+0x38]=0
allowed={0x4ba430,0x5345a0,0x955a00,0x43a750,0x9beeb0,0x955fd0,0x955f20,0xac02a0,0xac9f20}
calls=[];core_arguments=[]
def boundary(emu,address,length,_):
    assert address in allowed,f'excluded preprocessing/heap/cleanup path: {address:#x}'
    calls.append(hex(address))
    if address==0x5345a0:
        sp=emu.reg_read(UC_X86_REG_ESP)
        core_arguments.append((emu.reg_read(UC_X86_REG_EAX),*struct.unpack('<4I',emu.mem_read(sp+4,16))))
for at in allowed|{0x954f40,0x4beb50,0x955d40,0xaae9af,0xaae91b,0x967f10,0x4ee550,0x4d1020}:
    uc.hook_add(unicorn.UC_HOOK_CODE,boundary,begin=at,end=at)
def guard(emu,access,address,length,value,_):
    assert (arena<=address and address+length<=arena+65536) or (stack<=address and address+length<=stack+65536) or (address==0 and length==4),hex(address)
uc.hook_add(unicorn.UC_HOOK_MEM_WRITE,guard)
preserved={UC_X86_REG_EBX:0x12345678,UC_X86_REG_ESI:0x23456789,UC_X86_REG_EDI:0x3456789a,UC_X86_REG_EBP:0x456789ab}
cases=[]
for destination_index in range(3):
    for source_index in range(3):
        for selected in range(4):
            for size in (5,1000,2000000):
                for amount in (0,1,size):
                    uc.mem_write(arena,bytes(65536));uc.mem_write(stack,bytes(65536))
                    put(0x12587e4,manager);put(manager,3,array)
                    for i in range(3):put(array+i*4,contexts+i*0x400);put(contexts+i*0x400+0x20,i)
                    put(owner+0x128,0x778899aa,destination_index);put(region+0x128,0x22334455,source_index)
                    put(owner+0x30c,slots,slots+4*0x278,slots+5*0x278)
                    payload(source,0xa5);put(source+0x58,size,99,size,region,kind)
                    put(source+0x6c,0x101,0x202);put(source+0x78,0x303);put(source+0xa0,0x404);put(source+0x128,0x505,0x606)
                    put(source+0x158,*range(100,109));put(source+0x180,32768000,0)
                    uc.mem_write(kind+0x3d9,b'\x01')
                    target=slots+selected*0x278
                    for i in range(4):
                        at=slots+i*0x278;payload(at,0x5a)
                        put(at+0x58,0 if i>=selected else 17,88,0,owner,other_kind)
                        put(at+0x158,*range(200,209));put(at+0x180,333,0);put(at+0x274,1)
                    before=bytes(uc.mem_read(arena,65536))
                    # Original scheduled-update pointer route; no call or branch body substituted.
                    frame=stack+0x8000;sp=frame-0x100
                    uc.reg_write(UC_X86_REG_EBP,frame);uc.reg_write(UC_X86_REG_ESP,sp);uc.reg_write(UC_X86_REG_ECX,source)
                    for reg in (UC_X86_REG_EBX,UC_X86_REG_ESI,UC_X86_REG_EDI):uc.reg_write(reg,preserved[reg])
                    uc.emu_start(0x957ebe,0x957eed,count=30)
                    assert uc.reg_read(UC_X86_REG_EIP)==0x957eed
                    assert struct.unpack('<I',uc.mem_read(frame-0x1c,4))[0]==contexts+source_index*0x400
                    assert struct.unpack('<I',uc.mem_read(frame-0x48,4))[0]==0x22334455
                    assert bytes(uc.mem_read(arena,65536))==before
                    expected=bytearray(before);word(expected,target+0x68,kind);initialize_model(expected,target)
                    result=transfer(size,0,amount,32768000,333)
                    for off in (0x58,0x5c,0x60):word(expected,target+off,result['destination_size'])
                    for off in (0x58,0x60):word(expected,source+off,result['source_size'])
                    word(expected,source+0x5c,size)
                    same=source_index==destination_index;di=1 if same else 2;si=8 if same else 7
                    at=target+0x158+di*4;word(expected,at,get(expected,at)+result['amount'])
                    at=source+0x158+si*4;word(expected,at,get(expected,at)-result['amount'])
                    word(expected,target+0x64,region)
                    struct.pack_into('<Q',expected,source-arena+0x180,result['source_balance']);struct.pack_into('<Q',expected,target-arena+0x180,result['destination_balance'])
                    sp=stack+0xf000;put(sp,stop,source,amount);put(0,0xcafebabe)
                    for reg,value in preserved.items():uc.reg_write(reg,value)
                    uc.reg_write(UC_X86_REG_ECX,owner);uc.reg_write(UC_X86_REG_ESP,sp)
                    calls.clear();core_arguments.clear();uc.emu_start(0x4ba430,stop,count=20000)
                    assert uc.reg_read(UC_X86_REG_EIP)==stop and uc.reg_read(UC_X86_REG_ESP)==sp+12
                    assert all(uc.reg_read(reg)==value for reg,value in preserved.items())
                    assert bytes(uc.mem_read(0,4))==struct.pack('<I',0xcafebabe)
                    assert core_arguments==[(source,contexts+destination_index*0x400,target,amount,0)]
                    actual=bytes(uc.mem_read(arena,65536));assert actual==expected,(destination_index,source_index,selected,size,amount,[hex(i) for i,(a,b) in enumerate(zip(actual,expected)) if a!=b][:15])
                    wrapper_hash=hashlib.sha256(actual).hexdigest()
                    # Separate original cleanup subgraph, not the full consumer or its merge/new-node path.
                    after_cleanup=bytearray(actual);word(after_cleanup,target+0x60,0);word(after_cleanup,target+0x5c,get(after_cleanup,target+0x58));word(after_cleanup,target+0x58,0)
                    struct.pack_into('<Q',after_cleanup,target-arena+0x180,0)
                    cleanup_sp=stack+0xb000;put(cleanup_sp+0x14,0x11223344,0x55667788)
                    uc.reg_write(UC_X86_REG_EBX,target);uc.reg_write(UC_X86_REG_ESP,cleanup_sp)
                    uc.emu_start(0x4bac60,0x4bad00,count=40)
                    assert uc.reg_read(UC_X86_REG_EIP)==0x4bad00
                    cleaned=bytes(uc.mem_read(arena,65536));assert cleaned==after_cleanup
                    cases.append(dict(owner_index=destination_index,source_index=source_index,selected=selected,source_size=size,amount=amount,calls=list(calls),core_arguments=[list(x) for x in core_arguments],post_wrapper_sha256=wrapper_hash,post_cleanup_fragment_sha256=hashlib.sha256(cleaned).hexdigest()))
out=ROOT/'evidence/generated/pop-vector-callers';out.mkdir(parents=True,exist_ok=True)
for name,value in [('claims.json',claims),('reverify.json',report),('emulation.json',dict(binary_sha256=digest,cases=cases,mismatches=0,
    scope='Complete original4BA430 reuse path with type+3d9 one, optional resource null, type+40 zero, four null copied vectors and real transfer/size/region callees. Whole64KiB fixture,ABI,FS0 and actual core arguments checked. Separately original957EBE..957EED monthly context fragment and4BAC60..4BAD00 cleanup subgraph under type+40 zero; neither full monthly update nor full consumer or end-to-end tick. Type+3d9 one causes later monthly early-exit,so these are distinct experiments. Existing Ghidra direct-reference inventory not exhaustive indirect-call proof. No recursive preprocessing,append/growth,optional cleanup,live class provenance or game world validation.'))]:
    (out/name).write_text(json.dumps(value,indent=2)+'\n')
(out/'call-reference-snapshot.json').write_text(json.dumps(dict(binary_sha256=digest,calls_csv_sha256=hashlib.sha256(snapshot.read_bytes()).hexdigest(),direct_reference_sites={hex(t):[hex(s) for s in sorted(v)] for t,v in expected_sites.items()},scope='Existing saved Ghidra call references; direct CALL bytes independently checked; no exhaustive dynamic call graph.'),indent=2)+'\n')
ledger=Ledger.for_bytes(data,directory=ROOT/'.reverify');ledger.record(report,session='pop-vector-callers-and-context-routing');ledger.save()
print(f'POP vector callers: {len(claims)} static checks,{len(cases)} complete wrapper fixtures plus monthly context fragments;no mismatches.')
