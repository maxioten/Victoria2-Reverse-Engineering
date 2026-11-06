"""Differentially execute the complete country preparation phase and its C replacement."""
import hashlib
import json
from pathlib import Path
import random
import struct
import time
import pefile
import unicorn as u
from unicorn.x86_const import *
from build_phase import LAB,ROOT,EXPECTED,START,END,sha

ARENA,SIZE,STACK,SP=0x22000000,0x200000,0x20000000,0x20008000
REGS={'eax':UC_X86_REG_EAX,'ebx':UC_X86_REG_EBX,'ecx':UC_X86_REG_ECX,
      'edx':UC_X86_REG_EDX,'esi':UC_X86_REG_ESI,'edi':UC_X86_REG_EDI,
      'ebp':UC_X86_REG_EBP,'esp':UC_X86_REG_ESP,'eflags':UC_X86_REG_EFLAGS,
      'fpcw':UC_X86_REG_FPCW,'fpsw':UC_X86_REG_FPSW,'fptag':UC_X86_REG_FPTAG,
      'mxcsr':UC_X86_REG_MXCSR,'xmm0':UC_X86_REG_XMM0}


def fixture(count,markets,length,ring,slot):
    data=bytearray(b'\xa5'*SIZE);cursor=0
    rng=random.Random(20261029+count*101+markets*31+length+ring*7+slot)
    writes=[]
    def alloc(size):
        nonlocal cursor
        address=ARENA+cursor;cursor+=(size+15)&~15
        assert cursor<=SIZE
        return address
    def put(address,*words):struct.pack_into('<'+str(len(words))+'I',data,address-ARENA,*words)
    def buffer(size):
        start=alloc(size+32)+16
        for off in range(0,size,4):put(start+off,rng.getrandbits(32))
        return start
    world=alloc(0xc00);array=alloc(max(count,1)*4)
    put(world+0xadc,array,array+max(count,0)*4)
    countries=[]
    for i in range(max(count,0)):
        country=alloc(0xf00);countries.append(country);put(array+i*4,country)
        for j in range(2):
            a,b=buffer(88),buffer(80)
            put(country+(j+11)*16,a);put(country+(j+13)*16,b)
            if j==ring:writes.extend([(a,88),(b,80)])
        vector=alloc(max(markets,1)*4)
        put(country+0xa0,vector,vector+markets*4)
        for m in range(markets):
            market=alloc(0x70);put(vector+m*4,market)
            for j in range(2):
                size=8*(length+(i+m)%3 if length else 0)
                values=buffer(size)
                put(market+0x28+j*16,values,values+size)
                put(market+0x48+j*8,rng.getrandbits(32),rng.getrandbits(32))
                if j==slot:writes.extend([(market+0x48+j*8,8),(values,size)])
        nodes=[alloc(16) for _ in range(i%4)]
        put(country+0xe44,nodes[0] if nodes else 0)
        for n,address in enumerate(nodes):put(address+8,nodes[n+1] if n+1<len(nodes) else 0)
        put(country+0xe78,rng.getrandbits(32),rng.getrandbits(32),0x12345678,0x87654321)
        writes.append((country+0xe80,8))
    expected=bytearray(data)
    for address,size in writes:expected[address-ARENA:address-ARENA+size]=bytes(size)
    for country in countries:
        expected[country-ARENA+0xe80:country-ARENA+0xe88]=data[country-ARENA+0xe78:country-ARENA+0xe80]
    return bytes(data),bytes(expected),world,writes,cursor


def compare(build):
    assert sha(ROOT/'base-game/v2game.exe')==EXPECTED
    meta=json.loads((build/'build.json').read_text())
    blob=(build/'phase.bin').read_bytes();assert hashlib.sha256(blob).hexdigest()==meta['blob_sha256']
    for name,digest in meta['sources'].items():assert sha(build/name)==digest
    pe=pefile.PE(str(ROOT/'base-game/v2game.exe'))
    emu=u.Uc(u.UC_ARCH_X86,u.UC_MODE_32)
    image_size=(pe.OPTIONAL_HEADER.SizeOfImage+4095)&~4095
    emu.mem_map(0x400000,image_size);emu.mem_write(0x400000,pe.get_memory_mapped_image())
    emu.mem_protect(0x400000,image_size,u.UC_PROT_READ|u.UC_PROT_EXEC)
    emu.mem_protect(0x1258000,4096,u.UC_PROT_READ|u.UC_PROT_WRITE)
    emu.mem_map(ARENA,SIZE);emu.mem_map(STACK,0x10000)
    for base in [0x30000000,0x30010000]:
        emu.mem_map(base,4096);emu.mem_write(base,blob)
        emu.mem_protect(base,4096,u.UC_PROT_READ|u.UC_PROT_EXEC)
    stop,fxstub,fxbuffer=0x30020000,0x30030000,0x30040000
    emu.mem_map(stop,4096,u.UC_PROT_READ|u.UC_PROT_EXEC)
    emu.mem_map(fxstub,4096);emu.mem_write(fxstub,b'\x0f\xae\x05'+struct.pack('<I',fxbuffer))
    emu.mem_protect(fxstub,4096,u.UC_PROT_READ|u.UC_PROT_EXEC);emu.mem_map(fxbuffer,4096)
    allowed=[]
    def guard(uc,access,address,length,value,user):
        assert any(a<=address and address+length<=a+s for a,s in allowed), ('Unexpected CPU write',hex(address),length)
    emu.hook_add(u.UC_HOOK_MEM_WRITE,guard)
    cases=[];began=time.monotonic()
    for count in [-1,0,1,2,8]:
      if meta['negative_candidate'] and count<=0:continue
      for markets in [0,1,3]:
       for length in [0,1,65]:
        for ring in [0,1]:
         for slot in [0,1]:
          initial,expected,world,writes,used=fixture(count,markets,length,ring,slot)
          allowed=writes+[(SP-0x1000,0x1000),(fxbuffer,512)]
          snapshots=[]
          for compiled in [False,True]:
            emu.mem_write(ARENA,initial);emu.mem_write(STACK,b'\xa5'*0x10000)
            emu.mem_write(0x1258738,struct.pack('<I',ring));emu.mem_write(0x12586e4,struct.pack('<I',slot))
            values={'eax':16,'ebx':world,'ecx':0x12345678,'edx':0x23456789,'esi':0,'edi':count&0xffffffff,
                    'ebp':SP+0x1200,'esp':SP,'eflags':0x202,'fpcw':0x27f if ring else 0x37f,
                    'fpsw':0,'fptag':0xffff,'mxcsr':0x3f80 if slot else 0x1f80,
                    'xmm0':0x1234567890abcdef1234567890abcdef}
            for key,value in values.items():emu.reg_write(REGS[key],value)
            if compiled:
                address=0x30000000+(len(cases)%2)*0x10000
                emu.mem_write(SP-4,struct.pack('<I',stop));emu.reg_write(UC_X86_REG_ESP,SP-4)
                emu.emu_start(address+meta['entry_offset'],stop,count=1000000)
                assert emu.reg_read(UC_X86_REG_EIP)==stop
            else:
                emu.emu_start(START,END,count=1000000)
                assert emu.reg_read(UC_X86_REG_EIP)==END
            registers={key:emu.reg_read(reg) for key,reg in REGS.items()}
            emu.mem_write(fxbuffer,bytes(512));emu.emu_start(fxstub,fxstub+7,count=1)
            snapshot={'registers':registers,'arena':bytes(emu.mem_read(ARENA,used)),
                      'fxsave':bytes(emu.mem_read(fxbuffer,512))}
            assert snapshot['arena']==expected[:used], ('Phase memory mismatch',count,markets,length,ring,slot,compiled)
            snapshots.append(snapshot)
          assert snapshots[0]==snapshots[1], ('Phase register/FPU mismatch',count,markets,length,ring,slot,
                                              snapshots[0]['registers'],snapshots[1]['registers'])
          cases.append({'countries':count,'markets_per_country':markets,'length_base':length,
                        'ring':ring,'slot':slot,'regions_written':len(writes),'arena_bytes_compared':used,
                        'arena_sha256':hashlib.sha256(snapshots[1]['arena']).hexdigest()})
    return {'status':'PASS','binary_sha256':EXPECTED,'blob_sha256':meta['blob_sha256'],
            'build_receipt_sha256':sha(build/'build.json'),'verifier_sha256':sha(Path(__file__)),
            'engine':'Unicorn '+u.__version__,'cases':cases,'writes_guarded':True,
            'original_phase_rva':[hex(START-0x400000),hex(END-0x400000)],
            'elapsed_seconds':time.monotonic()-began,'scope':'Complete daily country preparation phase on synthetic typed graphs; native integration pending.'}


if __name__=='__main__':
    report=compare(LAB/'evidence/build-1')
    try:compare(LAB/'evidence/negative-1')
    except AssertionError as exc:
        assert 'Phase memory mismatch' in str(exc), str(exc)
        report['negative_control']={'status':'REJECTED','reason':str(exc),'mutation':'Last word of 88-byte country buffer omitted'}
    else:raise AssertionError('Incorrect compiled candidate was accepted')
    (LAB/'evidence/emulated.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='cases'},indent=2))
    print('Scenarios:',len(report['cases']))
