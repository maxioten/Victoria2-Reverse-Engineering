"""Execute PE bytes and the independently compiled entire POP preparation phase."""
import bisect
import hashlib
import itertools
import json
from pathlib import Path
import random
import struct
import time
import capstone
import pefile
import unicorn as u
from unicorn.x86_const import *
from build_phase import LAB,ROOT,EXPECTED,START,END,sha

ARENA,SIZE,STACK,SP=0x22000000,0x400000,0x20000000,0x20008000
REGS={'eax':UC_X86_REG_EAX,'ebx':UC_X86_REG_EBX,'ecx':UC_X86_REG_ECX,
      'edx':UC_X86_REG_EDX,'esi':UC_X86_REG_ESI,'edi':UC_X86_REG_EDI,
      'ebp':UC_X86_REG_EBP,'esp':UC_X86_REG_ESP,'eflags':UC_X86_REG_EFLAGS,
      'fpcw':UC_X86_REG_FPCW,'fpsw':UC_X86_REG_FPSW,'fptag':UC_X86_REG_FPTAG,
      'mxcsr':UC_X86_REG_MXCSR,'xmm0':UC_X86_REG_XMM0,'xmm7':UC_X86_REG_XMM7}


def fixture(provinces,groups,length,style,seed):
    rng=random.Random(seed);data=bytearray(b'\xa5'*SIZE);cursor=0
    writes=[];reads=[];nodes=[];last=[];total_groups=0
    def alloc(size):
        nonlocal cursor
        a=ARENA+cursor;cursor+=(size+15)&~15
        assert cursor<=SIZE
        return a
    def put(a,*v):struct.pack_into('<'+str(len(v))+'I',data,a-ARENA,*v)
    world=alloc(0xc00);table=alloc(max(provinces,1)*4)
    put(world+0xacc,table,table+provinces*4);reads.append((world+0xacc,8))
    if provinces:reads.append((table,provinces*4))
    pair=struct.pack('<2I',rng.getrandbits(32),rng.getrandbits(32))
    for i in range(provinces):
        province=alloc(0x240);put(table+i*4,province)
        # Mixed province sizes exercise the last-province ABI separately.
        n=groups if style!=3 else (groups+i)%max(groups+1,1)
        group=alloc(max(n,1)*16);put(province+0x194,group,group+n*16)
        reads.append((province+0x194,8));total_groups+=n
        c=table;a=n*16
        for j in range(n):
            count=length
            if style==1 and j==n-1:count=0
            if style==2 and j==0:count=0
            if style==3:count=(length+i+j)%max(length+1,1)
            addresses=[alloc(0x290) for _ in range(count)]
            put(group+j*16,addresses[0] if addresses else 0);reads.append((group+j*16,4))
            c=group
            for k,pop in enumerate(addresses):
                for off in range(0,0x290,4):put(pop+off,rng.getrandbits(32))
                put(pop+0x27c,addresses[k+1] if k+1<count else 0)
                reads.append((pop+0x27c,4))
                writes.extend([(pop+0x158,36),(pop+0x1d8,72)])
                nodes.append(pop);c=struct.unpack_from('<I',pair)[0]
            a=0
        last=[a,c,province]
    expected=bytearray(data)
    for pop in nodes:
        expected[pop-ARENA+0x158:pop-ARENA+0x17c]=bytes(36)
        expected[pop-ARENA+0x1d8:pop-ARENA+0x220]=pair*9
    return bytes(data),bytes(expected),world,writes,reads,cursor,pair,last,len(nodes),total_groups


def compare(build):
    assert sha(ROOT/'base-game/v2game.exe')==EXPECTED
    meta=json.loads((build/'build.json').read_text());blob=(build/'phase.bin').read_bytes()
    assert hashlib.sha256(blob).hexdigest()==meta['blob_sha256']
    for name,digest in meta['sources'].items():assert sha(build/name)==digest
    pe=pefile.PE(str(ROOT/'base-game/v2game.exe'))
    emu=u.Uc(u.UC_ARCH_X86,u.UC_MODE_32)
    image_size=(pe.OPTIONAL_HEADER.SizeOfImage+4095)&~4095
    emu.mem_map(0x400000,image_size);emu.mem_write(0x400000,pe.get_memory_mapped_image())
    emu.mem_protect(0x400000,image_size,u.UC_PROT_READ|u.UC_PROT_EXEC)
    emu.mem_map(ARENA,SIZE);emu.mem_map(STACK,0x10000)
    for base in [0x30000000,0x30010000]:
        emu.mem_map(base,4096);emu.mem_write(base,blob)
        emu.mem_protect(base,4096,u.UC_PROT_READ|u.UC_PROT_EXEC)
    stop,fxstub,fxbuffer=0x30020000,0x30030000,0x30040000
    emu.mem_map(stop,4096,u.UC_PROT_READ|u.UC_PROT_EXEC)
    emu.mem_map(fxstub,4096);emu.mem_write(fxstub,b'\x0f\xae\x05'+struct.pack('<I',fxbuffer))
    emu.mem_protect(fxstub,4096,u.UC_PROT_READ|u.UC_PROT_EXEC);emu.mem_map(fxbuffer,4096)
    allowed=[];readable=[];write_starts=[];read_starts=[]
    def merged(spans):
        result=[]
        for a,n in sorted(spans):
            if not n:continue
            if result and a<=result[-1][1]:result[-1]=(result[-1][0],max(a+n,result[-1][1]))
            else:result.append((a,a+n))
        return result,[a for a,_ in result]
    def guard(uc,access,address,length,value,user):
        spans=allowed if access==u.UC_MEM_WRITE else readable
        starts=write_starts if access==u.UC_MEM_WRITE else read_starts
        i=bisect.bisect_right(starts,address)-1
        assert i>=0 and address+length<=spans[i][1], ('Unexpected CPU memory access',access,hex(address),length)
    emu.hook_add(u.UC_HOOK_MEM_WRITE|u.UC_HOOK_MEM_READ,guard)
    cases=[];began=time.monotonic()
    for count,groups,length,style in itertools.product([0,1,2,8],[0,1,3,9],[0,1,2,7,31],range(4)):
        if meta['negative_candidate'] and not (count and groups and length and style==0):continue
        initial,expected,world,writes,reads,used,pair,last,pops,total_groups=fixture(count,groups,length,style,20261029+len(cases))
        readable,read_starts=merged(reads+writes+[(SP-0x2000,0x2000),(fxbuffer,512),(0x131b890,8)])
        allowed,write_starts=merged(writes+[(SP-0x2000,0x2000),(fxbuffer,512)])
        snapshots=[]
        for compiled in [False,True]:
            emu.mem_write(ARENA,initial);emu.mem_write(STACK,b'\xa5'*0x10000)
            emu.mem_write(0x131b890,pair)
            values={'eax':0x9eabcdef,'ebx':world,'ecx':0x12345678,'edx':0x23456789,
                    'esi':0x3456789a,'edi':0x456789ab,'ebp':SP+0x1200,'esp':SP,
                    'eflags':0xa93 if style%2 else 0x246,'fpcw':0x27f if style%2 else 0x37f,
                    'fpsw':0,'fptag':0xffff,'mxcsr':0x3f80 if style%2 else 0x1f80,
                    'xmm0':0x1234567890abcdef1234567890abcdef,
                    'xmm7':0xfedcba9876543210fedcba9876543210}
            for key,value in values.items():emu.reg_write(REGS[key],value)
            if compiled:
                address=0x30000000+(len(cases)%2)*0x10000
                emu.mem_write(SP-4,struct.pack('<I',stop));emu.reg_write(UC_X86_REG_ESP,SP-4)
                emu.emu_start(address+meta['entry_offset'],stop,count=2000000)
                assert emu.reg_read(UC_X86_REG_EIP)==stop
            else:
                emu.emu_start(START,END,count=2000000)
                assert emu.reg_read(UC_X86_REG_EIP)==END
            registers={key:emu.reg_read(reg) for key,reg in REGS.items()}
            wanted=dict(values);wanted.update(eax=last[0] if count else 0,edi=count,
                eflags=(values['eflags']&~0x8d5)|0x44)
            if count:wanted.update(ecx=last[1],esi=last[2],edx=count)
            assert registers==wanted,('Phase register mismatch',count,groups,length,style,compiled,registers,wanted)
            emu.mem_write(fxbuffer,bytes(512));emu.emu_start(fxstub,fxstub+7,count=1)
            snapshot={'registers':registers,'arena':bytes(emu.mem_read(ARENA,used)),
                      'fxsave':bytes(emu.mem_read(fxbuffer,512))}
            assert snapshot['arena']==expected[:used],('Phase memory mismatch',count,groups,length,style,compiled)
            snapshots.append(snapshot)
        assert snapshots[0]==snapshots[1],('Original/C disagreement',count,groups,length,style)
        cases.append({'provinces':count,'groups_base':groups,'list_length_base':length,'style':style,
                      'groups':total_groups,'pops':pops,'arena_bytes_compared':used,
                      'arena_sha256':hashlib.sha256(snapshots[1]['arena']).hexdigest()})
    return {'status':'PASS','binary_sha256':EXPECTED,'blob_sha256':meta['blob_sha256'],
            'build_receipt_sha256':sha(build/'build.json'),'verifier_sha256':sha(Path(__file__)),
            'engine':'Unicorn '+u.__version__,'cases':cases,'cpu_reads_and_writes_guarded':True,
            'original_phase_rva':[hex(START-0x400000),hex(END-0x400000)],
            'elapsed_seconds':time.monotonic()-began,
            'scope':'Whole phase on synthetic typed graphs, full arena/GPR/FXSAVE comparison. Native pending.'}


if __name__=='__main__':
    report=compare(LAB/'evidence/build-1')
    try:compare(LAB/'evidence/negative-2')
    except AssertionError as exc:
        assert 'Phase memory mismatch' in str(exc),str(exc)
        report['negative_control']={'status':'REJECTED','reason':str(exc),
            'mutation':'Last high word in repeated global-pair copies omitted',
            'blob_sha256':sha(LAB/'evidence/negative-2/phase.bin')}
    else:raise AssertionError('Incorrect C candidate accepted')
    (LAB/'evidence/emulated.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='cases'},indent=2))
    print('Scenarios:',len(report['cases']))
