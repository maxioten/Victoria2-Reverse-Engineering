"""Differentially execute original and compiled complete 1000-draw phase in Unicorn."""
import hashlib
import json
import os
from pathlib import Path
import random
import struct
import sys
import time

import pefile
import unicorn as u
from unicorn.x86_const import *
from build_phase import LAB, ROOT, EXPECTED, sha

sys.path.insert(0, str(ROOT/'research/scripts'))
from rng_model import initialize

BUILD = LAB/'evidence'/os.environ.get('V2_PHASE_BUILD','build-3')
REGS = {'eax':UC_X86_REG_EAX,'ebx':UC_X86_REG_EBX,'ecx':UC_X86_REG_ECX,
        'edx':UC_X86_REG_EDX,'esi':UC_X86_REG_ESI,'edi':UC_X86_REG_EDI,
        'ebp':UC_X86_REG_EBP,'esp':UC_X86_REG_ESP,'eflags':UC_X86_REG_EFLAGS,
        'fpcw':UC_X86_REG_FPCW,'fpsw':UC_X86_REG_FPSW,'fptag':UC_X86_REG_FPTAG,
        'mxcsr':UC_X86_REG_MXCSR,'xmm0':UC_X86_REG_XMM0}


def compare(blob=None):
    raw = (ROOT/'base-game/v2game.exe').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == EXPECTED
    build = json.loads((BUILD/'build.json').read_text())
    for name,digest in build['sources'].items():
        assert sha(BUILD/name)==digest, ('Frozen build source changed',name)
    if blob is None:
        blob = (BUILD/'phase.bin').read_bytes()
        assert hashlib.sha256(blob).hexdigest() == build['blob_sha256']
    pe = pefile.PE(data=raw)
    emu = u.Uc(u.UC_ARCH_X86, u.UC_MODE_32)
    size = (pe.OPTIONAL_HEADER.SizeOfImage+4095)&~4095
    emu.mem_map(0x400000,size)
    emu.mem_write(0x400000,pe.get_memory_mapped_image())
    emu.mem_protect(0x400000,size,u.UC_PROT_READ|u.UC_PROT_EXEC)
    emu.mem_protect(0xf0e000,0x2000,u.UC_PROT_READ|u.UC_PROT_WRITE)
    emu.mem_protect(0xf20000,0x1000,u.UC_PROT_READ|u.UC_PROT_WRITE)
    stack, frame = 0x20000000, 0x20008000
    sp = frame-0x1200
    output = frame-0x108c
    emu.mem_map(stack,0x10000)
    for address in [0x30000000,0x30010000]:
        emu.mem_map(address,0x1000)
        emu.mem_write(address,blob)
        emu.mem_protect(address,0x1000,u.UC_PROT_READ|u.UC_PROT_EXEC)
    stop = 0x30020000
    emu.mem_map(stop,0x1000,u.UC_PROT_READ|u.UC_PROT_EXEC)
    def write_guard(uc,access,address,length,value,user):
        valid = (0xf0ecf0 <= address and address+length <= 0xf0f6b4) or (
            address == 0xf20c14 and length == 4) or (
            output <= address and address+length <= output+4000) or (
            sp-0x1000 <= address and address+length <= sp)
        assert valid, ('Unexpected write',hex(address),length)
    emu.hook_add(u.UC_HOOK_MEM_WRITE,write_guard)
    randomizer = random.Random(20261028)
    vectors = [('seed-'+hex(seed),initialize(seed)) for seed in [0,1,5489,0x7fffffff,0x80000000,0xffffffff]]
    vectors += [('zeros',[0]*624),('ones',[0xffffffff]*624),('high-bit',[0x80000000]*624),
                ('alternating',[0xaaaaaaaa if i&1 else 0x55555555 for i in range(624)]),
                ('ascending',list(range(624))),('random',[randomizer.getrandbits(32) for _ in range(624)])]
    cases = []
    started = time.monotonic()
    for name, words in vectors:
        for index in [0,1,248,623]:
            for counter in [17,0xfffffff0]:
                initial = struct.pack('<625I',*words,index)
                snapshots = []
                for compiled in [False,True]:
                    emu.mem_write(stack,b'\xa5'*0x10000)
                    emu.mem_write(0xf0ecf0,initial)
                    emu.mem_write(0xf20c14,struct.pack('<III',counter,1,0x1234abcd))
                    values = {'eax':0x12345678,'ebx':0x23456789,'ecx':0x34567890,
                        'edx':0x45678901,'esi':0x56789012,'edi':0x67890123,'ebp':frame,'esp':sp,
                        'eflags':0x202,'fpcw':0x27f if index&1 else 0x37f,'fpsw':0,'fptag':0xffff,
                        'mxcsr':0x3f80 if index&1 else 0x1f80,'xmm0':0x1234567890abcdef1234567890abcdef}
                    for key,value in values.items():emu.reg_write(REGS[key],value)
                    if compiled:
                        address = 0x30000000+(len(cases)%2)*0x10000
                        emu.mem_write(sp-4,struct.pack('<I',stop))
                        emu.reg_write(UC_X86_REG_ESP,sp-4)
                        emu.reg_write(UC_X86_REG_EAX,0xf0ecf0)
                        emu.reg_write(UC_X86_REG_ECX,0xf20c14)
                        emu.reg_write(UC_X86_REG_EDX,output)
                        emu.emu_start(address+build['entry_offset'],stop,count=300000)
                        assert emu.reg_read(UC_X86_REG_EIP)==stop
                    else:
                        emu.emu_start(0x685b69,0x685c09,count=300000)
                        assert emu.reg_read(UC_X86_REG_EIP)==0x685c09
                    snapshots.append({'registers':{key:emu.reg_read(reg) for key,reg in REGS.items()},
                        'state':bytes(emu.mem_read(0xf0ecf0,2500)),
                        'globals':bytes(emu.mem_read(0xf20c14,12)),
                        'output':bytes(emu.mem_read(output,4000)),
                        'guards':bytes(emu.mem_read(output-16,16))+bytes(emu.mem_read(output+4000,16))})
                assert snapshots[0]==snapshots[1], (name,index,counter,
                    [key for key in snapshots[0] if snapshots[0][key]!=snapshots[1][key]],
                    snapshots[0]['registers'],snapshots[1]['registers'])
                final = snapshots[1]
                assert struct.unpack('<I',final['globals'][:4])[0] == (counter+1000)&0xffffffff
                assert struct.unpack_from('<I',final['state'],2496)[0] == (index+1000)%624
                cases.append({'vector':name,'initial_index':index,'initial_counter':counter,
                    'state_sha256':hashlib.sha256(final['state']).hexdigest(),
                    'output_sha256':hashlib.sha256(final['output']).hexdigest(),
                    'registers':final['registers']})
    return {'status':'PASS','binary_sha256':EXPECTED,'blob_sha256':hashlib.sha256(blob).hexdigest(),
        'build_receipt_sha256':sha(BUILD/'build.json'),'verifier_sha256':sha(Path(__file__)),
        'engine':'Unicorn '+u.__version__,'cases':cases,'outputs_compared':len(cases)*1000,
        'registers_compared':list(REGS),'memory_writes_guarded':True,'mismatches':0,
        'elapsed_seconds':time.monotonic()-started,
        'scope':'Complete existing-singleton RNG phase in emulation, original PE bytes versus compiled C/ABI bridge. '
                'Synthetic states; not yet a live-game replacement or proof for all possible states.'}


if __name__=='__main__':
    report=compare()
    BUILD = LAB/'evidence/negative-1'
    try:
        compare()
    except AssertionError as exc:
        # Accept only a completed differential mismatch containing output bytes.
        detail = exc.args[0]
        assert isinstance(detail, tuple) and len(detail) == 6 and 'output' in detail[3], str(exc)
        report['negative_control'] = {'status': 'REJECTED', 'mutation': 'Every RNG output low bit inverted'}
    else:
        raise AssertionError('Incorrect RNG candidate accepted')
    (LAB/'evidence/emulated.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS:',len(report['cases']),'cases,',report['outputs_compared'],'outputs, full state/register/FPU equality.')
