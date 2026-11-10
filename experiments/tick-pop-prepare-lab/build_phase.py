"""Compile only the reconstructed complete daily province/POP preparation phase."""
import os
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import pefile

LAB=Path(__file__).resolve().parent
ROOT=LAB.parents[1]
EXPECTED='62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'
START,END=0x685ae4,0x685b22


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tag',default='build-1')
    parser.add_argument('--negative',action='store_true')
    args=parser.parse_args()
    assert Path(args.tag).name==args.tag and args.tag not in ('.','..')
    assert sha(ROOT/'base-game/v2game.exe')==EXPECTED
    out=LAB/'evidence'/args.tag;out.mkdir(parents=True,exist_ok=False)
    names=['phase.c','entry.S','build_phase.py']
    for name in names:shutil.copy2(LAB/name,out/name)
    compiler=os.environ.get('V2_CC', 'i686-w64-mingw32-gcc')
    command=[str(compiler),'-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding',
             '-fno-builtin','-fno-stack-protector','-fno-asynchronous-unwind-tables',
             '-fno-unwind-tables','-fno-ident','-fno-tree-loop-distribute-patterns',
             '-mno-sse','-mno-mmx','-msoft-float','-nostdlib',
             '-Wl,--entry,_phase_entry,--image-base,0x10000000,--disable-dynamicbase',
             str(out/'phase.c'),str(out/'entry.S'),'-o',str(out/'phase.exe')]
    if args.negative:command.insert(1,'-DV2_OMIT_LAST_WORD')
    result=subprocess.run(command,capture_output=True,text=True)
    (out/'compiler.stdout').write_text(result.stdout);(out/'compiler.stderr').write_text(result.stderr)
    result.check_returncode()
    pe=pefile.PE(str(out/'phase.exe'))
    assert pe.FILE_HEADER.Machine==0x14c and not getattr(pe,'DIRECTORY_ENTRY_IMPORT',[])
    assert not any(e.type for b in getattr(pe,'DIRECTORY_ENTRY_BASERELOC',[]) for e in b.entries)
    sections=[s for s in pe.sections if s.Characteristics&0x20000000];assert len(sections)==1
    section=sections[0];blob=section.get_data()[:section.Misc_VirtualSize]
    entry=pe.OPTIONAL_HEADER.AddressOfEntryPoint-section.VirtualAddress
    assert 0<=entry<len(blob)
    (out/'phase.bin').write_bytes(blob)
    record={'status':'compiled_only','binary_sha256':EXPECTED,'negative_candidate':args.negative,
            'original_start_rva':hex(START-0x400000),'original_end_rva':hex(END-0x400000),
            'image_base':'0x00400000','sources':{name:sha(out/name) for name in names},
            'compiler_command':command,'compiler':subprocess.check_output([str(compiler),'--version'],text=True).splitlines()[0],
            'blob_sha256':sha(out/'phase.bin'),'exe_sha256':sha(out/'phase.exe'),
            'blob_bytes':len(blob),'entry_offset':entry,'imports':0,'base_fixups':0,
            'scope':'Complete daily province/POP preparation loop, including independent reset and global pair copy; semantic verification pending.'}
    (out/'build.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({k:record[k] for k in ['status','blob_bytes','blob_sha256','entry_offset','negative_candidate']},indent=2))
