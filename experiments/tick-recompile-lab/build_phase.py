"""Compile a self-contained PE32 code blob; reject imports and absolute fixups."""
import hashlib
import os
import argparse
import json
from pathlib import Path
import shutil
import subprocess

import pefile

LAB = Path(__file__).resolve().parent
ROOT = LAB.parents[1]
EXPECTED = '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tag',default='build-1')
    parser.add_argument('--negative', action='store_true')
    args=parser.parse_args()
    assert Path(args.tag).name==args.tag and args.tag not in ['.','..']
    assert sha(ROOT/'base-game/v2game.exe') == EXPECTED
    out = LAB/'evidence'/args.tag
    out.mkdir(parents=True, exist_ok=False)
    for name in ['phase.c','entry.S','build_phase.py']:
        shutil.copy2(LAB/name, out/name)
    compiler = os.environ.get('V2_CC', 'i686-w64-mingw32-gcc')
    executable = out/'phase.exe'
    command = [str(compiler), '-std=c11','-O2','-Wall','-Wextra','-Werror',
        '-ffreestanding','-fno-stack-protector','-fno-asynchronous-unwind-tables',
        '-fno-unwind-tables','-fno-ident','-mno-sse','-mno-mmx','-msoft-float',
        '-fno-tree-loop-distribute-patterns','-nostdlib',
        '-Wl,--entry,_phase_entry,--image-base,0x10000000,--disable-dynamicbase',
        str(out/'phase.c'),str(out/'entry.S'),'-o',str(executable)]
    if args.negative: command.insert(1, '-DV2_BAD_OUTPUT')
    result = subprocess.run(command, capture_output=True, text=True)
    (out/'compiler.stdout').write_text(result.stdout)
    (out/'compiler.stderr').write_text(result.stderr)
    result.check_returncode()
    pe = pefile.PE(str(executable))
    assert pe.FILE_HEADER.Machine == 0x14c and pe.OPTIONAL_HEADER.Magic == 0x10b
    assert not getattr(pe, 'DIRECTORY_ENTRY_IMPORT', [])
    assert not any(e.type for b in getattr(pe,'DIRECTORY_ENTRY_BASERELOC',[]) for e in b.entries)
    sections = [s for s in pe.sections if s.Characteristics & 0x20000000]
    assert len(sections) == 1 and sections[0].Name.rstrip(b'\0') == b'.text'
    section = sections[0]
    blob = section.get_data()[:section.Misc_VirtualSize]
    entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint-section.VirtualAddress
    assert 0 <= entry < len(blob)
    (out/'phase.bin').write_bytes(blob)
    record = {'status':'compiled_only','binary_sha256':EXPECTED,
        'original_start_rva':'0x00285b69','original_stop_rva':'0x00285c09','original_image_base':'0x00400000',
        'sources':{name:sha(out/name) for name in ['phase.c','entry.S','build_phase.py']},
        'compiler':subprocess.check_output([str(compiler),'--version'],text=True).splitlines()[0],
        'compiler_command':command,'exe_sha256':sha(executable),'blob_sha256':sha(out/'phase.bin'),
        'blob_bytes':len(blob),'entry_offset':entry,'imports':0,'base_fixups':0,
        'scope':'Experimental complete existing-singleton 1000-draw phase. Semantic equivalence not yet verified.'}
    (out/'build.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record,indent=2))
