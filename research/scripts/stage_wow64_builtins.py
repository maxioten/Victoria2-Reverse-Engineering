#!/usr/bin/env python3
"""Stage only missing installed Wine PE32 core DLLs in the dedicated probe prefix."""
import hashlib
import json
from pathlib import Path
import shutil
import pefile

ROOT=Path(__file__).resolve().parents[1]
prefix=ROOT/'projects/wine-probe'
if '#arch=win64' not in (prefix/'system.reg').read_text(errors='replace'):
    raise SystemExit('Expected the dedicated win64 probe prefix')
destination=prefix/'drive_c/windows/syswow64'
destination.mkdir(parents=True,exist_ok=True)
manifest=[]
for name in ('ntdll.dll','kernel32.dll','kernelbase.dll','ucrtbase.dll'):
    source=Path('/usr/lib/wine/i386-windows')/name
    target=destination/name
    raw=source.read_bytes()
    pe=pefile.PE(data=raw,fast_load=True)
    if pe.FILE_HEADER.Machine!=0x14c:
        raise SystemExit('Expected installed PE32/i386 DLL: '+name)
    added=not target.exists()
    if added:shutil.copy2(source,target)
    manifest.append({'name':name,'added':added,'source':str(source),
                     'source_sha256':hashlib.sha256(raw).hexdigest(),
                     'destination_sha256':hashlib.sha256(target.read_bytes()).hexdigest()})
out=ROOT/'evidence/generated/native-integer'
(out/'staged-wow64-builtins.json').write_text(json.dumps({
    'prefix':str(prefix),'files':manifest,
    'scope':'Only missing files in a dedicated experimental prefix; installed Wine DLLs unchanged. '
            'Staging does not establish that initialization or PE32 execution works.',
},indent=2)+'\n')
print('Staged missing PE32 core DLLs in the experimental prefix; execution remains to be tested.')
