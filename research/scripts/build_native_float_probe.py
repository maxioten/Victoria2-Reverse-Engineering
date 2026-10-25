#!/usr/bin/env python3
"""Prepare binary64 fixtures and exact original conversion block for native PE32."""
import hashlib
import json
import math
from pathlib import Path
import struct
import subprocess
import pefile
from fractions import Fraction
from float_model import encode_extended, floor_log2, pow2

ROOT=Path(__file__).resolve().parents[1]
data=(ROOT.parent/'base-game/v2game.exe').read_bytes()
digest=hashlib.sha256(data).hexdigest()
assert digest=='62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'
pe=pefile.PE(data=data)
out=ROOT/'evidence/generated/native-float';out.mkdir(parents=True,exist_ok=True)
rva,length=0x731c00,0xab
code=pe.get_data(rva,length)
assert len(code)==length and code[-1]==0xc3
fixups=[e.rva-rva for block in pe.DIRECTORY_ENTRY_BASERELOC for e in block.entries
        if e.type==3 and rva<=e.rva<rva+length]
assert fixups==[2,0x1e],fixups
assert all(struct.unpack_from('<I',code,offset)[0]==0x13f3be0 for offset in fixups)
(out/'original_float_bytes.h').write_text('/* Locally generated original bytes; do not upload. */\n'+
    'static const unsigned char original_float_block[] = {'+','.join(hex(x) for x in code)+'};\n'+
    'static const unsigned original_float_fixups[] = {2, 0x1e};\n')
values=[0.0,-0.0,0.1,-0.1,0.5,-0.5,1.0,-1.0,1.5,-1.5,2.5,-2.5,1.9999999999999998,-1.9999999999999998]
for boundary in (2**24,2**31,2**32,2**53,2**63):
    for sign in (1,-1):
        value=float(sign*boundary)
        values.extend((math.nextafter(value,-math.inf),value,math.nextafter(value,math.inf)))
values.extend((2147483647.5,-2147483648.5,2147483648.5,-2147483649.5,
               math.ldexp(1.0,-1074),-math.ldexp(1.0,-1074),math.ldexp(1.0,-1022),-math.ldexp(1.0,-1022)))
patterns=list(dict.fromkeys(struct.unpack('<Q',struct.pack('<d',v))[0] for v in values))
patterns.extend(x for x in (0x7ff0000000000000,0xfff0000000000000,0x7ff8000000000000,0x7ff0000000000001)
                if x not in patterns)
extended=[]
for integer in (1,2,3,17,1000,2000000,2**24-1,2**31-1,2**31,2**32,2**53,2**63-1):
    step=pow2(floor_log2(Fraction(integer))-63)
    for sign in (1,-1):
        for delta in (-1,0,1):extended.append(encode_extended(sign*(integer+delta*step)))
for power in (0,1,24,31,32,53,63):
    for sign in (1,-1):extended.append(encode_extended(sign*(pow2(power)-pow2(power-64))))
extended=list(dict.fromkeys(extended))
fixtures=b''.join(struct.pack('<Q',x)+bytes(2)+struct.pack('<HI',0,0) for x in patterns)
fixtures+=b''.join(bytes.fromhex(x)[::-1]+struct.pack('<HI',1,0) for x in extended)
(out/'fixtures.bin').write_bytes(fixtures)
(out/'fixtures.json').write_text(json.dumps({'input_binary64_bits':[f'{x:016x}' for x in patterns],
                                           'input_extended80_bits':extended},indent=2)+'\n')
source=ROOT/'harnesses/native_float_conversion.c'
compiler=ROOT.parent/'tools/mingw-local/root/usr/bin/i686-w64-mingw32-gcc'
command=[str(compiler),'-std=c11','-O2','-Wall','-Wextra','-Werror','-static-libgcc','-msse2',
         '-Wl,--dynamicbase,--nxcompat','-I',str(out),str(source),'-o',str(out/'float-probe.exe')]
subprocess.run(command,check=True)
(out/'build.json').write_text(json.dumps({
    'binary_sha256':digest,'block_rva':hex(rva),'block_length':length,'block_sha256':hashlib.sha256(code).hexdigest(),
    'loader_fixup_offsets':fixups,'fixture_sha256':hashlib.sha256(fixtures).hexdigest(),
    'fixture_records':len(patterns)+len(extended),'expected_cases':(len(patterns)+len(extended))*24,
    'binary64_records':len(patterns),'extended80_records':len(extended),'fixture_record_bytes':16,
    'model_source_sha256':hashlib.sha256((ROOT/'scripts/float_model.py').read_bytes()).hexdigest(),
    'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
    'exe_sha256':hashlib.sha256((out/'float-probe.exe').read_bytes()).hexdigest(),
    'compiler_command':command,'status':'compiled_only',
},indent=2)+'\n')
print(f'Built PE32 float conversion probe: {len(patterns)} binary64 + {len(extended)} extended80 fixtures, {(len(patterns)+len(extended))*24} cases.')
