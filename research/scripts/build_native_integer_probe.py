#!/usr/bin/env python3
"""Extract exact helper bytes locally and compile the independent PE32 execution probe."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import pefile
from integer_model import MASK, test_pairs, trunc_div

ROOT = Path(__file__).resolve().parents[1]
data = (ROOT.parent / 'base-game/v2game.exe').read_bytes()
digest = hashlib.sha256(data).hexdigest()
if digest != '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648':
    raise SystemExit('Binary profile mismatch')
pe = pefile.PE(data=data)
out = ROOT / 'evidence/generated/native-integer'
out.mkdir(parents=True, exist_ok=True)
header, functions = [], {}
for name, rva, length in [('divide',0x6c02a0,170),('multiply',0x6c9f20,52)]:
    code = pe.get_data(rva, length)
    if not code.endswith(b'\xc2\x10\x00'):
        raise SystemExit('Expected RET 16 boundary not present')
    header.append('static const unsigned char original_' + name + '[] = {' +
                  ','.join(f'0x{byte:02x}' for byte in code) + '};\n')
    functions[name] = {'rva':hex(rva),'length':length,'sha256':hashlib.sha256(code).hexdigest()}
(out / 'original_integer_bytes.h').write_text('/* Locally generated original bytes; do not upload. */\n' + ''.join(header))
fixtures, division_count = bytearray(), 0
for a,b in test_pairs():
    quotient = trunc_div(a,b) & MASK if b else 0
    fixtures.extend(struct.pack('<QQQQI',a & MASK,b & MASK,quotient,(a*b) & MASK,int(b != 0)))
    division_count += b != 0
(out / 'fixtures.bin').write_bytes(fixtures)
compiler = ROOT.parent / 'tools/mingw-local/root/usr/bin/i686-w64-mingw32-gcc'
source = ROOT / 'harnesses/native_integer_helpers.c'
command = [str(compiler),'-std=c11','-O2','-Wall','-Wextra','-Werror','-static-libgcc',
           '-Wl,--dynamicbase,--nxcompat','-I',str(out),str(source),'-o',str(out / 'integer-probe.exe')]
subprocess.run(command,check=True)
(out / 'build.json').write_text(json.dumps({
    'binary_sha256':digest,'functions':functions,'fixture_sha256':hashlib.sha256(fixtures).hexdigest(),
    'fixture_records':len(test_pairs()),'expected_divisions':division_count,
    'exe_sha256':hashlib.sha256((out / 'integer-probe.exe').read_bytes()).hexdigest(),
    'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'compiler_command':command,
    'status':'compiled_only; native execution not yet validated',
},indent=2)+'\n')
print('Built PE32 integer probe and deterministic fixtures: ' + str(out))
