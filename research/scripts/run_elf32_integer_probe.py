#!/usr/bin/env python3
"""Execute unchanged helper bytes on the host's i386 ABI, without Wine or Unicorn."""
import hashlib
import json
from pathlib import Path
import platform
import struct
import subprocess
import pefile
from integer_model import MASK, test_pairs, trunc_div

ROOT = Path(__file__).resolve().parents[1]
target = ROOT.parent / 'base-game/v2game.exe'
data = target.read_bytes()
digest = hashlib.sha256(data).hexdigest()
if digest != '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648':
    raise SystemExit('Binary profile mismatch')
pe = pefile.PE(data=data)
out = ROOT / 'evidence/generated/elf32-integer'
out.mkdir(parents=True, exist_ok=True)
helpers = {}
for name,rva,length in [('divide',0x6c02a0,170),('multiply',0x6c9f20,52)]:
    code = pe.get_data(rva,length)
    assert code.endswith(b'\xc2\x10\x00')
    (out / f'original_{name}.bin').write_bytes(code)
    helpers[name] = {'rva':hex(rva),'length':length,'sha256':hashlib.sha256(code).hexdigest()}
fixtures, divisions = bytearray(), 0
for a,b in test_pairs():
    fixtures.extend(struct.pack('<QQQQI',a & MASK,b & MASK,
                                trunc_div(a,b) & MASK if b else 0,(a*b) & MASK,int(b != 0)))
    divisions += b != 0
records = len(test_pairs())
(out / 'fixtures.bin').write_bytes(fixtures)
(out / 'expected_counts.inc').write_text(f'.equ EXPECTED_RECORDS, {records}\n.equ EXPECTED_DIVISIONS, {divisions}\n')
source = ROOT / 'harnesses/elf32_integer_helpers.S'
subprocess.run(['as','--32','-I',str(out),str(source),'-o',str(out / 'probe.o')],cwd=out,check=True)
subprocess.run(['ld','-m','elf_i386','-z','noexecstack',str(out / 'probe.o'),'-o',str(out / 'integer-probe')],check=True)
binary = (out / 'integer-probe').read_bytes()
assert binary[:5] == b'\x7fELF\x01'
result = subprocess.run([str(out / 'integer-probe')],capture_output=True,text=True,timeout=30)
(out / 'execution.stdout').write_text(result.stdout)
(out / 'execution.stderr').write_text(result.stderr)
report = {
    'pass':result.returncode == 0 and result.stdout == 'PASS: ELF32 original arithmetic helpers\n',
    'binary_sha256':digest,'engine':'Linux ELF32/i386 process; original helper bytes executed directly',
    'host_machine':platform.machine(),'helpers':helpers,'fixture_records':records,'division_cases':divisions,
    'fixture_sha256':hashlib.sha256(fixtures).hexdigest(),'elf_sha256':hashlib.sha256(binary).hexdigest(),
    'harness_source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'exit_code':result.returncode,
    'scope':'Original isolated self-contained arithmetic bodies with their original stack ABI, '
            'Python golden values and Linux i386 entry/IO. Not a Windows runtime, whole-game trace, '
            'native zero-divisor test, register/stack post-state test or universal equivalence proof.',
}
(out / 'execution.json').write_text(json.dumps(report,indent=2)+'\n')
if not report['pass']:
    raise SystemExit(f'ELF32 probe did not pass: {result.returncode}; inspect generated receipt')
print(f'PASS: ELF32 direct execution, {divisions} divisions and {records} products; original bytes unchanged.')
