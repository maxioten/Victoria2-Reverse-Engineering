#!/usr/bin/env python3
"""Run the prepared PE32 arithmetic probe and persist a hash-bound native receipt."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'evidence/generated/native-integer'
build = json.loads((OUT / 'build.json').read_text())
for path, expected in [
    (OUT / 'integer-probe.exe', build['exe_sha256']),
    (OUT / 'fixtures.bin', build['fixture_sha256']),
    (ROOT / 'harnesses/native_integer_helpers.c', build['source_sha256']),
    (ROOT.parent / 'base-game/v2game.exe', build['binary_sha256']),
]:
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise SystemExit('Artifact changed since compilation: ' + str(path))
environment = dict(os.environ, WINEPREFIX=str(ROOT / 'projects/wine-probe'), WINEARCH='wow64',
                   WINEDEBUG='-all', WINEDLLOVERRIDES='winemenubuilder.exe=d')
fixtures = 'Z:' + str(OUT / 'fixtures.bin').replace('/', '\\')
version = subprocess.check_output(['wine','--version'],text=True).strip()
command = ['wine',str(OUT / 'integer-probe.exe'),fixtures]
try:
    result = subprocess.run(command,capture_output=True,text=True,env=environment,timeout=180)
except subprocess.TimeoutExpired as error:
    def decoded(value):
        return value.decode(errors='replace') if isinstance(value,bytes) else (value or '')
    (OUT / 'execution.stdout').write_text(decoded(error.stdout))
    (OUT / 'execution.stderr').write_text(decoded(error.stderr))
    (OUT / 'execution.json').write_text(json.dumps({
        'pass':False,'status':'execution_timeout','timeout_seconds':180,
        'binary_sha256':build['binary_sha256'],'wine_version':version,
        'scope':'No successful probe result; not an arithmetic equivalence verdict.',
    },indent=2)+'\n')
    raise SystemExit('Wine probe exceeded its execution deadline; receipt saved')
(OUT / 'execution.stdout').write_text(result.stdout)
(OUT / 'execution.stderr').write_text(result.stderr)
if result.returncode != 0:
    (OUT / 'execution.json').write_text(json.dumps({
        'pass':False,'status':'execution_failed','exit_code':result.returncode,
        'binary_sha256':build['binary_sha256'],'wine_version':version,
        'scope':'No successful probe result; inspect stdout/stderr before classifying the cause.',
    },indent=2)+'\n')
    raise SystemExit(f'Native probe failed ({result.returncode}); inspect execution.stderr')
records = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
if len(records) != 1:
    raise SystemExit('Expected exactly one native probe result')
observed = records[0]
assert observed.get('pass') is True and observed.get('pointer_bytes') == 4
assert observed['records'] == build['fixture_records']
assert observed['multiplication_cases'] == build['fixture_records']
assert observed['division_cases'] == build['expected_divisions']
(OUT / 'execution.json').write_text(json.dumps({
    'pass':True,'binary_sha256':build['binary_sha256'], 'wine_version':version,
    'exe_sha256':build['exe_sha256'],'fixture_sha256':build['fixture_sha256'],
    'helper_code_sha256':build['functions'],'source_sha256':build['source_sha256'],
    'observed':observed,'exit_code':result.returncode,'wine_architecture_mode':'wow64',
    'scope':'Original isolated position-independent arithmetic bodies copied to RX memory in a PE32 '
            'process under Wine; golden results generated with Python integers. No whole-game runtime, '
            'zero-divisor native exception, caller fixed-point scaling or universal equivalence claim.',
},indent=2)+'\n')
print('PASS: PE32/Wine arithmetic execution; ' + str(observed))
