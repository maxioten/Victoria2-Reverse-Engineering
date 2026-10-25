#!/usr/bin/env python3
"""Execute the isolated synthetic POP lifetime probe under the dedicated Wine prefix."""
import hashlib
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'evidence/generated/native-pop'
build = json.loads((OUT / 'build.json').read_text())
attempt = OUT / ('attempt-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ'))
attempt.mkdir()
(attempt / 'build.json').write_text(json.dumps(build, indent=2) + '\n')
(attempt / 'native_pop_lifetime.c').write_bytes((ROOT / 'harnesses/native_pop_lifetime.c').read_bytes())
(attempt / 'native_registry_cases.h').write_bytes((ROOT / 'harnesses/native_registry_cases.h').read_bytes())
for path, expected in [
    (OUT / 'pop-probe.exe', build['exe_sha256']),
    (ROOT / 'harnesses/native_pop_lifetime.c', build['source_sha256']),
    (ROOT / 'harnesses/native_registry_cases.h', build['registry_source_sha256']),
    (ROOT.parent / 'base-game/v2game.exe', build['binary_sha256']),
]:
    assert hashlib.sha256(path.read_bytes()).hexdigest() == expected, str(path)
environment = dict(os.environ, WINEPREFIX=str(ROOT / 'projects/wine-probe'), WINEARCH='wow64',
                   WINEDEBUG='-all', WINEDLLOVERRIDES='winemenubuilder.exe=d')
reference = 'Z:' + str(ROOT.parent / 'base-game/v2game.exe').replace('/', '\\')
version = subprocess.check_output(['wine', '--version'], text=True).strip()
receipt = {
    'pass': False, 'binary_sha256': build['binary_sha256'],
    'source_sha256': build['source_sha256'], 'exe_sha256': build['exe_sha256'],
    'registry_source_sha256': build['registry_source_sha256'],
    'wine_version': version, 'wine_architecture_mode': 'wow64',
    'fixture_writes_va': build['fixture_writes_va'],
    'private_reference_base': build['private_reference_base'], 'loader_delta': build['loader_delta'],
    'build_script_sha256': hashlib.sha256((ROOT / 'scripts/build_native_pop_probe.py').read_bytes()).hexdigest(),
    'runner_script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    'relocated_fixture_writes_va': {
        hex(int(address, 16) + int(build['loader_delta'], 16)): purpose
        for address, purpose in build['fixture_writes_va'].items()
    },
    'scope': 'Original code with PE HIGHLOW loader relocations in a private reference-image mapping, no engine entry/TLS/init. '
             'Synthetic HeapAlloc nodes and 0..3 RTTI-linked CRegiment fixtures; absent registries, '
             'global state +0xd1d=1 and +0xd1c=0, null regiment +0x74. '
             'Also standalone registry first-key removal and deregistration with controlled live tables. '
             'Includes insertion, five explicit-key and 36 automatic-ID registered-POP lifecycles with empty owned containers. '
             'Three isolated original-lock cases include controlled worker-thread contention and real SwitchToThread. '
             'Real successful HeapAlloc/HeapFree forwarded by recording IAT callbacks; native FS:0 restored. No failure paths, '
             'live game objects, country/type bookkeeping, army callbacks, parallel registry mutation, duplicate-key error or exception unwinding tested.',
}
try:
    result = subprocess.run(['wine', str(OUT / 'pop-probe.exe'), reference], capture_output=True,
                            text=True, env=environment, timeout=120)
except subprocess.TimeoutExpired as error:
    def decoded(value):
        return value.decode(errors='replace') if isinstance(value, bytes) else value or ''
    stdout, stderr = decoded(error.stdout), decoded(error.stderr)
    receipt.update(status='execution_timeout', timeout_seconds=120)
else:
    stdout, stderr = result.stdout, result.stderr
    receipt.update(status='execution_failed', exit_code=result.returncode)
    if result.returncode == 0:
        records = [json.loads(line) for line in stdout.splitlines() if line.startswith('{')]
        summaries = [r for r in records if r.get('kind') == 'summary']
        cases = [r for r in records if r.get('kind') == 'case']
        assert len(summaries) == 1, stdout
        observed = summaries[0]
        assert observed.get('pass') is True and observed['pointer_bytes'] == 4
        for field in ('cases', 'actual_heap_frees', 'pre_free_snapshots', 'registry_cases', 'registry_heap_frees',
                      'actual_heap_allocs', 'registered_pop_cases', 'automatic_id_cases', 'lock_cases'):
            assert observed[field] == build['expected_' + field], (field, observed)
        assert len(cases) == build['expected_cases']
        for entry, count in build['expected_cases_by_entry'].items():
            assert sum(case.get('entry', 'pop_unlink') == entry for case in cases) == count, entry
        assert sum(case['original_heap_frees'] for case in cases) == observed['actual_heap_frees']
        assert sum(case.get('original_heap_allocs', 0) for case in cases) == observed['actual_heap_allocs']
        for case in cases:
            if case.get('entry') == 'automatic_pop_lifecycle':
                assert case['key_type'] == case['namespace'] + 0x1268
                assert case['key_id'] == (case['seed'] + 1) & 0xffffffff
            if case.get('entry') == 'spinlock_acquire':
                assert (case['yield_calls'] == 0) if case['initial_byte'] == 0 else (case['yield_calls'] > 0)
        assert observed['highlow_relocations'] == build['highlow_relocations']
        receipt.update(status='passed', observed=observed, cases=cases, **{'pass': True})
for directory in (attempt, OUT):
    (directory / 'execution.stdout').write_text(stdout)
    (directory / 'execution.stderr').write_text(stderr)
    (directory / 'execution.json').write_text(json.dumps(receipt, indent=2) + '\n')
if not receipt['pass']:
    raise SystemExit('Native POP probe did not pass; inspect local receipt and stderr')
print('PASS: PE32/Wine original POP lifetime paths: ' + str(receipt['observed']))
