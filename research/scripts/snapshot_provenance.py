#!/usr/bin/env python3
"""Record local source revisions and baseline/patch separation for later sessions."""
import hashlib
from importlib import metadata
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT.parent
repos = {
    'maxioten': BASE / 'references/victoria2-reverse-engineering',
    'grand-loader': BASE / 'tools/grand-loader-upstream',
    'v2dll': BASE / 'tools/v2dll-upstream',
    'reverify': BASE / 'tools/reverify',
}
report = {'repositories': {}, 'binary_baseline': {}, 'parked_patches': {}}
for name, path in repos.items():
    report['repositories'][name] = {
        'path': str(path),
        'revision': subprocess.check_output(['git', '-C', str(path), 'rev-parse', 'HEAD'], text=True).strip(),
        'remote': subprocess.check_output(['git', '-C', str(path), 'remote', 'get-url', 'origin'], text=True).strip(),
        'status': subprocess.check_output(['git', '-C', str(path), 'status', '--porcelain'], text=True).splitlines(),
    }
for name in ['v2game.exe', 'lua51.dll', 'tbb.dll', 'steam_api.dll']:
    report['binary_baseline'][name] = hashlib.sha256((BASE / 'base-game' / name).read_bytes()).hexdigest()
for path in (BASE / 'experiments/installed-patches').rglob('*'):
    if path.is_file():
        report['parked_patches'][str(path.relative_to(BASE))] = hashlib.sha256(path.read_bytes()).hexdigest()
report['reverify_installed_version'] = metadata.version('reverify')
(ROOT / 'evidence/provenance.json').write_text(json.dumps(report, indent=2) + '\n')
print('Saved source revisions, repository changes, baseline hashes and parked patch hashes')
