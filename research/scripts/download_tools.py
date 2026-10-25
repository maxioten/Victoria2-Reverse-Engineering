#!/usr/bin/env python3
"""Download pinned official assets and verify GitHub-provided SHA-256 digests."""
import hashlib
import json
from pathlib import Path
import shutil
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
DOWNLOADS = ROOT.parent / 'tools/downloads'
META = ROOT / 'evidence/tool-releases'
DOWNLOADS.mkdir(parents=True, exist_ok=True)
request = Request('https://api.github.com/repos/astral-sh/uv/releases/latest', headers={'User-Agent': 'victoria2-research'})
with urlopen(request, timeout=45) as response:
    uv = json.load(response)
(META / 'uv.json').write_text(json.dumps(uv, indent=2) + '\n')
selectors = {
    'ghidra': lambda n: n.startswith('ghidra_') and n.endswith('.zip'),
    'jdk': lambda n: 'jdk_x64_linux_hotspot' in n and n.endswith('.tar.gz'),
    'rizin': lambda n: n.endswith('static-x86_64.tar.xz'),
    'x64dbg': lambda n: n.startswith('snapshot_') and n.endswith('.zip'),
    'uv': lambda n: n == 'uv-x86_64-unknown-linux-gnu.tar.gz',
}
lock = {}
for name, select in selectors.items():
    release = json.loads((META / f'{name}.json').read_text())
    assets = [a for a in release['assets'] if select(a['name'])]
    if len(assets) != 1:
        raise SystemExit(f'Expected exactly one asset for {name}: {[a["name"] for a in assets]}')
    asset = assets[0]
    expected = asset.get('digest', '')
    if not expected.startswith('sha256:'):
        raise SystemExit(f'Official SHA-256 missing for {name}; do not run an unverified asset')
    path = DOWNLOADS / asset['name']
    if not path.exists():
        print('Downloading', name, release['tag_name'], asset['size'], flush=True)
        with urlopen(Request(asset['browser_download_url'], headers={'User-Agent': 'victoria2-research'}), timeout=120) as response, path.with_suffix(path.suffix + '.part').open('wb') as output:
            shutil.copyfileobj(response, output, length=1024 * 1024)
        path.with_suffix(path.suffix + '.part').rename(path)
    digest = hashlib.file_digest(path.open('rb'), 'sha256').hexdigest()
    if digest != expected.split(':', 1)[1]:
        raise SystemExit(f'SHA-256 mismatch: {path}')
    lock[name] = {'tag': release['tag_name'], 'published_at': release['published_at'],
                  'release': release['html_url'], 'url': asset['browser_download_url'],
                  'sha256': digest, 'asset': str(path.relative_to(ROOT.parent)), 'verified': True}
    (ROOT / 'toolchain.lock.json').write_text(json.dumps(lock, indent=2) + '\n')
    print('Verified', name, release['tag_name'], digest, flush=True)
