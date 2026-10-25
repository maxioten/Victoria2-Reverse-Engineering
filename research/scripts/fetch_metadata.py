#!/usr/bin/env python3
"""Resolve official releases; save metadata before selecting or executing downloads."""
import json
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
REPOS = {
    'ghidra': 'NationalSecurityAgency/ghidra',
    'jdk': 'adoptium/temurin25-binaries',
    'rizin': 'rizinorg/rizin',
    'cutter': 'rizinorg/cutter',
    'x64dbg': 'x64dbg/x64dbg',
    'frida': 'frida/frida',
    'capstone': 'capstone-engine/capstone',
    'lief': 'lief-project/LIEF',
    'unicorn': 'unicorn-engine/unicorn',
}
dest = ROOT / 'evidence/tool-releases'
dest.mkdir(parents=True, exist_ok=True)
for name, repo in REPOS.items():
    url = f'https://api.github.com/repos/{repo}/releases/latest'
    request = Request(url, headers={'User-Agent': 'victoria2-research', 'Accept': 'application/vnd.github+json'})
    try:
        with urlopen(request, timeout=45) as response:
            data = json.load(response)
        (dest / f'{name}.json').write_text(json.dumps(data, indent=2) + '\n')
        print(name, data['tag_name'], data['published_at'], data['html_url'], flush=True)
        for asset in data.get('assets', []):
            if name in ('ghidra', 'rizin', 'x64dbg') or (name == 'jdk' and 'jdk_x64_linux_hotspot' in asset['name'] and asset['name'].endswith('.tar.gz')):
                print(' ', asset['name'], asset['size'], asset.get('digest'), asset['browser_download_url'], flush=True)
    except Exception as exc:
        print(name, 'UNAVAILABLE', str(exc), flush=True)
