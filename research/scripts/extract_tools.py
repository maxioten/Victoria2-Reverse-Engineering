#!/usr/bin/env python3
"""Extract only verified official assets into separate local directories."""
import json
from pathlib import Path
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
for name, artifact in json.loads((ROOT / 'toolchain.lock.json').read_text()).items():
    if not artifact['verified']:
        raise SystemExit(f'Unverified asset: {name}')
    source = ROOT.parent / artifact['asset']
    dest = ROOT.parent / 'tools' / name
    if dest.exists() and any(dest.iterdir()):
        print('Already extracted:', name)
        continue
    dest.mkdir(parents=True, exist_ok=True)
    if source.suffix == '.zip':
        with zipfile.ZipFile(source) as archive:
            for entry in archive.infolist():
                if not (dest / entry.filename).resolve().is_relative_to(dest.resolve()):
                    raise SystemExit('Unsafe archive path')
            archive.extractall(dest)
        # Zip does not automatically preserve Unix executable mode.
        with zipfile.ZipFile(source) as archive:
            for entry in archive.infolist():
                mode = (entry.external_attr >> 16) & 0o777
                if mode and not entry.is_dir():
                    (dest / entry.filename).chmod(mode)
    else:
        with tarfile.open(source) as archive:
            archive.extractall(dest, filter='data')
    print('Extracted:', name, flush=True)
