"""Build and differentially verify three bounded PE32 phases; keep all output local."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
EXPECTED = '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'
LABS = [('tick-recompile-lab', 'build-3', 'negative-1'),
        ('tick-country-prepare-lab', 'build-1', 'negative-1'),
        ('tick-pop-prepare-lab', 'build-1', 'negative-2')]


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    if not __debug__ or os.environ.get('PYTHONOPTIMIZE'):
        raise SystemExit('Assertions are verification checks: do not use Python -O/PYTHONOPTIMIZE.')
    binary = ROOT / 'base-game/v2game.exe'
    if not binary.is_file() or hashlib.sha256(binary.read_bytes()).hexdigest() != EXPECTED:
        raise SystemExit('Provide the exact locally owned reference at base-game/v2game.exe; see README.')
    # Preflight every directory before starting: never mix old receipts and new builds.
    for name, _, _ in LABS:
        if (ROOT/'experiments'/name/'evidence').exists():
            raise SystemExit(f'{name}/evidence already exists; preserve it and use a fresh checkout.')
    env = dict(os.environ, V2_PHASE_BUILD='build-3')
    for name, tag, negative in LABS:
        lab = ROOT/'experiments'/name
        def run(*args):
            subprocess.run([sys.executable, *args], cwd=ROOT, env=env, check=True)
        run(str(lab/'build_phase.py'), '--tag', tag)
        if negative:
            run(str(lab/'build_phase.py'), '--tag', negative, '--negative')
        run(str(lab/'verify_phase.py'))
    print(json.dumps({'status': 'PASS', 'binary_sha256': EXPECTED,
                      'scope': 'Synthetic differential fixtures only; no native campaign or complete engine.'}))


if __name__ == '__main__':
    main()
