#!/usr/bin/env python3
"""Reverify gate + negative controls + a persistent binary-keyed ledger."""
import hashlib
import json
from pathlib import Path
import struct
from reverify.verifier import Claim, Verifier
from reverify.ledger import Ledger

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT.parent / 'base-game/v2game.exe'
OUT = ROOT / 'evidence/generated/reverify'
OUT.mkdir(parents=True, exist_ok=True)
data = TARGET.read_bytes()
digest = hashlib.sha256(data).hexdigest()
expected_hash = '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'
if digest != expected_hash:
    raise SystemExit('Wrong binary profile; do not apply these claims to another executable')

# Candidates taken from the pinned reference. These assertions verify CALL bytes and
# operands, not the free-text function names or the behavior of their callees.
sites = [(0x32ecfa, 0x282ec0), (0x283ab1, 0x2859c0),
         (0x285f7e, 0x089990), (0x10861b, 0x11fd10)]
claims = []
for site, target in sites:
    ident = f'call_{site:x}'
    encoded = b'\xe8' + struct.pack('<i', target - (site + 5))
    claims.append({'id': ident, 'kind': 'bytes_at', 'offset': hex(site), 'space': 'rva',
                   'expected': encoded.hex()})
    claims.append({'id': ident + '_decoded', 'kind': 'instructions', 'depends_on': [ident],
                   'offset': hex(site), 'space': 'rva', 'length': 5, 'base': hex(0x400000 + site),
                   'arch': 'x86', 'mnemonics': ['call'], 'operands': [hex(0x400000 + target)]})
(OUT / 'claims.json').write_text(json.dumps(claims, indent=2) + '\n')
verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
(OUT / 'verified.json').write_text(json.dumps(report, indent=2) + '\n')
if any(r['verdict'] != 'VERIFIED' for r in report['results']):
    raise SystemExit('Gate failed: an inconclusive, invalidated or refuted assertion is not a fact')

# The gate must reject an intentionally wrong destination and invalidate its dependent.
wrong = dict(claims[0], id='negative_control', expected='e8c241f5ff')
dependent = dict(claims[1], id='negative_dependent', depends_on=['negative_control'])
controls = verifier.verify_all([Claim.from_dict(wrong), Claim.from_dict(dependent)])
(OUT / 'negative-controls.json').write_text(json.dumps(controls, indent=2) + '\n')
assert [r['verdict'] for r in controls['results']] == ['REFUTED', 'INVALIDATED'], controls

# A raw CALL does not prove where a whole function starts. Without angr this
# question must stay inconclusive; keep this diagnostic outside the established ledger.
semantic = verifier.verify(Claim.from_dict({'kind': 'function_at', 'offset': '0x2859c0', 'space': 'rva'}))
(OUT / 'semantic-limit.json').write_text(json.dumps(semantic, indent=2) + '\n')
ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify', file_path=str(TARGET))
ledger.start_run('Verify four direct CALL sites; no semantic function naming', session='environment-bootstrap')
ledger.record(report, rnd=1, session='environment-bootstrap')
ledger.finish_run(1, report['grounded'], report['information'])
ledger.save()
print(f'Reverify: {report["verified"]}/{report["total_claims"]} assertions verified; '
      'wrong-target control REFUTED; dependent INVALIDATED.')
print(f'Semantic boundary diagnostic: {semantic["verdict"]}. Ledger: {ledger.path}')
