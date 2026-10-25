#!/usr/bin/env python3
"""Do not confuse successful import/export with complete Ghidra autoanalysis."""
import csv
import json
import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--output', type=Path, default=ROOT / 'evidence/generated/ghidra')
parser.add_argument('--existing-project', action='store_true')
parser.add_argument('--require-audit', action='store_true')
args = parser.parse_args()
OUT = args.output.resolve()
log = (OUT / 'analysis.log').read_text(errors='replace')
audit_file = OUT / 'saved-project-audit.json'
metadata_audit = json.loads(audit_file.read_text()) if audit_file.exists() else None
def count(name):
    with (OUT / name).open() as source:
        return sum(1 for _ in csv.DictReader(source))
report = {
    'import_saved': 'Import succeeded' in log and 'Save succeeded' in log,
    'existing_project': args.existing_project,
    'save_succeeded': 'Save succeeded' in log,
    'analysis_complete': 'Analysis timed out' not in log and 'Analysis succeeded' in log,
    'analysis_timed_out': 'Analysis timed out' in log,
    'metadata_audit': metadata_audit,
    'function_candidates': count('functions.csv'),
    'call_references': count('calls.csv'),
    'candidate_decompilations': len(list(OUT.glob('candidate_*.c'))),
    'semantics_confirmed': False,
    'limits': 'Analysis completion means the Ghidra pass finished, not that all recovered facts are correct. '
              'Automatic boundaries and references; indirect edges and types may be incomplete. '
              'Timeout state is retained even when Ghidra exits with code 0.',
}
(OUT / 'status.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
if args.require_audit and (metadata_audit is None or metadata_audit.get('pass') is not True):
    raise SystemExit('Saved-project metadata audit missing or failed')
