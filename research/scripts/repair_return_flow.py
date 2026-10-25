#!/usr/bin/env python3
"""Converge only the returning-wrapper candidate flow repair, preserving each pass."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
if not (ROOT / 'projects/before-return-flow-repair/victoria2-3.04.gpr').exists():
    raise SystemExit('Create a closed-project backup before candidate flow repair')
ghidra = Path(os.environ['GHIDRA_INSTALL_DIR']) / 'support/analyzeHeadless'
environment = dict(os.environ)
environment['JAVA_TOOL_OPTIONS'] = environment.get('JAVA_TOOL_OPTIONS','') + ' -Duser.home=' + str(ROOT / 'projects/tool-home')
stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
out = Path(tempfile.mkdtemp(prefix='return-flow-convergence-' + stamp + '-',dir=ROOT / 'evidence/generated'))
passes = []
for index in range(1,7):
    current = out / f'pass-{index}'
    current.mkdir()
    command = [str(ghidra),str(ROOT / 'projects'),'victoria2-3.04','-process','v2game.exe','-noanalysis',
               '-scriptPath',str(ROOT / 'ghidra_scripts'),'-postScript','RepairReturningCallers.java',str(current),
               '-postScript','AuditReturningWrapper.java',str(current),'-log',str(current / 'ghidra.log')]
    with (current / 'stdout.log').open('w') as log:
        subprocess.run(command,env=environment,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=180)
    summary = json.loads((current / 'repair-summary.json').read_text())
    audit = json.loads((current / 'saved-project-audit.json').read_text())
    if audit.get('pass') is not True:
        raise SystemExit('Metadata invariant failed; inspect ' + str(current))
    passes.append(summary)
    print(f'Pass {index}: missing={summary["missing_fallthrough_instructions"]}, '
          f'changed_bodies={summary["function_bodies_changed"]}, unowned={summary["no_owner_sites"]}',flush=True)
    if summary['missing_fallthrough_instructions'] == 0 and summary['function_bodies_changed'] == 0:
        (out / 'convergence.json').write_text(json.dumps({
            'converged':True,'passes':passes,'scope':'Only owned returning-wrapper call continuations; '
            'unowned sites and other noreturn claims remain unresolved; bodies are analyzer candidates.',
        },indent=2)+'\n')
        (ROOT / 'evidence/generated/latest-return-flow-convergence.txt').write_text(str(out)+'\n')
        print('Candidate flow converged: ' + str(out),flush=True)
        break
else:
    (out / 'convergence.json').write_text(json.dumps({'converged':False,'passes':passes},indent=2)+'\n')
    raise SystemExit('Candidate flow still changes after six passes; inspect ' + str(out))
