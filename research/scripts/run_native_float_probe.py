#!/usr/bin/env python3
"""Run native conversions and contrast outputs with bounded integer models."""
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import struct
import subprocess
from float_model import decode, expected_bits, rounded_integer

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'evidence/generated/native-float'
build=json.loads((OUT/'build.json').read_text())
for path,expected in (
    (OUT/'float-probe.exe',build['exe_sha256']),
    (OUT/'fixtures.bin',build['fixture_sha256']),
    (ROOT/'harnesses/native_float_conversion.c',build['source_sha256']),
    (ROOT.parent/'base-game/v2game.exe',build['binary_sha256']),
    (ROOT/'scripts/float_model.py',build['model_source_sha256']),
):assert hashlib.sha256(path.read_bytes()).hexdigest()==expected,str(path)
attempt=OUT/('attempt-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ'))
attempt.mkdir()
(attempt/'build.json').write_text(json.dumps(build,indent=2)+'\n')
(attempt/'native_float_conversion.c').write_bytes((ROOT/'harnesses/native_float_conversion.c').read_bytes())
(attempt/'float_model.py').write_bytes((ROOT/'scripts/float_model.py').read_bytes())
environment=dict(os.environ,WINEPREFIX=str(ROOT/'projects/wine-probe'),WINEARCH='wow64',WINEDEBUG='-all',
                 WINEDLLOVERRIDES='winemenubuilder.exe=d')
fixture_path='Z:'+str(OUT/'fixtures.bin').replace('/','\\')
receipt={'pass':False,'binary_sha256':build['binary_sha256'],'source_sha256':build['source_sha256'],
         'fixture_sha256':build['fixture_sha256'],'exe_sha256':build['exe_sha256'],
         'model_source_sha256':build['model_source_sha256'],
         'build_script_sha256':hashlib.sha256((ROOT/'scripts/build_native_float_probe.py').read_bytes()).hexdigest(),
         'runner_script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
         'wine_version':subprocess.check_output(['wine','--version'],text=True).strip(),
         'block_sha256':build['block_sha256'],'loader_fixup_offsets':build['loader_fixup_offsets'],
         'scope':'Original 171-byte conversion block with two PE HIGHLOW relocations, binary64 and canonical extended80 inputs '
                 'loaded into ST(0), all exceptions masked, precision-control 64-bit, four x87/MXCSR '
                 'rounding modes, selector zero/one, three entries. Host FPU state saved/restored. '
                 'Rational model includes directed binary64 quantization and initial FISTP rounding/range. '
                 'No whole POP update, all possible extended inputs/encodings, unmasked exception, '
                 'other precision control or universal ABI/equivalence proof.',
         'preferred_global_selector_va':'0x13f3be0','selector_rva':'0xff3be0'}
try:
    result=subprocess.run(['wine',str(OUT/'float-probe.exe'),fixture_path],env=environment,
                          capture_output=True,text=True,timeout=120)
except subprocess.TimeoutExpired as error:
    def decoded(v):return v.decode(errors='replace') if isinstance(v,bytes) else v or ''
    stdout,stderr=decoded(error.stdout),decoded(error.stderr)
    receipt.update(status='execution_timeout',timeout_seconds=120)
else:
    stdout,stderr=result.stdout,result.stderr
    receipt.update(status='execution_failed',exit_code=result.returncode)
    if result.returncode==0:
        records=[json.loads(line) for line in stdout.splitlines() if line.startswith('{')]
        summaries=[r for r in records if r.get('kind')=='summary']
        cases=[r for r in records if r.get('kind')=='case']
        assert len(summaries)==1 and len(cases)==build['expected_cases']
        summary=summaries[0]
        assert summary['pass'] and summary['pointer_bytes']==4
        assert summary['records']==build['fixture_records'] and summary['cases']==len(cases)
        fixture_patterns=[]
        for raw,format_id,reserved in struct.iter_unpack('<10sHI',(OUT/'fixtures.bin').read_bytes()):
            assert format_id in (0,1) and reserved==0
            fixture_patterns.append((format_id,raw[:8 if format_id==0 else 10][::-1].hex()))
        expected_keys={(format_id,pattern,entry,flag,rounding) for format_id,pattern in fixture_patterns
                       for entry in (0,0x1c,0x36) for flag in (0,1) for rounding in range(4)}
        assert {(c['input_format'],c['input_bits'],c['entry_offset'],c['flag'],c['rounding']) for c in cases}==expected_keys
        mismatches=[]
        finite_in_range,exceptional=0,0
        for case in cases:
            fast=case['flag']!=0 and case['entry_offset'] in (0,0x1c)
            width=32 if fast else 64
            expected,in_range=expected_bits(case['input_format'],case['input_bits'],fast,case['rounding'])
            actual=case['eax'] if fast else case['eax'] | (case['edx']<<32)
            if actual!=expected or (fast and case['edx']!=0xa1a2a3a4):
                mismatches.append({**case,'fast':fast,'width':width,'expected_bits':hex(expected),'actual_bits':hex(actual)})
            finite_in_range+=in_range;exceptional+=not in_range
        by_key={(c['input_format'],c['input_bits'],c['entry_offset'],c['flag'],c['rounding']):c for c in cases}
        differences=[]
        rounding_differences=[]
        in_range_quantization=[]
        for format_id,pattern in fixture_patterns:
            slow=by_key[format_id,pattern,0,0,0];fast=by_key[format_id,pattern,0,1,0]
            if slow['eax']!=fast['eax']:
                differences.append({'input_format':format_id,'input_bits':pattern,'fallback_edx_eax':hex(slow['eax']|(slow['edx']<<32)),
                                    'fallback_low32':hex(slow['eax']),'fast_eax':hex(fast['eax'])})
                value=decode(format_id,pattern)
                if value is not None and -(1<<31)<=rounded_integer(value,3)<(1<<31):
                    in_range_quantization.append(differences[-1])
            rounded_outputs=[by_key[format_id,pattern,0,1,m]['eax'] for m in range(4)]
            if len(set(rounded_outputs))>1:
                rounding_differences.append({'input_format':format_id,'input_bits':pattern,
                                            'fast_eax_by_x87_rounding':list(map(hex,rounded_outputs))})
        receipt.update(status='model_mismatch' if mismatches else 'passed',observed=summary,
                       model_mismatches=mismatches,valid_intermediate_cases=finite_in_range,
                       indefinite_result_cases=exceptional,width_path_counterexamples=differences,
                       in_signed32_quantization_counterexamples=in_range_quantization,
                       fast_rounding_counterexamples=rounding_differences,
                       input_records_by_format={'binary64':build['binary64_records'],'extended80':build['extended80_records']},
                       actual_entry_va={hex(offset):hex(summary['private_image_base']+0x731c00+offset)
                                        for offset in (0,0x1c,0x36)},
                       actual_selector_va=hex(summary['private_image_base']+0xff3be0),
                       **{'pass':not mismatches})
receipt['stdout_sha256']=hashlib.sha256(stdout.encode()).hexdigest()
receipt['stderr_sha256']=hashlib.sha256(stderr.encode()).hexdigest()
for directory in (attempt,OUT):
    (directory/'execution.stdout').write_text(stdout)
    (directory/'execution.stderr').write_text(stderr)
    (directory/'execution.json').write_text(json.dumps(receipt,indent=2)+'\n')
if not receipt['pass']:raise SystemExit('Native conversion probe did not pass; inspect saved receipt')
print('PASS: native x87/SSE conversion cases: '+str(receipt['observed']))
