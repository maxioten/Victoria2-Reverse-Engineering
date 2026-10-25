#!/usr/bin/env python3
"""Characterize saved native observations without claiming a fresh execution."""
import hashlib
import json
from pathlib import Path
from float_model import decode, rounded_integer

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'evidence/generated/native-float'
receipt_path=OUT/'execution.json'
receipt=json.loads(receipt_path.read_text())
assert receipt['pass'] is True
stdout=(OUT/'execution.stdout').read_bytes()
assert hashlib.sha256(stdout).hexdigest()==receipt['stdout_sha256']
assert hashlib.sha256((ROOT/'scripts/float_model.py').read_bytes()).hexdigest()==receipt['model_source_sha256']
examples={}
for line in stdout.decode().splitlines():
    case=json.loads(line)
    if case.get('kind')!='case' or (case['flag'] and case['entry_offset'] in (0,28)):
        continue
    value=decode(case['input_format'],case['input_bits'])
    if value is None:continue
    naive=rounded_integer(value,3)
    actual=case['eax']|(case['edx']<<32)
    if -(1<<63)<=naive<(1<<63) and actual!=(naive&((1<<64)-1)):
        intermediate=rounded_integer(value,case['rounding'])
        examples[(case['input_format'],case['input_bits'],case['rounding'])]={
            'input_format':case['input_format'],'input_bits':case['input_bits'],
            'rounding':case['rounding'],'actual_bits':hex(actual),
            'truncation_bits':hex(naive&((1<<64)-1)),
            'mechanism':'INT64_MIN shortcut' if -(1<<63)<=intermediate<(1<<63) else 'FISTP intermediate outside signed64'}
report={
    'binary_sha256':receipt['binary_sha256'],
    'execution_receipt_sha256':hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
    'native_stdout_sha256':receipt['stdout_sha256'],'fresh_execution':False,
    'analysis_source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    'model_source_sha256':receipt['model_source_sha256'],
    'examples':list(examples.values()),
    'method':'Exact rational decode; compare saved observed fallback bits with the mathematical '
             'toward-zero integer when that integer fits signed64. Group equal input/mode observations.',
}
(OUT/'extended-counterexamples.json').write_text(json.dumps(report,indent=2)+'\n')
print(f'Extended conversion analysis: {len(examples)} distinct input/mode counterexamples to unconditional truncation.')
