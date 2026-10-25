#!/usr/bin/env python3
"""Ground the complete factory-internal selector's layout and direct calls."""
import csv
import hashlib
import json
from pathlib import Path
import capstone
import pefile
from reverify.ledger import Ledger
from reverify.verifier import Claim,Verifier

ROOT=Path(__file__).resolve().parents[1]
data=(ROOT.parent/'base-game/v2game.exe').read_bytes();digest=hashlib.sha256(data).hexdigest()
assert digest=='62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'
pe=pefile.PE(data=data);image=pe.get_memory_mapped_image();base=0x400000;claims=[]
cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
for at,mnemonic,operand in (
    (0x4b8c87,'mov','ecx, dword ptr [edi + 0x3d4]'),
    (0x4b8c92,'call','edx'),
    (0x4b8c96,'jne','0x4b8c9d'),
    (0x4b8c98,'mov','eax, edi'),
    (0x4b8c9c,'ret',''),
    (0x4b8ca2,'mov','esi, dword ptr [eax + 0x58]'),
    (0x4b8ca5,'mov','eax, dword ptr [0x1258728]'),
    (0x4b8cd2,'mov','ecx, dword ptr [eax]'),
    (0x4b8cd4,'imul','esi, esi, 0xb0'),
    (0x4b8cda,'mov','eax, dword ptr [esi + ecx + 8]'),
    (0x4b8cde,'mov','esi, dword ptr [eax + 0x108]'),
    (0x4b8ce4,'mov','ecx, dword ptr [eax + 0x10c]'),
    (0x4b8cec,'sar','ecx, 5'),
    (0x4b8cf3,'jle','0x4b8d17'),
    (0x4b8cf5,'mov','ebx, dword ptr [edi + 0x3d4]'),
    (0x4b8cfb,'add','esi, 8'),
    (0x4b8d00,'mov','edi, dword ptr [esi]'),
    (0x4b8d02,'cmp','edi, ebx'),
    (0x4b8d04,'je','0x4b8d1e'),
    (0x4b8d06,'mov','eax, dword ptr [ebp + 8]'),
    (0x4b8d09,'cmp','edi, eax'),
    (0x4b8d0b,'je','0x4b8d19'),
    (0x4b8d0e,'add','esi, 0x20'),
    (0x4b8d13,'jl','0x4b8d00'),
    (0x4b8d15,'mov','edi, eax'),
    (0x4b8d1d,'ret',''),
    (0x4b8d1f,'mov','eax, ebx'),
    (0x4b8d24,'ret',''),
):
    ins=next(cs.disasm(image[at-base:at-base+16],at))
    claims.append(dict(id=f'internal_selector_{at:x}',kind='instructions',space='rva',offset=hex(at-base),base=hex(at),arch='x86',length=ins.size,mnemonics=[mnemonic],operands=[operand]))
snapshot=ROOT/'evidence/generated/ghidra-converged/calls.csv'
rows=list(csv.DictReader(snapshot.open()))
expected_sites={0x4b8d5c,0x4b8f90,0x4b919a,0x4b96d7,0x95b4bc,0x95bbf0}
found={int(r['site_va'],16) for r in rows if r['target_va'].lower()=='004b8c80'}
assert found==expected_sites,(found,expected_sites)
for at in sorted(found):
    claims.append(dict(id=f'internal_selector_caller_{at:x}',kind='instructions',space='rva',offset=hex(at-base),base=hex(at),arch='x86',length=5,mnemonics=['call'],operands=['0x4b8c80']))
report=Verifier(data).verify_all([Claim.from_dict(c) for c in claims]);assert all(r['verdict']=='VERIFIED' for r in report['results']),report
out=ROOT/'evidence/generated/factory-internal-selector';out.mkdir(parents=True,exist_ok=True)
for name,value in [('claims.json',claims),('reverify.json',report),('call-reference-snapshot.json',dict(binary_sha256=digest,calls_csv_sha256=hashlib.sha256(snapshot.read_bytes()).hexdigest(),direct_call_sites=[hex(x) for x in sorted(found)],scope='Existing Ghidra direct-reference snapshot only;CALL instructions independently checked;not exhaustive indirect-call or caller semantics proof.'))]:
    (out/name).write_text(json.dumps(value,indent=2)+'\n')
ledger=Ledger.for_bytes(data,directory=ROOT/'.reverify');ledger.record(report,session='factory-internal-selector-and-callers');ledger.save()
print(f'Factory internal selector: {len(claims)} instruction/direct-call checks;native whole-entry evidence separate.')
