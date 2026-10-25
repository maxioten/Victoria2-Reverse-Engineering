#!/usr/bin/env python3
"""Inventory the exact PE and retain byte evidence without semantic guesses."""
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT.parent / 'base-game/v2game.exe'
EXPECTED = '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'
OUT = ROOT / 'evidence/generated/static'
OUT.mkdir(parents=True, exist_ok=True)
raw = TARGET.read_bytes()
digest = hashlib.sha256(raw).hexdigest()
if digest != EXPECTED:
    raise SystemExit(f'Unexpected target: {digest}; create a separate binary profile first')
pe = pefile.PE(data=raw)
if pe.FILE_HEADER.Machine != 0x14c or pe.OPTIONAL_HEADER.Magic != 0x10b:
    raise SystemExit('Expected x86 PE32')
image_base = pe.OPTIONAL_HEADER.ImageBase
def text(b):
    return b.decode('ascii', errors='backslashreplace') if b else None
inventory = {
    'path': str(TARGET), 'sha256': digest, 'file_size': len(raw),
    'machine': 'i386', 'format': 'PE32', 'image_base': image_base,
    'entry_rva': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
    'image_size': pe.OPTIONAL_HEADER.SizeOfImage,
    'aslr': bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x40),
    'large_address_aware': bool(pe.FILE_HEADER.Characteristics & 0x20),
    'sections': [{'name': text(s.Name.rstrip(b'\0')), 'rva': s.VirtualAddress,
                  'virtual_size': s.Misc_VirtualSize, 'file_offset': s.PointerToRawData,
                  'raw_size': s.SizeOfRawData, 'characteristics': s.Characteristics}
                 for s in pe.sections],
    'imports': [{'dll': text(d.dll), 'entries': [
        {'name': text(i.name), 'ordinal': i.ordinal, 'iat_va': i.address} for i in d.imports]}
        for d in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', [])],
    'exports': [{'name': text(s.name), 'ordinal': s.ordinal, 'rva': s.address}
                for s in getattr(getattr(pe, 'DIRECTORY_ENTRY_EXPORT', None), 'symbols', [])],
    'python': sys.version, 'host': platform.platform(),
    'reference_sources': [],
}
for label, repo in [('maxioten', ROOT.parent / 'references/victoria2-reverse-engineering'),
                    ('grand-loader', ROOT.parent / 'tools/grand-loader-upstream'),
                    ('v2dll', ROOT.parent / 'tools/v2dll-upstream')]:
    try:
        revision = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip()
        inventory['reference_sources'].append({'name': label, 'path': str(repo), 'revision': revision})
    except subprocess.CalledProcessError:
        inventory['reference_sources'].append({'name': label, 'unavailable': True})
(OUT / 'pe.json').write_text(json.dumps(inventory, indent=2) + '\n')

decoder = Cs(CS_ARCH_X86, CS_MODE_32)
sites = [(0x32ecfa, 0x282ec0), (0x283ab1, 0x2859c0),
         (0x285f7e, 0x089990), (0x10861b, 0x11fd10)]
evidence = []
for rva, expected_target in sites:
    code = pe.get_data(rva, 5)
    instructions = list(decoder.disasm(code, image_base + rva, count=1))
    ins = instructions[0] if instructions else None
    actual = rva + 5 + int.from_bytes(code[1:], 'little', signed=True) if code[:1] == b'\xe8' else None
    matched = actual == expected_target
    evidence.append({'binary_sha256': digest, 'site_rva': rva, 'site_va': image_base + rva,
                     'bytes': code.hex(), 'instruction': f'{ins.mnemonic} {ins.op_str}' if ins else None,
                     'actual_target_rva': actual, 'expected_target_rva': expected_target,
                     'status': 'confirmed' if matched else 'hypothesis', 'matched': matched,
                     'scope': 'Only direct CALL bytes and target, not function semantics',
                     'reproduce': 'python scripts/inventory.py'})
(OUT / 'call-sites.json').write_text(json.dumps(evidence, indent=2) + '\n')
print(f'PE inventory: {digest}; {len(inventory["imports"])} imported DLLs; '
      f'{sum(e["matched"] for e in evidence)}/{len(evidence)} candidate CALL sites match')
if not all(e['matched'] for e in evidence):
    raise SystemExit('At least one external candidate failed; inspect evidence, do not rename it')
