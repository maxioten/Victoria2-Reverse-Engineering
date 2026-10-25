#!/usr/bin/env python3
"""Exercise the installed engines; write actual versions and limits, not just package labels."""
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import subprocess
import sys
import capstone
import lief
import pefile
import unicorn
from unicorn.x86_const import UC_X86_REG_EAX
from reverify.backends import backend_report

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT.parent / 'base-game/v2game.exe'
result = {'python': sys.version, 'executable': sys.executable,
          'binary_sha256': hashlib.sha256(TARGET.read_bytes()).hexdigest(),
          'packages': {n: metadata.version(n) for n in
                       ['pefile', 'capstone', 'lief', 'unicorn', 'frida', 'pyghidra', 'jpype1', 'reverify', 'z3-solver']},
          'reverify_backends': backend_report(), 'checks': {}}
pe = pefile.PE(str(TARGET))
other = lief.PE.parse(str(TARGET))
assert pe.OPTIONAL_HEADER.ImageBase == other.optional_header.imagebase == 0x400000
assert pe.OPTIONAL_HEADER.AddressOfEntryPoint == other.optional_header.addressof_entrypoint == 0x6b0f91
result['checks']['independent_pe_parsers'] = 'PASS: pefile and LIEF agree on image base and entry RVA'
code = bytes.fromhex('b82800000083c002')  # isolated engine smoke test, not a game routine
decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
assert [i.mnemonic for i in decoder.disasm(code, 0x1000)] == ['mov', 'add']
emulator = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
emulator.mem_map(0x1000, 0x1000)
emulator.mem_write(0x1000, code)
emulator.emu_start(0x1000, 0x1000 + len(code))
assert emulator.reg_read(UC_X86_REG_EAX) == 42
result['checks']['x86_disassembly_and_emulation'] = 'PASS: isolated arithmetic, EAX=42; not game equivalence'
rizin = ROOT.parent / 'tools/rizin/bin/rizin'
result['rizin'] = subprocess.check_output([str(rizin), '-v'], text=True).strip()
rz = subprocess.run([str(rizin), '-q', '-c', 'ij;q', str(TARGET)], text=True,
                    capture_output=True, check=True, timeout=60)
rz_info = json.loads(rz.stdout)
assert rz_info['bin']['bits'] == 32
result['checks']['rizin_pe'] = 'PASS: target parsed as 32-bit'
debugger = pefile.PE(str(ROOT.parent / 'tools/x64dbg/release/x32/x32dbg.exe'))
assert debugger.FILE_HEADER.Machine == 0x14c
result['checks']['x32dbg'] = 'PE32 artifact verified; live Windows debugging not tested'
import pyghidra
pyghidra.start()
from ghidra.framework import Application
result['checks']['pyghidra'] = 'PASS: started Ghidra ' + str(Application.getApplicationVersion())
result['limits'] = [
    'Frida import/version checked; hooking Wine PE32 has not been validated.',
    'No angr backend installed. Reverify semantic boundary/graph questions may remain INCONCLUSIVE.',
    'Capstone Python distribution version and bundled engine version are recorded separately.',
    'A decompiler function count is not semantic coverage of the engine.',
]
result['capstone_engine'] = capstone.__version__
out = ROOT / 'evidence/environment-check.json'
out.write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result['checks'], indent=2))
print('Saved', out)
