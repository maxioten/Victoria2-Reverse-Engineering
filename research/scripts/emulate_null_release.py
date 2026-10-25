#!/usr/bin/env python3
"""Counterexample to Ghidra's noreturn flag using unmodified PE instructions."""
import hashlib
import json
from pathlib import Path
import struct
import capstone
import pefile
import unicorn
from unicorn.x86_const import UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EIP

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT.parent / 'base-game/v2game.exe'
raw = TARGET.read_bytes()
digest = hashlib.sha256(raw).hexdigest()
if digest != '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648':
    raise SystemExit('Binary profile mismatch')
pe = pefile.PE(data=raw)
base = pe.OPTIONAL_HEADER.ImageBase
entry = base + 0x6ae91b
stack = 0x20000000
initial_sp = stack + 0x1800
sentinel = 0x30000000
emu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
emu.mem_map(base, (pe.OPTIONAL_HEADER.SizeOfImage + 4095) & ~4095)
emu.mem_write(base, pe.get_memory_mapped_image())
emu.mem_map(stack, 0x2000)
emu.mem_map(sentinel, 0x1000)
emu.mem_write(initial_sp, struct.pack('<II', sentinel, 0))
emu.reg_write(UC_X86_REG_ESP, initial_sp)
emu.reg_write(UC_X86_REG_EBP, 0x13572468)
decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
trace, writes = [], []
returned = False
def instruction(uc, address, size, _):
    global returned
    if address == sentinel:
        returned = True
        uc.emu_stop()
        return
    if not base <= address < base + pe.OPTIONAL_HEADER.SizeOfImage:
        raise RuntimeError(f'Unexpected external execution: {address:#x}')
    code = bytes(uc.mem_read(address, size))
    ins = next(decoder.disasm(code, address))
    trace.append({'va': hex(address), 'rva': hex(address - base), 'bytes': code.hex(),
                  'mnemonic': ins.mnemonic, 'operands': ins.op_str})
def write(uc, access, address, size, value, _):
    if not stack <= address < stack + 0x2000:
        raise RuntimeError(f'Unexpected non-stack write: {address:#x}')
    writes.append({'address': hex(address), 'size': size, 'value': value})
emu.hook_add(unicorn.UC_HOOK_CODE, instruction)
emu.hook_add(unicorn.UC_HOOK_MEM_WRITE, write)
emu.emu_start(entry, sentinel + 1, count=64)
assert returned, 'No return observed within the instruction budget'
assert emu.reg_read(UC_X86_REG_ESP) == initial_sp + 4
assert emu.reg_read(UC_X86_REG_EBP) == 0x13572468
assert [int(i['va'], 16) for i in trace] == [
    0xaae91b, 0xaae91d, 0xaae91e, 0xaae920, 0xaae921,
    0xaaeed7, 0xaaeed9, 0xaaeeda, 0xaaeedc, 0xaaeee0, 0xaaef0f, 0xaaef10]
report = {
    'binary_sha256': digest, 'engine': 'unicorn', 'engine_version': unicorn.__version__,
    'entry_va': hex(entry), 'input': {'first_cdecl_stack_argument': 0, 'initial_esp': hex(initial_sp)},
    'returned_to_sentinel': returned, 'final_eip': hex(emu.reg_read(UC_X86_REG_EIP)),
    'final_esp': hex(emu.reg_read(UC_X86_REG_ESP)), 'trace': trace, 'writes': writes,
    'verdict': 'COUNTEREXAMPLE: this entry is not unconditionally noreturn',
    'scope': 'The null argument path only, using actual PE bytes; no heap API was invoked or modeled.',
    'reproduce': 'source research/env.sh; python research/scripts/emulate_null_release.py',
}
out = ROOT / 'evidence/generated/crt-null-release.json'
out.write_text(json.dumps(report, indent=2) + '\n')
print(f'PASS: {len(trace)} original instructions return on NULL; ESP and EBP restored. {out}')
