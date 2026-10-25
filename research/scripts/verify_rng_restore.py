#!/usr/bin/env python3
"""Emulate global RNG reconstruction with existing singleton and empty auxiliary list."""
import hashlib
import json
from pathlib import Path
import struct
import pefile
import unicorn
from unicorn.x86_const import (
    UC_X86_REG_EBP, UC_X86_REG_EBX, UC_X86_REG_EDI, UC_X86_REG_EIP,
    UC_X86_REG_ESI, UC_X86_REG_ESP,
)
from reverify.ledger import Ledger
from reverify.verifier import Claim, Verifier
from rng_model import initialize, regenerate

ROOT = Path(__file__).resolve().parents[1]
data = (ROOT.parent / 'base-game/v2game.exe').read_bytes()
digest = hashlib.sha256(data).hexdigest()
if digest != '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648':
    raise SystemExit('Binary profile mismatch')
claims = []
for address, length, mnemonic, operands in [
    (0x9b7c83, 5, 'call', '0x9b7de0'),
    (0x9b7cb4, 5, 'mov', 'eax, dword ptr [0xf20c1c]'),
    (0x9b7cb9, 5, 'mov', 'ecx, 0xf0ecf0'),
    (0x9b7cbe, 5, 'call', '0x9b7670'),
    (0x9b7cc3, 6, 'mov', 'dword ptr [0xf0f6b0], ebx'),
    (0x9b7cf4, 6, 'cmp', 'ebx, dword ptr [0xf20c14]'),
    (0x9b7d0a, 5, 'call', '0x9b7700'),
    (0x9b7d24, 2, 'jmp', '0x9b7cd0'),
]:
    claims.append({'id': f'rng_restore_{address:x}', 'kind': 'instructions',
                   'offset': hex(address - 0x400000), 'space': 'rva',
                   'base': hex(address), 'length': length, 'arch': 'x86',
                   'mnemonics': [mnemonic], 'operands': [operands]})
verification = Verifier(data).verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in verification['results']), verification
pe = pefile.PE(data=data)
base = pe.OPTIONAL_HEADER.ImageBase
emu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
size = (pe.OPTIONAL_HEADER.SizeOfImage + 4095) & ~4095
emu.mem_map(base, size)
emu.mem_write(base, pe.get_memory_mapped_image())
emu.mem_protect(base, size, unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC)
for address, length in [(0xf08000, 0x2000), (0xf0e000, 0x2000),
                        (0xf20000, 0x1000), (0x131c000, 0x1000)]:
    emu.mem_protect(address, length, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
stack, sentinel, initial_sp = 0x20000000, 0x21000000, 0x20003000
emu.mem_map(stack, 0x4000, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
emu.mem_map(sentinel, 0x1000, unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC)
preserved = {UC_X86_REG_EBX: 0x12345678, UC_X86_REG_ESI: 0x23456789,
             UC_X86_REG_EDI: 0x34567890, UC_X86_REG_EBP: 0x45678901}
regenerations = []
def note_regeneration(uc, address, size, _):
    regenerations.append(uc.reg_read(UC_X86_REG_EBX))
def forbidden_allocator(uc, address, size, _):
    raise RuntimeError('Unexpected allocation or nonempty-list cleanup')
def check_write(uc, access, address, size, value, _):
    allowed = any(lo <= address and address + size <= hi for lo, hi in [
        (stack, stack + 0x4000), (0xf08778, 0xf09138),
        (0xf0ecf0, 0xf0f6b4), (0x131c9f4, 0x131ca00)])
    assert allowed, (hex(address), size)
emu.hook_add(unicorn.UC_HOOK_MEM_WRITE, check_write)
emu.hook_add(unicorn.UC_HOOK_CODE, note_regeneration, begin=0x9b7700, end=0x9b7700)
for entry in (0xaae9af, 0xaae91b):
    emu.hook_add(unicorn.UC_HOOK_CODE, forbidden_allocator, begin=entry, end=entry)
cases = []
for seed in (0, 5489, 0x80000000):
    for count in (0, 1, 623, 624, 625, 1000, 1248):
        expected, index, regeneration_indices = initialize(seed), 0, []
        for draw in range(count):
            if index == 0:
                regenerate(expected)
                regeneration_indices.append(draw)
            index = (index + 1) % 624
        emu.mem_write(0xf08778, struct.pack('<I', 0xffffffff))
        emu.mem_write(0xf0ecf0, struct.pack('<625I', *([0xa5a5a5a5] * 624), 321))
        emu.mem_write(0xf20c14, struct.pack('<3I', count, 1, seed))
        emu.mem_write(0x131c9f4, struct.pack('<3I', 0, 0xa5a5a5a5, 0xa5a5a5a5))
        emu.mem_write(initial_sp, struct.pack('<I', sentinel))
        emu.reg_write(UC_X86_REG_ESP, initial_sp)
        for register, value in preserved.items():
            emu.reg_write(register, value)
        regenerations.clear()
        emu.emu_start(0x9b7c80, sentinel, count=200000)
        assert emu.reg_read(UC_X86_REG_EIP) == sentinel
        assert emu.reg_read(UC_X86_REG_ESP) == initial_sp + 4
        assert all(emu.reg_read(reg) == value for reg, value in preserved.items())
        actual = bytes(emu.mem_read(0xf0ecf0, 2500))
        assert list(struct.unpack('<625I', actual)) == expected + [index], (seed, count)
        assert struct.unpack('<3I', emu.mem_read(0xf20c14, 12)) == (count, 1, seed)
        assert bytes(emu.mem_read(0x131c9f4, 12)) == bytes(12)
        assert regenerations == regeneration_indices
        cases.append({'seed': hex(seed), 'draw_count': count, 'final_index': index,
                      'regeneration_draw_indices': list(regenerations),
                      'state_sha256': hashlib.sha256(actual).hexdigest()})
out = ROOT / 'evidence/generated/rng-restore'
out.mkdir(parents=True, exist_ok=True)
for name, value in [('claims.json', claims), ('reverify.json', verification), ('emulation.json', {
    'binary_sha256': digest, 'engine': f'unicorn {unicorn.__version__}',
    'entry_va': '0x9b7c80', 'cases': cases, 'mismatches': 0,
    'scope': 'Complete entry and actual callees, preexisting singleton and empty auxiliary list. '
             'Synthetic seeds/counts only; no allocation, heap deletion, threading or game runtime trace.',
})]:
    (out / name).write_text(json.dumps(value, indent=2) + '\n')
ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify')
ledger.record(verification, session='rng-rebuild-from-counter')
ledger.save()
print('RNG rebuild: 21 seed/counter cases, full state and preserved counters match.')
