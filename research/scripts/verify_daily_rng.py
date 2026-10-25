#!/usr/bin/env python3
"""Execute the original 1000-draw tick fragment with a preexisting singleton."""
import hashlib
import json
from pathlib import Path
import struct
import pefile
import unicorn
from unicorn.x86_const import (
    UC_X86_REG_EBP, UC_X86_REG_EIP, UC_X86_REG_ESI, UC_X86_REG_ESP,
)
from reverify.ledger import Ledger
from reverify.verifier import Claim, Verifier
from rng_model import initialize, regenerate, temper

ROOT = Path(__file__).resolve().parents[1]
data = (ROOT.parent / 'base-game/v2game.exe').read_bytes()
digest = hashlib.sha256(data).hexdigest()
if digest != '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648':
    raise SystemExit('Binary profile mismatch')
claims = []
for address, length, mnemonic, operands in [
    (0x685b69, 2, 'xor', 'esi, esi'),
    (0x685b99, 6, 'inc', 'dword ptr [0xf20c14]'),
    (0x685bad, 5, 'call', '0x9b7700'),
    (0x685bc0, 3, 'sar', 'edx, 0xb'),
    (0x685be1, 3, 'sar', 'edx, 0x12'),
    (0x685bef, 7, 'mov', 'dword ptr [ebp + esi*4 - 0x108c], ecx'),
    (0x685bfd, 6, 'cmp', 'esi, 0x3e8'),
    (0x685c03, 6, 'jl', '0x685b6b'),
]:
    claims.append({'id': f'daily_rng_{address:x}', 'kind': 'instructions',
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
emu.mem_protect(0xf0e000, 0x2000, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
emu.mem_protect(0xf20000, 0x1000, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
stack, frame, initial_sp = 0x20000000, 0x20008000, 0x2000f000
emu.mem_map(stack, 0x10000, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
regenerations = []
def regeneration(uc, address, size, _):
    regenerations.append(uc.reg_read(UC_X86_REG_ESI))
def forbidden_allocator(uc, address, size, _):
    raise RuntimeError('Unexpected singleton allocation path')
def check_write(uc, access, address, size, value, _):
    allowed = (stack <= address and address + size <= stack + 0x10000) or (
        0xf0ecf0 <= address and address + size <= 0xf0f6b4) or (
        address == 0xf20c14 and size == 4)
    assert allowed, (hex(address), size)
emu.hook_add(unicorn.UC_HOOK_CODE, regeneration, begin=0x9b7700, end=0x9b7700)
emu.hook_add(unicorn.UC_HOOK_CODE, forbidden_allocator, begin=0xaae9af, end=0xaae9af)
emu.hook_add(unicorn.UC_HOOK_MEM_WRITE, check_write)
cases = []
for seed in (0, 5489, 0x80000000):
    for initial_index in (0, 1, 623):
        words, index = initialize(seed), initial_index
        expected, expected_regenerations = [], []
        for draw in range(1000):
            if index == 0:
                regenerate(words)
                expected_regenerations.append(draw)
            expected.append(temper(words[index]))
            index = (index + 1) % 624
        emu.mem_write(0xf0ecf0, struct.pack('<625I', *initialize(seed), initial_index))
        emu.mem_write(0xf20c18, struct.pack('<I', 1))  # non-null, never dereferenced on this path
        emu.mem_write(0xf20c14, struct.pack('<I', 17))
        emu.mem_write(frame - 0x108c, bytes(4000))
        emu.reg_write(UC_X86_REG_ESI, 0xdeadbeef)  # original XOR must reset the loop index
        emu.reg_write(UC_X86_REG_EBP, frame)
        emu.reg_write(UC_X86_REG_ESP, initial_sp)
        regenerations.clear()
        emu.emu_start(0x685b69, 0x685c09, count=200000)
        assert emu.reg_read(UC_X86_REG_EIP) == 0x685c09
        assert emu.reg_read(UC_X86_REG_ESI) == 1000
        assert emu.reg_read(UC_X86_REG_EBP) == frame
        assert emu.reg_read(UC_X86_REG_ESP) == initial_sp
        assert list(struct.unpack('<1000I', emu.mem_read(frame - 0x108c, 4000))) == expected
        assert list(struct.unpack('<625I', emu.mem_read(0xf0ecf0, 2500))) == words + [index]
        assert struct.unpack('<I', emu.mem_read(0xf20c14, 4))[0] == 1017
        assert regenerations == expected_regenerations
        cases.append({'seed': hex(seed), 'initial_index': initial_index,
                      'final_index': index, 'regeneration_draw_indices': list(regenerations),
                      'draw_counter_delta': 1000,
                      'array_sha256': hashlib.sha256(struct.pack('<1000I', *expected)).hexdigest()})
out = ROOT / 'evidence/generated/daily-rng'
out.mkdir(parents=True, exist_ok=True)
for name, value in [('claims.json', claims), ('reverify.json', verification), ('emulation.json', {
    'binary_sha256': digest, 'engine': f'unicorn {unicorn.__version__}',
    'start_va': '0x685b69', 'stop_va': '0x685c09', 'cases': cases,
    'total_outputs_compared': 9000, 'mismatches': 0,
    'scope': 'Original fragment including loop-index initialization and actual regeneration calls, synthetic states. '
             'Singleton already present. Allocation and earlier/later tick phases are excluded.',
})]:
    (out / name).write_text(json.dumps(value, indent=2) + '\n')
ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify')
ledger.record(verification, session='daily-rng-fragment')
ledger.save()
print('Daily RNG: 9 original-fragment cases, 9000 outputs, states and counters match.')
