#!/usr/bin/env python3
"""Compare original x86 RNG entries with an explicit signed 32-bit model."""
import hashlib
import json
from pathlib import Path
import random
import struct

import pefile
import unicorn
from unicorn.x86_const import (
    UC_X86_REG_EAX, UC_X86_REG_EBP, UC_X86_REG_EBX, UC_X86_REG_EDI,
    UC_X86_REG_EIP, UC_X86_REG_ESI, UC_X86_REG_ESP,
)
from reverify.ledger import Ledger
from reverify.verifier import Claim, Verifier
from rng_model import MASK, initialize, regenerate, temper

ROOT = Path(__file__).resolve().parents[1]
data = (ROOT.parent / 'base-game/v2game.exe').read_bytes()
digest = hashlib.sha256(data).hexdigest()
if digest != '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648':
    raise SystemExit('Binary profile mismatch')
claims = []
for address, length, mnemonic, operands in [
    (0x9b762d, 3, 'sar', 'edx, 0xb'),
    (0x9b7657, 3, 'sar', 'eax, 0x12'),
    (0x9b774a, 2, 'sar', 'ebx, 1'),
    (0x9b7760, 3, 'cmp', 'eax, 1'),
    (0x9b7763, 2, 'jne', '0x9b776e'),
    (0x9b765c, 6, 'mov', 'dword ptr [edi + 0x9c0], edx'),
    (0x9b76d4, 3, 'sar', 'esi, 0x1e'),
    (0x9b76bd, 2, 'rep movsd', 'dword ptr es:[edi], dword ptr [esi]'),
]:
    claims.append({'id': f'rng_instruction_{address:x}', 'kind': 'instructions',
                   'offset': hex(address - 0x400000), 'space': 'rva',
                   'base': hex(address), 'arch': 'x86', 'length': length,
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
state, stack, sentinel = 0x20000000, 0x20010000, 0x21000000
emu.mem_map(state, 0x1000, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
emu.mem_map(stack, 0x4000, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
emu.mem_map(sentinel, 0x1000, unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC)
initial_sp = stack + 0x3000

def invoke(entry, seed=None):
    emu.mem_write(initial_sp, struct.pack('<I', sentinel))
    emu.reg_write(UC_X86_REG_ESP, initial_sp)
    emu.reg_write(UC_X86_REG_EAX, state if seed is None else seed)
    if seed is not None:
        from unicorn.x86_const import UC_X86_REG_ECX
        emu.reg_write(UC_X86_REG_ECX, state)
    emu.reg_write(UC_X86_REG_EDI, state if entry == 0x9b7700 else 0x12345678)
    emu.reg_write(UC_X86_REG_ESI, 0x34567890)
    emu.reg_write(UC_X86_REG_EBX, 0x45678901)
    emu.reg_write(UC_X86_REG_EBP, 0x56789012)
    emu.emu_start(entry, sentinel, count=100000)
    assert emu.reg_read(UC_X86_REG_EIP) == sentinel
    assert emu.reg_read(UC_X86_REG_ESP) == initial_sp + 4
    assert emu.reg_read(UC_X86_REG_ESI) == 0x34567890
    assert emu.reg_read(UC_X86_REG_EBX) == 0x45678901
    assert emu.reg_read(UC_X86_REG_EBP) == 0x56789012
    assert emu.reg_read(UC_X86_REG_EDI) == (state if entry == 0x9b7700 else 0x12345678)
    return emu.reg_read(UC_X86_REG_EAX)

# The zero-seed entry lazily builds a global cached initial state. Only its two
# pages become writable; a write hook checks every actual destination below.
cache = 0xf08778
emu.mem_protect(cache & ~4095, 0x2000, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
emu.mem_write(cache, struct.pack('<I', MASK))  # force the original zero-seed initializer
seed_results, seed_writes = [], []
def seed_write(uc, access, address, size, value, _):
    allowed = (state <= address and address + size <= state + 2496) or (
        stack <= address and address + size <= stack + 0x4000) or (
        cache <= address and address + size <= cache + 2496)
    assert allowed, (hex(address), size)
    seed_writes.append(address)
hook = emu.hook_add(unicorn.UC_HOOK_MEM_WRITE, seed_write)
for seed in (0, 0, 1, 5489, 0x7fffffff, 0x80000000, MASK):
    emu.mem_write(state, struct.pack('<625I', *([0xa5a5a5a5] * 624), 321))
    before = len(seed_writes)
    invoke(0x9b7670, seed=seed)
    expected = initialize(seed)
    assert list(struct.unpack('<625I', emu.mem_read(state, 2500))) == expected + [321], hex(seed)
    seed_results.append({'seed': hex(seed), 'index_before_and_after': 321,
                         'cache_writes': sum(cache <= a < cache + 2496 for a in seed_writes[before:]),
                         'state_sha256': hashlib.sha256(struct.pack('<624I', *expected)).hexdigest()})
emu.hook_del(hook)
emu.mem_protect(cache & ~4095, 0x2000, unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC)

generator = random.Random(20261021)  # deterministic test-data generation only
vectors = {
    'zeros': [0] * 624,
    'ones': [MASK] * 624,
    'high_bit': [0x80000000] * 624,
    'alternating': [0x80000001 if i % 2 else 1 for i in range(624)],
    'ascending': list(range(624)),
    'deterministic_random': [generator.getrandbits(32) for _ in range(624)],
}
results = []
for name, initial in vectors.items():
    words = initial.copy()
    emu.mem_write(state, struct.pack('<625I', *initial, 0))
    regenerate(words)
    invoke(0x9b7700)
    assert list(struct.unpack('<624I', emu.mem_read(state, 2496))) == words, name
    # Start fresh so the first draw exercises the zero-index regeneration path.
    words = initial.copy()
    emu.mem_write(state, struct.pack('<625I', *initial, 0))
    index, output_bytes, regeneration_count = 0, bytearray(), 0
    for draw in range(1250):
        if index == 0:
            regenerate(words)
            regeneration_count += 1
        expected = temper(words[index])
        index = (index + 1) % 624
        actual = invoke(0x9b7610)
        assert actual == expected, (name, draw, hex(actual), hex(expected))
        assert list(struct.unpack('<625I', emu.mem_read(state, 2500))) == words + [index], (name, draw)
        output_bytes.extend(struct.pack('<I', actual))
    results.append({'vector': name, 'draws': 1250, 'regenerations': regeneration_count,
                    'all_state_words_compared_after_each_draw': True,
                    'output_sha256': hashlib.sha256(output_bytes).hexdigest()})

# A logical-shift substitution must be rejected even outside regeneration.
counterexample_word = 0x80000000
emu.mem_write(state, struct.pack('<625I', *([counterexample_word] * 624), 1))
observed = invoke(0x9b7610)
logical_candidate = temper(counterexample_word, arithmetic=False)
assert observed == temper(counterexample_word) and observed != logical_candidate
out = ROOT / 'evidence/generated/rng'
out.mkdir(parents=True, exist_ok=True)
for name, value in [('claims.json', claims), ('reverify.json', verification), ('emulation.json', {
    'binary_sha256': digest, 'engine': f'unicorn {unicorn.__version__}',
    'entries_va': ['0x9b7610', '0x9b7670', '0x9b7700'], 'image_base': hex(base),
    'seed_tests': seed_results,
    'vectors': results, 'total_draws': 7500, 'mismatches': 0,
    'logical_shift_negative_control': {'state_word': hex(counterexample_word),
        'observed': hex(observed), 'logical_candidate': hex(logical_candidate), 'verdict': 'REFUTED'},
    'scope': 'Synthetic state vectors, complete original entries, no game runtime trace. '
             'Other RNG functions, invalid indices, threads and callers are not covered. '
             'Zero-seed cache is tested from an explicitly forced uninitialized state, then reused.',
})]:
    (out / name).write_text(json.dumps(value, indent=2) + '\n')
ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify')
ledger.record(verification, session='rng-signed-instructions')
ledger.save()
print('RNG: 7 initializer cases; 6 regeneration vectors; 7500 draws and complete states match; logical-shift candidate REFUTED.')
