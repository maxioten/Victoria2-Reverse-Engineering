#!/usr/bin/env python3
"""Execute the complete original POP destructor for explicitly empty owned containers."""
import hashlib
import json
from pathlib import Path
import struct
import pefile
import unicorn
from unicorn.x86_const import (
    UC_X86_REG_EBP, UC_X86_REG_EBX, UC_X86_REG_EDI, UC_X86_REG_EIP,
    UC_X86_REG_ESI, UC_X86_REG_ESP, UC_X86_REG_ECX, UC_X86_REG_EAX,
)
from reverify.ledger import Ledger
from reverify.verifier import Claim, Verifier

ROOT = Path(__file__).resolve().parents[1]
data = (ROOT.parent / 'base-game/v2game.exe').read_bytes()
digest = hashlib.sha256(data).hexdigest()
if digest != '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648':
    raise SystemExit('Binary profile mismatch')
claims = []
for address, length, mnemonic, operands in [
    (0x955aff, 6, 'mov', 'dword ptr [edi], 0xe36428'),
    (0x955b57, 5, 'call', '0x967f50'),
    (0x955b94, 7, 'cmp', 'dword ptr [edi + 0x240], 0x10'),
    (0x955bac, 10, 'mov', 'dword ptr [edi + 0x240], 0xf'),
    (0x955cff, 6, 'mov', 'dword ptr [edi], 0xe3a544'),
    (0x955d05, 5, 'call', '0x9c1650'),
    (0x955d22, 7, 'mov', 'dword ptr [edi + 0x28], 0xf'),
    (0x955d39, 3, 'ret', '4'),
]:
    claims.append({'id': f'pop_destructor_{address:x}', 'kind': 'instructions',
                   'space': 'rva', 'offset': hex(address - 0x400000), 'base': hex(address),
                   'arch': 'x86', 'length': length, 'mnemonics': [mnemonic], 'operands': [operands]})
verification = Verifier(data).verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in verification['results']), verification
pe = pefile.PE(data=data)
base = pe.OPTIONAL_HEADER.ImageBase
emu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
size = (pe.OPTIONAL_HEADER.SizeOfImage + 4095) & ~4095
emu.mem_map(base, size)
emu.mem_write(base, pe.get_memory_mapped_image())
emu.mem_protect(base, size, unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC)
node, stack, sentinel = 0x20000000, 0x20010000, 0x21000000
emu.mem_map(node, 0x1000, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
emu.mem_map(stack, 0x10000, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
emu.mem_map(0, 0x1000, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)  # synthetic FS:0 exception-chain slot
emu.mem_map(sentinel, 0x1000, unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC)
for address in (0x1258a94, 0x1258a98):
    emu.mem_write(address, bytes(4))  # absent handle databases, declared fixture
preserved = {UC_X86_REG_EBX: 0x12345678, UC_X86_REG_ESI: 0x23456789,
             UC_X86_REG_EDI: 0x34567890, UC_X86_REG_EBP: 0x45678901}
writes, calls = [], []
def on_write(uc, access, address, size, value, _):
    assert (node <= address and address + size <= node + 0x300) or (
        stack <= address and address + size <= stack + 0x10000) or (address == 0 and size == 4), hex(address)
    if node <= address < node + 0x300:
        writes.append({'offset': hex(address - node), 'size': size, 'value': hex(value)})
def call_boundary(uc, address, size, _):
    calls.append(hex(address))
    if address not in (0x967f50, 0x9c1650):
        raise RuntimeError(f'Excluded path executed: {address:#x}')
emu.hook_add(unicorn.UC_HOOK_MEM_WRITE, on_write)
for address in (0x967f50, 0x9c1650, 0xaae91b, 0x68a900, 0x955d40, 0x967f10, 0x9c1d40, 0x5f2ae0, 0x965bd0):
    emu.hook_add(unicorn.UC_HOOK_CODE, call_boundary, begin=address, end=address)
cases = []
for entry, flags in [(0x955ae0, None), *[(0x4a8230, f) for f in (0, 2, 0x100, 0xfffffffe)]]:
 for string_length in (0, 1, 15):
    for handle_type in (0, 0x1268, 0x1269):
        fixture = bytearray(0x300)
        struct.pack_into('<I', fixture, 0, 0x11111111)
        for text, size_at, capacity_at in ((0x14, 0x24, 0x28), (0x22c, 0x23c, 0x240)):
            fixture[text:text+string_length] = b'x' * string_length
            struct.pack_into('<I', fixture, size_at, string_length)
            struct.pack_into('<I', fixture, capacity_at, 15)
        struct.pack_into('<3I', fixture, 0x220, 0xa5a5a5a5, handle_type, 17)
        expected = bytearray(fixture)
        struct.pack_into('<I', expected, 0, 0xe3a544)
        struct.pack_into('<I', expected, 0x220, 0)
        for text, size_at in ((0x14, 0x24), (0x22c, 0x23c)):
            expected[text] = 0
            struct.pack_into('<I', expected, size_at, 0)
        emu.mem_write(node, bytes(fixture))
        initial_sp = stack + 0xf000
        emu.mem_write(initial_sp, struct.pack('<2I', sentinel, node if flags is None else flags))
        emu.mem_write(0, struct.pack('<I', 0xcafebabe))
        emu.reg_write(UC_X86_REG_ESP, initial_sp)
        for register, value in preserved.items():
            emu.reg_write(register, value)
        emu.reg_write(UC_X86_REG_ECX, node)
        writes.clear()
        calls.clear()
        emu.emu_start(entry, sentinel, count=1000)
        assert emu.reg_read(UC_X86_REG_EIP) == sentinel
        assert emu.reg_read(UC_X86_REG_ESP) == initial_sp + 8
        assert all(emu.reg_read(reg) == value for reg, value in preserved.items())
        if flags is not None:
            assert emu.reg_read(UC_X86_REG_EAX) == node
        assert bytes(emu.mem_read(0, 4)) == struct.pack('<I', 0xcafebabe)
        actual = bytes(emu.mem_read(node, 0x300))
        assert actual == expected, [hex(i) for i, (a,b) in enumerate(zip(actual,expected)) if a != b]
        assert calls == ['0x967f50', '0x9c1650']
        cases.append({'entry_va': hex(entry), 'flags': None if flags is None else hex(flags),
                      'string_length': string_length, 'handle_type': hex(handle_type),
                      'calls': list(calls), 'object_writes': list(writes),
                      'post_object_sha256': hashlib.sha256(actual).hexdigest()})
out = ROOT / 'evidence/generated/pop-destructor'
out.mkdir(parents=True, exist_ok=True)
for name, value in [('claims.json', claims), ('reverify.json', verification), ('emulation.json', {
    'binary_sha256': digest, 'engine': f'unicorn {unicorn.__version__}',
    'entry_va': ['0x955ae0', '0x4a8230'], 'cases': cases, 'mismatches': 0,
    'scope': 'Full original destructor and actual callees for empty owned containers, null optional '
             'pointer, inline strings and absent handle databases; synthetic FS:0 exception-chain slot. '
             'Also executes the virtual wrapper with ECX=this and four flags whose low bit is clear. '
             'No heap API, low-bit-set flag, nonempty container, live database or exception unwinding is modeled or tested.',
})]:
    (out / name).write_text(json.dumps(value, indent=2) + '\n')
ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify')
ledger.record(verification, session='pop-destructor-empty-owned-containers')
ledger.save()
print('POP destructor: 9 direct + 36 virtual-wrapper cases; all 768 object bytes and FS:0 restoration match.')
