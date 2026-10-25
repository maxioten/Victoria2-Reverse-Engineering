#!/usr/bin/env python3
"""Check null, deferred and pre-destruction unlink paths from original POP list code."""
import hashlib
import json
from pathlib import Path
import struct
import pefile
import unicorn
from unicorn.x86_const import (
    UC_X86_REG_EAX, UC_X86_REG_EBP, UC_X86_REG_ECX, UC_X86_REG_EDI, UC_X86_REG_EIP,
    UC_X86_REG_ESI, UC_X86_REG_ESP,
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
    (0x4be8e2, 4, 'cmp', 'byte ptr [esi + 0xc], 0'),
    (0x4be8ea, 7, 'mov', 'byte ptr [eax + 0x280], 1'),
    (0x4be8f8, 6, 'mov', 'ecx, dword ptr [eax + 0x278]'),
    (0x4be8fe, 6, 'mov', 'eax, dword ptr [eax + 0x27c]'),
    (0x4be908, 6, 'mov', 'dword ptr [ecx + 0x27c], eax'),
    (0x4be912, 6, 'mov', 'dword ptr [eax + 0x278], ecx'),
    (0x4be91c, 2, 'mov', 'dword ptr [esi], eax'),
    (0x4be923, 3, 'mov', 'dword ptr [esi + 4], ecx'),
    (0x4be927, 5, 'call', '0x955ae0'),
    (0x4be92d, 5, 'call', '0xaae91b'),
    (0x4be935, 3, 'dec', 'dword ptr [esi + 8]'),
    (0x4be93c, 3, 'ret', '4'),
    (0x4be0f0, 4, 'cmp', 'byte ptr [ecx + 0xc], 0'),
    (0x4be0f4, 2, 'jne', '0x4be13d'),
    (0x4be125, 3, 'dec', 'dword ptr [ecx + 8]'),
    (0x4be128, 10, 'mov', 'dword ptr [eax + 0x278], 0'),
    (0x4be132, 10, 'mov', 'dword ptr [eax + 0x27c], 0'),
]:
    claims.append({'id': f'pop_unlink_{address:x}', 'kind': 'instructions',
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
arena, bucket, sentinel, initial_sp = 0x20000000, 0x20001000, 0x21000000, 0x20008000
emu.mem_map(arena, 0x10000, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
emu.mem_map(sentinel, 0x1000, unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC)
def stop_before_destructor(uc, address, size, _):
    uc.emu_stop()
emu.hook_add(unicorn.UC_HOOK_CODE, stop_before_destructor, begin=0x4be927, end=0x4be927)
def write_guard(uc, access, address, size, value, _):
    assert arena <= address and address + size <= arena + 0x10000, hex(address)
emu.hook_add(unicorn.UC_HOOK_MEM_WRITE, write_guard)
def word(address):
    return struct.unpack('<I', emu.mem_read(address, 4))[0]
cases = []
for length, target_index in ((0, None), (1, None), (1, 0), (3, 0), (3, 1), (3, 2)):
    for deferred in (0, 1):
        emu.mem_write(arena, bytes(0x10000))
        nodes = [arena + 0x2000 + i * 0x400 for i in range(length)]
        target = 0 if target_index is None else nodes[target_index]
        emu.mem_write(bucket, struct.pack('<4I', nodes[0] if nodes else 0,
                                        nodes[-1] if nodes else 0, length, deferred))
        for i, node in enumerate(nodes):
            emu.mem_write(node + 0x278, struct.pack('<2I', nodes[i-1] if i else 0,
                                                  nodes[i+1] if i+1 < length else 0))
        before_bucket = bytes(emu.mem_read(bucket, 16))
        before_nodes = [bytes(emu.mem_read(node, 0x281)) for node in nodes]
        emu.mem_write(initial_sp, struct.pack('<2I', sentinel, target))
        emu.reg_write(UC_X86_REG_ESP, initial_sp)
        emu.reg_write(UC_X86_REG_ESI, bucket)
        emu.reg_write(UC_X86_REG_EDI, 0x12345678)
        emu.reg_write(UC_X86_REG_EBP, 0x23456789)
        emu.emu_start(0x4be8d0, sentinel, count=128)
        at = emu.reg_read(UC_X86_REG_EIP)
        if target == 0 or deferred:
            assert at == sentinel
            assert emu.reg_read(UC_X86_REG_EAX) & 0xff == (1 if target else 0)
            assert emu.reg_read(UC_X86_REG_ESP) == initial_sp + 8
            assert emu.reg_read(UC_X86_REG_EDI) == 0x12345678
            assert emu.reg_read(UC_X86_REG_EBP) == 0x23456789
            assert bytes(emu.mem_read(bucket, 16)) == before_bucket
            for node, prior in zip(nodes, before_nodes):
                expected = bytearray(prior)
                if node == target:
                    expected[0x280] = 1
                assert bytes(emu.mem_read(node, 0x281)) == expected
            path = 'null return' if target == 0 else 'deferred mark'
        else:
            assert at == 0x4be927
            remaining = [node for node in nodes if node != target]
            assert word(bucket) == (remaining[0] if remaining else 0)
            assert word(bucket + 4) == (remaining[-1] if remaining else 0)
            assert word(bucket + 8) == length  # decrement happens after excluded callees
            for i, node in enumerate(remaining):
                assert word(node + 0x278) == (remaining[i-1] if i else 0)
                assert word(node + 0x27c) == (remaining[i+1] if i+1 < len(remaining) else 0)
            path = 'relinked before destructor'
        assert emu.reg_read(UC_X86_REG_ESI) == bucket
        cases.append({'length': length, 'target_index': target_index,
                      'deferred': deferred, 'path': path, 'stop_va': hex(at)})
detach_cases = []
detach_sp = arena + 0xf000
for length in (1, 3, 8, 32):
    for target_index in range(length):
        for locked in (0, 1):
            emu.mem_write(arena, bytes(0x10000))
            nodes = [arena + 0x2000 + i * 0x400 for i in range(length)]
            target = nodes[target_index]
            emu.mem_write(bucket, struct.pack('<4I', nodes[0], nodes[-1], length, locked))
            for i, node in enumerate(nodes):
                emu.mem_write(node + 0x278, struct.pack('<2I', nodes[i-1] if i else 0,
                                                      nodes[i+1] if i+1 < length else 0))
            expected = bytearray(emu.mem_read(arena, 0xd000))
            if not locked:
                remaining = [node for node in nodes if node != target]
                struct.pack_into('<3I', expected, bucket - arena,
                                 remaining[0] if remaining else 0, remaining[-1] if remaining else 0, length - 1)
                struct.pack_into('<2I', expected, target - arena + 0x278, 0, 0)
                for i, node in enumerate(remaining):
                    struct.pack_into('<2I', expected, node - arena + 0x278,
                                     remaining[i-1] if i else 0, remaining[i+1] if i+1 < len(remaining) else 0)
            emu.mem_write(detach_sp, struct.pack('<I', sentinel))
            emu.reg_write(UC_X86_REG_ESP, detach_sp)
            emu.reg_write(UC_X86_REG_EAX, target)
            emu.reg_write(UC_X86_REG_ECX, bucket)
            emu.reg_write(UC_X86_REG_ESI, 0x12345678)
            emu.emu_start(0x4be0f0, sentinel, count=128)
            assert emu.reg_read(UC_X86_REG_EIP) == sentinel
            assert emu.reg_read(UC_X86_REG_ESP) == detach_sp + 4
            assert emu.reg_read(UC_X86_REG_ESI) == 0x12345678
            assert bytes(emu.mem_read(arena, 0xd000)) == expected
            detach_cases.append({'length': length, 'target_index': target_index,
                                 'locked': locked, 'count_after': length if locked else length - 1})
out = ROOT / 'evidence/generated/pop-unlink'
out.mkdir(parents=True, exist_ok=True)
for name, value in [('claims.json', claims), ('reverify.json', verification), ('emulation.json', {
    'binary_sha256': digest, 'engine': f'unicorn {unicorn.__version__}',
    'entry_va': '0x4be8d0', 'cases': cases, 'mismatches': 0,
    'detach_entry_va': '0x4be0f0', 'detach_cases': detach_cases,
    'scope': 'Complete null/deferred paths; immediate path stops before call 0x955ae0. '
             'Destruction, heap release and post-call count decrement are not emulated. '
             'Separate detach entry is executed completely for valid listed nodes, with no destructor calls.',
})]:
    (out / name).write_text(json.dumps(value, indent=2) + '\n')
ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify')
ledger.record(verification, session='pop-list-unlink')
ledger.save()
print(f'POP unlink: {len(cases)} null/deferred/relink cases; {len(detach_cases)} full detach cases; no heap emulation.')
