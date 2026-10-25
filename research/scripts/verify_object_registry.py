#!/usr/bin/env python3
"""Exercise original chained-hash lookup and both object-handle resolver variants."""
import hashlib
import json
from pathlib import Path
import random
import struct
import pefile
import unicorn
from unicorn.x86_const import (
    UC_X86_REG_EAX, UC_X86_REG_EBP, UC_X86_REG_EBX, UC_X86_REG_ECX,
    UC_X86_REG_EDI, UC_X86_REG_EIP, UC_X86_REG_ESI, UC_X86_REG_ESP,
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
    (0x9c1d4f, 3, 'shl', 'eax, 0x10'),
    (0x9c1d52, 2, 'add', 'eax, esi'),
    (0x9c1d56, 3, 'div', 'dword ptr [ecx + 4]'),
    (0x9c1d5c, 3, 'mov', 'edx, dword ptr [eax + edx*4]'),
    (0x9c1d6b, 3, 'cmp', 'dword ptr [eax + 4], esi'),
    (0x9c1d7e, 3, 'mov', 'edx, dword ptr [edx + 4]'),
    (0x9c1d8d, 2, 'mov', 'eax, dword ptr [edx]'),
    (0x967f66, 5, 'cmp', 'eax, 0x1268'),
    (0x967f6b, 2, 'jbe', '0x967f85'),
    (0x967f7f, 2, 'mov', 'dword ptr [esi], eax'),
    (0x967f8f, 2, 'mov', 'dword ptr [esi], eax'),
    (0x967f41, 5, 'call', '0x9c1d40'),
    (0x955486, 3, 'mov', 'dword ptr [edi + 8], eax'),
    (0x95548f, 3, 'mov', 'dword ptr [edi + 0xc], ecx'),
    (0x955492, 4, 'mov', 'byte ptr [edi + 0x10], 0'),
    (0x9c1ccb, 3, 'div', 'dword ptr [ecx + 4]'),
    (0x9c1ce9, 3, 'cmp', 'dword ptr [eax + 4], esi'),
    (0x9c1cee, 2, 'cmp', 'edx, edi'),
    (0x9c1d1b, 2, 'mov', 'dword ptr [eax], edx'),
    (0x9c1d1f, 3, 'mov', 'dword ptr [ebx + 4], edx'),
    (0x9c1d23, 5, 'call', '0xaae91b'),
    (0x9c1d2e, 2, 'dec', 'dword ptr [eax]'),
    (0x9c1d32, 2, 'mov', 'al, 1'),
    (0x9c166c, 4, 'cmp', 'byte ptr [esi + 0x10], 0'),
    (0x9c1672, 7, 'cmp', 'dword ptr [esi + 8], 0x1268'),
    (0x9c1680, 2, 'jbe', '0x9c168b'),
    (0x9c1696, 5, 'call', '0x9c1cb0'),
    (0x9c169b, 3, 'mov', 'eax, dword ptr [esi + 0xc]'),
    (0x9c16a3, 3, 'mov', 'dword ptr [esi + 8], eax'),
    (0x9c16a6, 3, 'mov', 'dword ptr [esi + 0xc], ecx'),
    (0x9c16a9, 2, 'mov', 'al, 1'),
    (0x9c13e5, 5, 'call', '0x9c1d40'),
    (0x9c156a, 5, 'call', '0x9c1590'),
    (0x9c1576, 4, 'mov', 'byte ptr [edi + 0x10], 1'),
    (0x9c1594, 4, 'cmp', 'byte ptr [esi + 0x10], 0'),
    (0x9c15a1, 5, 'call', '0x9c1650'),
    (0x9c15a8, 3, 'mov', 'dword ptr [esi + 8], edi'),
    (0x9c15ab, 3, 'mov', 'dword ptr [esi + 0xc], ebx'),
    (0x9c15ae, 6, 'cmp', 'edi, 0x1268'),
    (0x9c15d7, 5, 'call', '0xaae9af'),
    (0x9c15e9, 2, 'mov', 'dword ptr [eax], esi'),
    (0x9c15eb, 3, 'mov', 'dword ptr [eax + 4], ecx'),
    (0x9c15f1, 3, 'mov', 'dword ptr [edx + ebx*4], eax'),
    (0x9c15f4, 2, 'inc', 'dword ptr [edi]'),
    (0x9c1619, 5, 'call', '0xaae9af'),
    (0x9c1633, 3, 'mov', 'dword ptr [edx + ebx*4], eax'),
    (0x9c1636, 2, 'inc', 'dword ptr [edi]'),
    (0xaae9c9, 5, 'call', '0xab049c'),
    (0xab04e1, 6, 'call', 'dword ptr [0xc8a05c]'),
    (0x9c12e3, 4, 'lock cmpxchg', 'byte ptr [edx], cl'),
    (0x9c1321, 4, 'lock cmpxchg', 'byte ptr [edx], cl'),
    (0x9c12f9, 6, 'mov', 'edi, dword ptr [0xc8a188]'),
    (0x9c130a, 2, 'pause', ''),
    (0x9c1318, 2, 'call', 'edi'),
    (0x9c132f, 2, 'xor', 'eax, eax'),
    (0x9c1510, 5, 'mov', 'eax, dword ptr [0x1268ff0]'),
    (0x9c1515, 6, 'mov', 'ecx, dword ptr [0x1268fec]'),
    (0x9c1523, 3, 'cmp', 'dword ptr [esi + 4], eax'),
    (0x9c1528, 2, 'cmp', 'dword ptr [esi], ecx'),
    (0x9c1531, 5, 'call', '0x9c12d0'),
    (0x9c1536, 6, 'mov', 'edx, dword ptr [0x1258a9c]'),
    (0x9c153c, 7, 'movzx', 'ecx, word ptr [0x1258a90]'),
    (0x9c1543, 1, 'inc', 'edx'),
    (0x9c1544, 6, 'mov', 'dword ptr [0x1258a9c], edx'),
    (0x9c154a, 6, 'add', 'ecx, 0x1268'),
    (0x9c1550, 5, 'mov', 'byte ptr [0x131ca68], al'),
    (0x9c1555, 3, 'mov', 'dword ptr [edi + 8], ecx'),
    (0x9c1558, 3, 'mov', 'dword ptr [edi + 0xc], edx'),
]:
    claims.append({'id': f'object_registry_{address:x}', 'kind': 'instructions',
                   'space': 'rva', 'offset': hex(address - 0x400000), 'base': hex(address),
                   'arch': 'x86', 'length': length, 'mnemonics': [mnemonic], 'operands': [operands]})
verification = Verifier(data).verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in verification['results']), [
    r for r in verification['results'] if r['verdict'] != 'VERIFIED']
pe = pefile.PE(data=data)
base = pe.OPTIONAL_HEADER.ImageBase
emu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
image_size = (pe.OPTIONAL_HEADER.SizeOfImage + 4095) & ~4095
emu.mem_map(base, image_size)
emu.mem_write(base, pe.get_memory_mapped_image())
emu.mem_protect(base, image_size, unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC)
arena, key, table, buckets, links, objects = 0x20000000, 0x20000000, 0x20001000, 0x20002000, 0x20004000, 0x20008000
handle, stack, initial_sp, sentinel = 0x20020000, 0x20030000, 0x2003f000, 0x21000000
emu.mem_map(arena, 0x40000, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
emu.mem_map(sentinel, 0x1000, unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC)
def write_guard(uc, access, address, size, value, _):
    assert (stack <= address and address + size <= stack + 0x10000) or (
        address == handle and size == 4), (hex(address), size)
emu.hook_add(unicorn.UC_HOOK_MEM_WRITE, write_guard)
preserved = {UC_X86_REG_EBX: 0x12345678, UC_X86_REG_EDI: 0x23456789, UC_X86_REG_EBP: 0x34567890}
def invoke(entry, input_eax, input_ecx=0):
    emu.mem_write(initial_sp, struct.pack('<I', sentinel))
    emu.reg_write(UC_X86_REG_ESP, initial_sp)
    emu.reg_write(UC_X86_REG_EAX, input_eax)
    emu.reg_write(UC_X86_REG_ECX, input_ecx)
    incoming_esi = handle if entry == 0x967f50 else 0x45678901
    emu.reg_write(UC_X86_REG_ESI, incoming_esi)
    for reg, value in preserved.items():
        emu.reg_write(reg, value)
    emu.emu_start(entry, sentinel, count=4000)
    assert emu.reg_read(UC_X86_REG_EIP) == sentinel
    assert emu.reg_read(UC_X86_REG_ESP) == initial_sp + 4
    assert all(emu.reg_read(reg) == value for reg, value in preserved.items())
    assert emu.reg_read(UC_X86_REG_ESI) == incoming_esi
    return emu.reg_read(UC_X86_REG_EAX)

def build(rows, bucket_count):
    emu.mem_write(table, bytes(0x10000))
    emu.mem_write(table, struct.pack('<3I', 0xabcdef01, bucket_count, buckets))
    chains = [[] for _ in range(bucket_count)]
    for i, (kind, ident) in enumerate(rows):
        chains[(((kind << 16) + ident) & 0xffffffff) % bucket_count].append(i)
        emu.mem_write(objects + i * 0x20 + 8, struct.pack('<2I', kind, ident))
    for bucket, indices in enumerate(chains):
        emu.mem_write(buckets + bucket * 4, struct.pack('<I', links + indices[0]*8 if indices else 0))
        for position, i in enumerate(indices):
            emu.mem_write(links + i*8, struct.pack('<2I', objects + i*0x20,
                links + indices[position+1]*8 if position+1 < len(indices) else 0))

generator = random.Random(20261021)
raw_cases, raw_queries = [], 0
for bucket_count in (1, 3, 7, 257):
    for count in (0, 1, 5, 31, 64):
        special = [(0,0),(0,0),(0x80000000,0xffffffff),(0xffffffff,1),(0xffff,0xffffffff)]
        rows = (special + [(generator.getrandbits(32), generator.getrandbits(32)) for _ in range(count)])[:count]
        build(rows, bucket_count)
        before = bytes(emu.mem_read(table, 0x10000))
        queries = rows + [(0,1),(1,0),(0x80000000,0),(0xffffffff,0xffffffff)] + [
            (generator.getrandbits(32),generator.getrandbits(32)) for _ in range(10)]
        outputs = bytearray()
        for query in queries:
            emu.mem_write(key, struct.pack('<2I', *query))
            expected = next((objects + i*0x20 for i, row in enumerate(rows) if row == query), 0)
            actual = invoke(0x9c1d40, key, table)
            assert actual == expected, (bucket_count, count, query, hex(actual), hex(expected))
            outputs.extend(struct.pack('<I', actual))
            raw_queries += 1
        assert bytes(emu.mem_read(table, 0x10000)) == before
        raw_cases.append({'bucket_count': bucket_count, 'rows': count, 'queries': len(queries),
                          'output_sha256': hashlib.sha256(outputs).hexdigest()})

resolver_cases = []
for kind in (0, 0x1268, 0x1269, 0xffffffff):
    build([(kind,17)], 7)
    for database_present in (False, True):
        for found in (False, True):
            for initial_cache in (0, 0xa5a5a5a5):
                ident = 17 if found else 18
                # Populate only the table selected by this unsigned type threshold.
                for global_at in (0x1258a94, 0x1258a98):
                    emu.mem_write(global_at, bytes(4))
                selected = 0x1258a98 if kind <= 0x1268 else 0x1258a94
                if database_present:
                    emu.mem_write(selected, struct.pack('<I', table))
                expected = objects if database_present and found else 0
                fixture = struct.pack('<3I', initial_cache, kind, ident)
                emu.mem_write(handle, fixture)
                assert invoke(0x967f50, 0) == expected
                assert bytes(emu.mem_read(handle, 12)) == struct.pack('<3I', expected, kind, ident)
                emu.mem_write(handle, fixture)
                assert invoke(0x967f10, handle) == expected
                assert bytes(emu.mem_read(handle, 12)) == fixture
                resolver_cases.append({'type': hex(kind), 'database_present': database_present,
                                       'found': found, 'initial_cache': hex(initial_cache),
                                       'result': hex(expected), 'refresh_wrote_cache': True,
                                       'lookup_left_cache_unchanged': True})

out = ROOT / 'evidence/generated/object-registry'
out.mkdir(parents=True, exist_ok=True)
for name, value in [('claims.json', claims), ('reverify.json', verification), ('emulation.json', {
    'binary_sha256': digest, 'engine': f'unicorn {unicorn.__version__}',
    'entries_va': ['0x9c1d40','0x967f50','0x967f10'], 'raw_table_cases': raw_cases,
    'raw_queries': raw_queries, 'resolver_cases': resolver_cases, 'mismatches': 0,
    'scope': 'Original complete entries and actual call into lookup. Synthetic valid tables, '
             'acyclic chains and positive bucket counts. Invalid pointers, zero divisor, cycles, '
             'concurrent mutation, real game registry population and object ownership are excluded.',
})]:
    (out / name).write_text(json.dumps(value, indent=2) + '\n')
ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify')
ledger.record(verification, session='object-registry-and-handle-resolvers')
ledger.save()
print(f'Object registry: {raw_queries} lookup queries across {len(raw_cases)} tables; '
      f'{len(resolver_cases)} fixtures for both resolvers; no mismatches.')
