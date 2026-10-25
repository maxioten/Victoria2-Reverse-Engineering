#!/usr/bin/env python3
"""Compile a private-image PE32 POP lifetime probe, bound to the reference hash."""
import hashlib
import json
from pathlib import Path
import subprocess
import pefile

ROOT = Path(__file__).resolve().parents[1]
reference = ROOT.parent / 'base-game/v2game.exe'
data = reference.read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'
pe = pefile.PE(data=data)
assert pe.OPTIONAL_HEADER.ImageBase == 0x400000
assert pe.OPTIONAL_HEADER.SizeOfImage == 0x1092000
imports = {i.address: (e.dll.decode(), i.name.decode() if i.name else None)
           for e in pe.DIRECTORY_ENTRY_IMPORT for i in e.imports}
assert imports[0xc8a070] == ('KERNEL32.dll', 'HeapFree')
assert imports[0xc8a05c] == ('KERNEL32.dll', 'HeapAlloc')
assert imports[0xc8a188] == ('KERNEL32.dll', 'SwitchToThread')
relocations = [entry for block in pe.DIRECTORY_ENTRY_BASERELOC for entry in block.entries]
assert all(entry.type in (0, 3) for entry in relocations)
assert sum(entry.type == 3 for entry in relocations) == 249412
out = ROOT / 'evidence/generated/native-pop'
out.mkdir(parents=True, exist_ok=True)
compiler = ROOT.parent / 'tools/mingw-local/root/usr/bin/i686-w64-mingw32-gcc'
source = ROOT / 'harnesses/native_pop_lifetime.c'
command = [str(compiler), '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-static-libgcc',
           '-Wl,--image-base,0x20000000,--disable-dynamicbase,--nxcompat',
           str(source), '-o', str(out / 'pop-probe.exe')]
subprocess.run(command, check=True)
probe = pefile.PE(str(out / 'pop-probe.exe'))
assert probe.OPTIONAL_HEADER.ImageBase == 0x20000000
assert not probe.OPTIONAL_HEADER.DllCharacteristics & 0x40
(out / 'build.json').write_text(json.dumps({
    'binary_sha256': digest,
    'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
    'registry_source_sha256': hashlib.sha256((ROOT / 'harnesses/native_registry_cases.h').read_bytes()).hexdigest(),
    'exe_sha256': hashlib.sha256((out / 'pop-probe.exe').read_bytes()).hexdigest(),
    'compiler_command': command,
    'probe_image_base': '0x20000000', 'private_reference_base': '0x30000000',
    'original_preferred_base': '0x00400000', 'loader_delta': '0x2fc00000',
    'highlow_relocations': 249412,
    'expected_cases': 452, 'expected_actual_heap_frees': 790, 'expected_pre_free_snapshots': 350,
    'expected_registry_cases': 274, 'expected_registry_heap_frees': 76,
    'expected_actual_heap_allocs':81, 'expected_registered_pop_cases':41,
    'expected_automatic_id_cases':36, 'expected_lock_cases':3,
    'expected_cases_by_entry': {'pop_unlink':134, 'registry_remove':114, 'registry_deregister':80,
                              'registry_insert':80, 'registered_pop_lifecycle':5,
                              'automatic_pop_lifecycle':36, 'spinlock_acquire':3},
    'fixture_writes_va': {
        '0x00c8a070': 'HeapFree IAT -> recording callback forwarding to real HeapFree',
        '0x00c8a05c': 'HeapAlloc IAT -> recording callback forwarding to real HeapAlloc; success paths only',
        '0x00c8a188': 'SwitchToThread IAT -> recording callback forwarding to real SwitchToThread',
        '0x00f202e8': 'CRT heap -> new private HeapCreate handle',
        '0x01258a94': 'registry A: absent in POP phase; controlled fixture in registry phase',
        '0x01258a98': 'registry B: absent in POP phase; controlled fixture in registry phase',
        '0x012588e8': 'private 0xd20-byte state fixture, byte +0xd1d=1, byte +0xd1c=0',
        '0x01258a90': '16-bit automatic type offset fixture, upper neighbor word unchanged',
        '0x01258a9c': '32-bit automatic ID counter seed and observed increment',
        '0x0131ca68': 'one-byte automatic-ID lock, initially zero; isolated contention cases also use 1 and 0x7f',
    },
    'status': 'compiled_only; native execution not yet validated',
}, indent=2) + '\n')
print('Built isolated PE32 POP lifetime probe: ' + str(out))
