#!/usr/bin/env python3
"""Build isolated PE32 original POP-vector growth probe; never run engine init."""
import hashlib
import json
from pathlib import Path
import subprocess
import pefile

ROOT=Path(__file__).resolve().parents[1]
data=(ROOT.parent/'base-game/v2game.exe').read_bytes()
digest=hashlib.sha256(data).hexdigest()
assert digest=='62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'
pe=pefile.PE(data=data)
imports={i.address:(e.dll.decode(),i.name.decode() if i.name else None) for e in pe.DIRECTORY_ENTRY_IMPORT for i in e.imports}
assert imports[0xc8a05c]==('KERNEL32.dll','HeapAlloc')
assert imports[0xc8a070]==('KERNEL32.dll','HeapFree')
assert imports[0xc8a188]==('KERNEL32.dll','SwitchToThread')
out=ROOT/'evidence/generated/native-growth';out.mkdir(parents=True,exist_ok=True)
source=ROOT/'harnesses/native_pop_growth.c';header=ROOT/'harnesses/native_private_image.h'
exe=out/'growth-probe.exe'
command=[str(ROOT.parent/'tools/mingw-local/root/usr/bin/i686-w64-mingw32-gcc'),
    '-std=c11','-O2','-Wall','-Wextra','-Werror','-static-libgcc',
    '-Wl,--image-base,0x20000000,--disable-dynamicbase,--nxcompat',str(source),'-o',str(exe)]
subprocess.run(command,check=True)
probe=pefile.PE(str(exe));assert probe.OPTIONAL_HEADER.ImageBase==0x20000000
assert not probe.OPTIONAL_HEADER.DllCharacteristics&0x40
receipt=dict(binary_sha256=digest,source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
    loader_source_sha256=hashlib.sha256(header.read_bytes()).hexdigest(),exe_sha256=hashlib.sha256(exe.read_bytes()).hexdigest(),
    compiler_command=command,private_reference_base='0x30000000',loader_delta='0x2fc00000',highlow_relocations=249412,
    expected_cases=9897,expected_actual_heap_allocs=31116,expected_actual_heap_frees=29997,expected_pre_free_snapshots=29997,
    expected_distribution_cases=336,expected_catalog_cases=216,expected_constructor_cases=384,expected_optional_cases=192,expected_catalog_words_checked=27072,
    expected_pool_copy_cases=480,
    expected_optional_copy_cases=180,
    expected_combined_copy_cases=216,
    expected_registered_copy_cases=108,expected_registered_growth_cases=108,
    expected_factory_cases=1053,expected_consumer_cases=1080,expected_consumer_merge_cases=1152,expected_consumer_type_selection_cases=1536,expected_internal_selector_cases=2178,expected_internal_integration_cases=960,
    fixture_writes_va={
        '0x00c8a05c':'HeapAlloc IAT forwards real HeapAlloc, checks size then fills returned uninitialized block with declared pattern',
        '0x00c8a070':'HeapFree IAT checks pre-free snapshot/order then forwards real HeapFree',
        '0x00c8a188':'SwitchToThread IAT rejects unexpected use',
        '0x00f202e8':'CRT heap -> private HeapCreate handle',
        '0x01258a94':'registry A absent except explicit registered-source fixtures with controlled tables',
        '0x01258a98':'registry B absent except explicit registered-source fixtures with controlled tables',
        '0x01268fec':'default key word 0x76543210','0x01268ff0':'default key word 0xfedcba98',
        '0x0131bb34':'existing singleton fixture','0x012586dc':'existing cache source fixture',
        '0x01258a48':'catalog B fixture, empty or 0..7 entries with controlled +0x30 metadata',
        '0x01258a3c':'catalog A fixture, empty or 0..7 entries with controlled +8 metadata',
        '0x012587ec':'constructor pre-existing singleton fixture at catalog storage+0xa00',
        '0x0125880c':'constructor pre-existing singleton fixture at catalog storage+0xb00',
        '0x0125e448':'8-byte optional-vector initial value fixture (also writes high dword at +4)',
        '0x012587f4':'number of map bytes copied by CGoodsPool assignment; fixture 0/1/31/64',
        '0x01258728':'pre-existing singleton/array fixture for complete factory-internal selector calls;cleared after each case',
        '0x012588e8':'controlled movement-log world fixture for full consumer new-node cases',
        '0x01258a2c':'pre-existing CNullPopType fixture with original RTTI-linked vtable',
        '0x00f09568':'factory-specific ID counter seed; original code uses old value and increments with32-bit wrap',
        '0x00f20c0c':'pre-existing default-constructor cache fixture; no lazy world initialization',
        '0x00f20c04':'cache reset before each call, original copy code writes observed value',
        '0x00f20c08':'cache reset before each call, original copy code writes observed value'},
    status='compiled_only; execution unvalidated')
(out/'build.json').write_text(json.dumps(receipt,indent=2)+'\n')
print('Built native growth probe: '+str(out))
