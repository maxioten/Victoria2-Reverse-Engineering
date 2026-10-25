#!/usr/bin/env python3
"""Check original 64-bit arithmetic helpers including observable argument-stack writes."""
import hashlib
import json
from pathlib import Path
import struct
import pefile
import unicorn
from unicorn.x86_const import (
    UC_X86_REG_EAX, UC_X86_REG_EBP, UC_X86_REG_EBX, UC_X86_REG_EDI,
    UC_X86_REG_EDX, UC_X86_REG_EIP, UC_X86_REG_ESI, UC_X86_REG_ESP,
)
from reverify.ledger import Ledger
from reverify.verifier import Claim, Verifier
from integer_model import MASK, test_pairs, trunc_div

ROOT = Path(__file__).resolve().parents[1]
data = (ROOT.parent / 'base-game/v2game.exe').read_bytes()
digest = hashlib.sha256(data).hexdigest()
if digest != '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648':
    raise SystemExit('Binary profile mismatch')
claims = []
for address, length, mnemonic, operands in [
    (0xac02a5, 4, 'mov', 'eax, dword ptr [esp + 0x14]'),
    (0xac02b9, 4, 'mov', 'dword ptr [esp + 0x14], eax'),
    (0xac02d5, 4, 'mov', 'dword ptr [esp + 0x1c], eax'),
    (0xac02eb, 2, 'div', 'ecx'),
    (0xac0313, 2, 'div', 'ecx'),
    (0xac0335, 1, 'dec', 'esi'),
    (0xac0347, 3, 'ret', '0x10'),
    (0xac9f34, 2, 'mul', 'ecx'),
    (0xac9f4c, 2, 'mul', 'ecx'),
    (0xac9f51, 3, 'ret', '0x10'),
]:
    claims.append({'id': f'int_helper_{address:x}', 'kind': 'instructions',
                   'space': 'rva', 'offset': hex(address - 0x400000), 'base': hex(address),
                   'arch': 'x86', 'length': length, 'mnemonics': [mnemonic], 'operands': [operands]})
verification = Verifier(data).verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in verification['results']), verification
pe = pefile.PE(data=data)
base = pe.OPTIONAL_HEADER.ImageBase
emu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
image_size = (pe.OPTIONAL_HEADER.SizeOfImage + 4095) & ~4095
emu.mem_map(base, image_size)
emu.mem_write(base, pe.get_memory_mapped_image())
emu.mem_protect(base, image_size, unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC)
stack, initial_sp, sentinel = 0x20000000, 0x20008000, 0x21000000
emu.mem_map(stack, 0x10000, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
emu.mem_map(sentinel, 0x1000, unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC)
def write_guard(uc, access, address, size, value, _):
    assert stack <= address and address + size <= stack + 0x10000, hex(address)
emu.hook_add(unicorn.UC_HOOK_MEM_WRITE, write_guard)
coverage = {}
def note(uc, address, size, _):
    coverage[hex(address)] = coverage.get(hex(address), 0) + 1
for address in (0xac02e1,0xac02f9,0xac0335,0xac033d,0xac9f30,0xac9f39):
    emu.hook_add(unicorn.UC_HOOK_CODE, note, begin=address, end=address)
preserved = {UC_X86_REG_EBX: 0x12345678, UC_X86_REG_ESI: 0x23456789,
             UC_X86_REG_EDI: 0x34567890, UC_X86_REG_EBP: 0x45678901}
def invoke(entry, a, b, expect_fault=False):
    emu.mem_write(initial_sp, struct.pack('<IQQ', sentinel, a & MASK, b & MASK))
    emu.reg_write(UC_X86_REG_ESP, initial_sp)
    for reg, value in preserved.items():
        emu.reg_write(reg, value)
    try:
        emu.emu_start(entry, sentinel, count=1024)
    except unicorn.UcError as error:
        if expect_fault and error.errno == unicorn.UC_ERR_EXCEPTION:
            assert emu.reg_read(UC_X86_REG_EIP) == 0xac02eb
            return {'fault': '#DE observed in Unicorn', 'va': '0xac02eb'}
        raise
    assert not expect_fault, 'Division by zero unexpectedly returned'
    assert emu.reg_read(UC_X86_REG_EIP) == sentinel
    assert emu.reg_read(UC_X86_REG_ESP) == initial_sp + 20
    assert all(emu.reg_read(reg) == value for reg, value in preserved.items())
    actual = (emu.reg_read(UC_X86_REG_EDX) << 32) | emu.reg_read(UC_X86_REG_EAX)
    arguments = bytes(emu.mem_read(initial_sp + 4, 16))
    if entry == 0xac02a0:
        assert actual == trunc_div(a, b) & MASK, (a, b, hex(actual))
        assert arguments == struct.pack('<QQ', abs(a) & MASK, abs(b) & MASK)
    else:
        assert actual == (a * b) & MASK, (a, b, hex(actual))
        assert arguments == struct.pack('<QQ', a & MASK, b & MASK)
    return actual

pairs = test_pairs()
divisions, multiplications, samples = 0, 0, []
for a,b in pairs:
    product = invoke(0xac9f20, a, b)
    multiplications += 1
    if b:
        quotient = invoke(0xac02a0, a, b)
        divisions += 1
        if (a,b) in ((-3,2),(3,-2),(-(1<<63),-1),((1<<63)-1,1)):
            samples.append({'a':a,'b':b,'quotient_bits':hex(quotient),'product_bits':hex(product)})
faults = []
normal_machine = emu
for a in (0,1,-1,-(1<<63),(1<<63)-1):
    # Each CPU-fault observation starts with a fresh machine. Reusing Unicorn
    # after an unhandled #DE can retain exception state across emu_start calls.
    emu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
    emu.mem_map(base, image_size)
    emu.mem_write(base, pe.get_memory_mapped_image())
    emu.mem_protect(base, image_size, unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC)
    emu.mem_map(stack, 0x10000, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
    emu.mem_map(sentinel, 0x1000, unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC)
    emu.hook_add(unicorn.UC_HOOK_MEM_WRITE, write_guard)
    faults.append({'a':a,'b':0,**invoke(0xac02a0,a,0,expect_fault=True)})
emu = normal_machine
for address in ('0xac02e1','0xac02f9','0xac0335','0xac033d','0xac9f30','0xac9f39'):
    assert coverage.get(address,0) > 0, address
out = ROOT / 'evidence/generated/integer-helpers'
out.mkdir(parents=True, exist_ok=True)
for name, value in [('claims.json', claims), ('reverify.json', verification), ('emulation.json', {
    'binary_sha256': digest, 'engine': f'unicorn {unicorn.__version__}',
    'entries_va': ['0xac02a0','0xac9f20'], 'division_cases': divisions,
    'multiplication_cases': multiplications, 'zero_divisor_cases': faults,
    'samples': samples, 'selected_block_coverage': coverage, 'mismatches': 0,
    'scope': 'Complete original entries, deterministic edge/random inputs. Arithmetic results, '
             'argument-stack mutation and nonvolatile registers checked; flags and volatile registers '
             'not compared. Divide-by-zero CPU exception observed, no game SEH unwinding. '
             'Finite tests are not universal equivalence proofs and do not establish caller fixed-point scale.',
})]:
    (out / name).write_text(json.dumps(value, indent=2) + '\n')
ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify')
ledger.record(verification, session='integer64-division-multiplication')
ledger.save()
print(f'Integer helpers: {divisions} signed divisions, {multiplications} modular products, 5 zero-divisor faults; no mismatches.')
