#!/usr/bin/env python3
"""Execute the original date preparation and POP scheduling guard, without updating POPs."""
import hashlib
import json
from pathlib import Path
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
    (0x509232, 6, 'mov', 'eax, dword ptr [eax + 0xb0c]'),
    (0x509306, 3, 'mov', 'dword ptr [ebp - 0x7c], ecx'),
    (0x50933a, 7, 'mov', 'eax, dword ptr [ecx*4 + 0xf1027c]'),
    (0x5093cb, 3, 'cmp', 'dword ptr [edi + 0x58], esi'),
    (0x5093ce, 6, 'jle', '0x509467'),
    (0x5093d4, 3, 'mov', 'eax, dword ptr [edi + 0xc]'),
    (0x5093d7, 2, 'xor', 'edx, edx'),
    (0x5093d9, 3, 'div', 'dword ptr [ebp - 0x1c]'),
    (0x5093dc, 3, 'cmp', 'dword ptr [ebp - 0x7c], edx'),
    (0x5093df, 6, 'jne', '0x509462'),
    (0x5093c0, 6, 'mov', 'edx, dword ptr [edi + 0x27c]'),
    (0x5093c8, 3, 'mov', 'dword ptr [ebp - 0x14], edx'),
    (0x50945d, 5, 'call', '0x957ea0'),
    (0x50946b, 5, 'call', '0x4b9250'),
    (0x509472, 3, 'mov', 'edi, dword ptr [ebp - 0x14]'),
    (0x509477, 6, 'jne', '0x5093c0'),
    (0x50947d, 4, 'add', 'dword ptr [ebp - 0x18], 0x10'),
]:
    claims.append({'id': f'pop_schedule_{address:x}', 'kind': 'instructions',
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
memory, frame, world, country, pop = 0x20000000, 0x20008000, 0x20010000, 0x20012000, 0x20014000
emu.mem_map(memory, 0x20000, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
def stop_guard(uc, address, size, _):
    uc.emu_stop()
for boundary in (0x5093e5, 0x509462, 0x509467):
    emu.hook_add(unicorn.UC_HOOK_CODE, stop_guard, begin=boundary, end=boundary)
def write_guard(uc, access, address, size, value, _):
    assert frame - 0x200 <= address and address + size <= frame + 0x10, hex(address)
emu.hook_add(unicorn.UC_HOOK_MEM_WRITE, write_guard)
months = (31,28,31,30,31,30,31,31,30,31,30,31)
assert tuple(struct.unpack('<12I', pe.get_data(0xb1027c, 48))) == months
dates, guards, selected = 0, 0, 0
for year in (1836, 1900):
    ordinal = 0
    for month, length in enumerate(months):
        for day in range(length):
            for hour in (0, 23):
                raw = 43800000 + (year * 365 + ordinal) * 24 + hour
                emu.mem_write(world + 0xb0c, struct.pack('<I', raw))
                emu.reg_write(UC_X86_REG_EAX, world)
                emu.reg_write(UC_X86_REG_EBX, country)
                emu.reg_write(UC_X86_REG_ECX, 0)
                emu.reg_write(UC_X86_REG_EDI, 0)
                emu.reg_write(UC_X86_REG_ESI, 0)
                emu.reg_write(UC_X86_REG_EBP, frame)
                emu.reg_write(UC_X86_REG_ESP, frame + 0x1000)
                emu.emu_start(0x50921b, 0x509341, count=256)
                assert emu.reg_read(UC_X86_REG_EIP) == 0x509341
                assert emu.reg_read(UC_X86_REG_EAX) == length
                assert struct.unpack('<I', emu.mem_read(frame - 0x7c, 4))[0] == day
                # This store normally follows at VA 509349; seed the same local for the isolated guard.
                emu.mem_write(frame - 0x1c, struct.pack('<I', length))
                dates += 1
                for ident in (0, 1, length - 1, length, length + 1, 65535, 0x80000000, 0xffffffff):
                    for population_size in (0, 1, 0xffffffff):
                        emu.mem_write(pop + 0xc, struct.pack('<I', ident))
                        emu.mem_write(pop + 0x58, struct.pack('<I', population_size))
                        emu.reg_write(UC_X86_REG_EDI, pop)
                        emu.emu_start(0x5093c6, 0x5093e5, count=16)
                        at = emu.reg_read(UC_X86_REG_EIP)
                        expected = 0x509467 if population_size in (0, 0xffffffff) else (
                            0x5093e5 if ident % length == day else 0x509462)
                        assert at == expected, (year, month, day, ident, population_size, hex(at))
                        selected += at == 0x5093e5
                        guards += 1
            ordinal += 1
out = ROOT / 'evidence/generated/pop-schedule'
out.mkdir(parents=True, exist_ok=True)
for name, value in [('claims.json', claims), ('reverify.json', verification), ('emulation.json', {
    'binary_sha256': digest, 'engine': f'unicorn {unicorn.__version__}',
    'calendar_fragment_va': ['0x50921b', '0x509341'],
    'guard_entry_va': '0x5093c6', 'dates_tested': dates, 'guards_tested': guards,
    'selected_cases': selected, 'mismatches': 0,
    'operational_rule': 'signed32(pop+0x58)>0 and unsigned32(pop+0xc)%month_length == zero_based_day',
    'scope': 'Synthetic objects and two isolated original fragments. Local month length seeded from the '
             'calendar result; actual POP update, merging, allocation, effects and linked-list lifetime excluded.',
})]:
    (out / name).write_text(json.dumps(value, indent=2) + '\n')
ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify')
ledger.record(verification, session='pop-schedule-guard')
ledger.save()
print(f'POP schedule: {dates} date inputs; {guards} guarded cases; 0 mismatches.')
