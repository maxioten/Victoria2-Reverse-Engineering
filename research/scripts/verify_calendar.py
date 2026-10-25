#!/usr/bin/env python3
"""Exercise the original calendar fragment and prove a bounded arithmetic identity."""
import hashlib
import json
from pathlib import Path
import struct
import pefile
import unicorn
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_ESI, UC_X86_REG_EBP
import z3
from reverify.verifier import Claim, Verifier
from reverify.ledger import Ledger

ROOT = Path(__file__).resolve().parents[1]
data = (ROOT.parent / 'base-game/v2game.exe').read_bytes()
digest = hashlib.sha256(data).hexdigest()
if digest != '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648':
    raise SystemExit('Binary profile mismatch')
pe = pefile.PE(data=data)
base, bias = pe.OPTIONAL_HEADER.ImageBase, 0x029c55c0
months = (31,28,31,30,31,30,31,31,30,31,30,31)
assert struct.unpack('<12I', pe.get_data(0xb1027c, 48)) == months
assert struct.unpack('<d', pe.get_data(0xa45930, 8))[0] == 365.0
claims = [
    {'id': 'calendar_increment', 'kind': 'instructions', 'offset': '0x282fa5', 'space': 'rva',
     'base': '0x682fa5', 'length': 7, 'arch': 'x86', 'mnemonics': ['add'],
     'operands': ['dword ptr [esi + 0xb0c], 0x18']},
    {'id': 'calendar_bias', 'kind': 'instructions', 'offset': '0x282f47', 'space': 'rva',
     'base': '0x682f47', 'length': 6, 'arch': 'x86', 'mnemonics': ['sub'],
     'operands': ['ecx, 0x29c55c0']},
    {'id': 'calendar_year_length', 'kind': 'bytes_at', 'offset': '0xa45930', 'space': 'rva',
     'expected': struct.pack('<d', 365.0).hex()},
    {'id': 'calendar_months', 'kind': 'bytes_at', 'offset': '0xb1027c', 'space': 'rva',
     'expected': struct.pack('<12I', *months).hex()},
]
verifier = Verifier(data)
verification = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in verification['results']), verification
emu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
emu.mem_map(base, (pe.OPTIONAL_HEADER.SizeOfImage + 4095) & ~4095)
emu.mem_write(base, pe.get_memory_mapped_image())
world, frame = 0x20000000, 0x20004000
emu.mem_map(world, 0x8000)
tested = 0
examples = []
for year in (0, 1, 1836, 1900, 1948, 2000, 2030, 9999):
    ordinal = 0
    for month, length in enumerate(months):
        for day in range(length):
            for hour in (0, 23):
                raw = bias + (year * 365 + ordinal) * 24 + hour
                emu.mem_write(world + 0xb0c, struct.pack('<I', raw))
                emu.reg_write(UC_X86_REG_ESI, world)
                emu.reg_write(UC_X86_REG_EBP, frame)
                emu.emu_start(0x682f39, 0x682f9f, count=128)
                actual_year = emu.reg_read(UC_X86_REG_ECX)
                actual_month = emu.reg_read(UC_X86_REG_EDX)
                assert (actual_year, actual_month) == (year, month), (raw, year, month, actual_year, actual_month)
                assert struct.unpack('<I', emu.mem_read(frame - 0x48, 4))[0] == month
                emu.emu_start(0x682fa5, 0x682fac, count=1)
                assert struct.unpack('<I', emu.mem_read(world + 0xb0c, 4))[0] == raw + 24
                tested += 1
                if month == 0 and day == 0 and hour == 0:
                    examples.append({'input_raw': raw, 'fragment_year': actual_year,
                                     'fragment_month_zero_based': actual_month,
                                     'raw_div_8760_minus_5000': raw // 8760 - 5000,
                                     'external_double_bias_formula': ((raw - bias) // 24) // 365 - 5000})
            ordinal += 1

# This is a proof of the declared integer model on nonnegative relative dates.
# It does not prove that every game routine uses this calendar or handles negatives alike.
raw_symbol = z3.Int('raw_hours')
solver = z3.Solver()
solver.add(raw_symbol >= bias, raw_symbol <= 0x7fffffff)
solver.add(((raw_symbol - bias) / 24) / 365 != raw_symbol / 8760 - 5000)
proof = str(solver.check())
assert proof == 'unsat'
out = ROOT / 'evidence/generated/calendar'
out.mkdir(parents=True, exist_ok=True)
(out / 'claims.json').write_text(json.dumps(claims, indent=2) + '\n')
(out / 'reverify.json').write_text(json.dumps(verification, indent=2) + '\n')
(out / 'model-proof.smt2').write_text(solver.to_smt2())
(out / 'emulation.json').write_text(json.dumps({
    'binary_sha256': digest, 'engine': f'unicorn {unicorn.__version__}',
    'calendar_fragment_va': ['0x682f39', '0x682f9f'], 'increment_va': '0x682fa5',
    'tested_inputs': tested, 'mismatches': 0, 'examples': examples,
    'z3_model_result': proof, 'z3_version': z3.get_version_string(),
    'proof_domain': 'Integer raw_hours in [43800000, INT32_MAX]; floor divisions in mathematical model.',
    'scope': 'Original fragments only. Years/months are operational labels from the reference. '
             'Negative relative dates, complete calendar APIs and all world update effects are not covered.',
}, indent=2) + '\n')
ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify')
ledger.record(verification, session='calendar-static-fragments')
ledger.save()
print(f'Calendar: {tested} original-fragment inputs, 0 mismatches; Z3 identity {proof}; four reverify checks pass.')
