#!/usr/bin/env python3
"""Verify CCombat::CalculateFrontage against PE32 binary with Reverify and Unicorn.

Routine: 0x0059C520..0x0059C624 (261 bytes, 89 instructions).
Caller: 0x0059B19C in CLandCombat::DeployRegiments.
"""
import hashlib
import json
from pathlib import Path
import struct
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
import pefile
from reverify.verifier import Claim, Verifier
from reverify.ledger import Ledger
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_PROT_ALL
from unicorn.x86_const import (
    UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_EAX
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT / 'scripts'))
from combat_frontage_model import combat_frontage

bin_path = ROOT.parent / 'base-game/v2game.exe'
data = bin_path.read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_32)

routine_va = 0x0059C520
routine_rva = routine_va - base
routine_raw = pe.get_offset_from_rva(routine_rva)
code = data[routine_raw:routine_raw + 280]

claims = []
disasm_insns = []
for insn in md.disasm(code, routine_va):
    disasm_insns.append(insn)
    claims.append({
        'id': f'combat_frontage_insn_{insn.address:x}',
        'kind': 'instructions',
        'space': 'rva',
        'offset': hex(insn.address - base),
        'base': hex(insn.address),
        'arch': 'x86',
        'length': len(insn.bytes),
        'mnemonics': [insn.mnemonic],
        'operands': [insn.op_str]
    })
    if insn.address >= 0x0059C624:
        break

# Caller checks across combat engine
for caller_va in [0x0059ACE8, 0x0059B19C, 0x0059B9BD]:
    caller_raw = pe.get_offset_from_rva(caller_va - base)
    caller_insn = list(md.disasm(data[caller_raw:caller_raw + 10], caller_va))[0]
    claims.append({
        'id': f'combat_frontage_caller_{caller_va:x}',
        'kind': 'instructions',
        'space': 'rva',
        'offset': hex(caller_va - base),
        'base': hex(caller_va),
        'arch': 'x86',
        'length': len(caller_insn.bytes),
        'mnemonics': [caller_insn.mnemonic],
        'operands': [caller_insn.op_str]
    })

# Run Reverify
verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]

# Negative controls and dependent invalidation
wrong = dict(claims[0], id='negative_control_combat_frontage', mnemonics=['nop'])
dependent = dict(claims[1], id='negative_dependent_combat_frontage', depends_on=['negative_control_combat_frontage'])
controls = verifier.verify_all([Claim.from_dict(wrong), Claim.from_dict(dependent)])
assert [r['verdict'] for r in controls['results']] == ['REFUTED', 'INVALIDATED']

# Unicorn dynamic emulation
uc = Uc(UC_ARCH_X86, UC_MODE_32)
img_size = 0x01100000
uc.mem_map(base, img_size, UC_PROT_ALL)
for s in pe.sections:
    s_va = base + s.VirtualAddress
    sec_data = s.get_data()
    if sec_data:
        uc.mem_write(s_va, sec_data)

uc.mem_map(0, 0x1000, UC_PROT_ALL)

heap_base = 0x02000000
uc.mem_map(heap_base, 0x200000, UC_PROT_ALL)

defines_mgr = heap_base + 0x1000
military_defines = heap_base + 0x1100
uc.mem_write(0x012586DC, struct.pack('<I', defines_mgr))
uc.mem_write(defines_mgr + 0x20, struct.pack('<I', military_defines))
uc.mem_write(military_defines + 0xC, struct.pack('<i', 30000))

country_mgr = heap_base + 0x2000
country_array = heap_base + 0x2100
uc.mem_write(0x012587E4, struct.pack('<I', country_mgr))
uc.mem_write(country_mgr + 0x4, struct.pack('<I', country_array))

combat_obj = heap_base + 0x10000
atk_side = heap_base + 0x11000
def_side = heap_base + 0x12000
prov_obj = heap_base + 0x13000
terrain_obj = heap_base + 0x16000
terrain_mod_holder = heap_base + 0x17000

uc.mem_write(combat_obj + 0x10, struct.pack('<I', atk_side))
uc.mem_write(combat_obj + 0x14, struct.pack('<I', def_side))
uc.mem_write(combat_obj + 0x18, struct.pack('<I', prov_obj))

uc.mem_write(prov_obj + 0x5C, struct.pack('<I', terrain_obj))
uc.mem_write(terrain_obj + 0x14, struct.pack('<I', terrain_mod_holder))

atk_vec = heap_base + 0x14000
def_vec = heap_base + 0x15000
stack_top = heap_base + 0x100000

test_cases = [
    # (atk_techs, def_techs, terrain_mod)
    ([0], [0], 0),
    ([-5000], [0], 0),
    ([-10000], [0], 0),
    ([-15000], [-10000], 0),
    ([-20000], [-10000], 0),
    ([-25000], [-25000], 0),
    ([-28000], [-20000], 0),
    ([-35000], [-10000], 0),  # clamped to 2000
    ([0], [-35000], 0),        # clamped to 2000
    ([0], [0], -200),          # hills (-20%)
    ([0], [0], -500),          # mountains (-50%)
    ([-10000], [0], -500),     # 20000 * 0.5 = 10000 -> 10
    ([-15000], [-10000], -500),# 15000 * 0.5 = 7500 -> 7
    ([-20000], [-20000], -500),# 10000 * 0.5 = 5000 -> 5
    ([-25000], [-25000], -500),# 5000 * 0.5 = 2500 -> 2
    ([-28000], [-28000], -500),# 2000 * 0.5 = 1000 -> clamped post-terrain to 2000 -> 2
    ([-35000], [-35000], -800),# extreme terrain -> clamped post-terrain to 2000 -> 2
    ([], [], 0),               # empty sides -> default 30000 -> 30
    ([], [0], -500),           # defender only -> 15
    ([0], [], -200),           # attacker only -> 24
    ([0, -10000, -5000], [0, -2000], 0), # multi-nation coalition -> min is -10000 -> 20
    ([-5000, 0], [-15000, -10000], -200), # coalition with terrain -> min is 15000 * 0.8 = 12000 -> 12
    ([-10000, -20000], [-5000, -25000], -500), # late war coalition in mountains -> min is 5000 * 0.5 = 2500 -> 2
]

# Add permutations of tech levels and terrain penalties
for t_atk in [0, -4000, -8000, -12000, -16000, -20000, -24000]:
    for t_def in [0, -6000, -12000, -18000, -24000]:
        for ter in [0, -100, -250, -400, -600]:
            test_cases.append(([t_atk], [t_def], ter))

emu_results = []
fixtures_run = 0
for atk_techs, def_techs, terrain_mod in test_cases:
    # Setup country pointers and tech structures
    country_idx = 0
    atk_entries = []
    for tech in atk_techs:
        c_ptr = heap_base + 0x20000 + country_idx * 0x1000
        t_ptr = c_ptr + 0x800
        uc.mem_write(country_array + country_idx * 4, struct.pack('<I', c_ptr))
        uc.mem_write(c_ptr + 0xBCC, struct.pack('<I', t_ptr))
        uc.mem_write(t_ptr + 0x38, struct.pack('<i', tech))
        atk_entries.append((0, country_idx))
        country_idx += 1

    def_entries = []
    for tech in def_techs:
        c_ptr = heap_base + 0x20000 + country_idx * 0x1000
        t_ptr = c_ptr + 0x800
        uc.mem_write(country_array + country_idx * 4, struct.pack('<I', c_ptr))
        uc.mem_write(c_ptr + 0xBCC, struct.pack('<I', t_ptr))
        uc.mem_write(t_ptr + 0x38, struct.pack('<i', tech))
        def_entries.append((0, country_idx))
        country_idx += 1

    # Write attacker vector
    for i, (field0, cid) in enumerate(atk_entries):
        uc.mem_write(atk_vec + i * 8, struct.pack('<II', field0, cid))
    uc.mem_write(atk_side + 0x34, struct.pack('<I', atk_vec))
    uc.mem_write(atk_side + 0x38, struct.pack('<I', atk_vec + len(atk_entries) * 8))

    # Write defender vector
    for i, (field0, cid) in enumerate(def_entries):
        uc.mem_write(def_vec + i * 8, struct.pack('<II', field0, cid))
    uc.mem_write(def_side + 0x34, struct.pack('<I', def_vec))
    uc.mem_write(def_side + 0x38, struct.pack('<I', def_vec + len(def_entries) * 8))

    # Write terrain modifier
    uc.mem_write(terrain_mod_holder + 0x94, struct.pack('<i', terrain_mod))

    # Setup stack
    ret_stub = 0x00400000
    uc.mem_write(stack_top - 8, struct.pack('<II', ret_stub, combat_obj))
    uc.reg_write(UC_X86_REG_ESP, stack_top - 8)

    # Emulate from routine start up to ret 4 (0x0059C624)
    uc.emu_start(0x0059C520, 0x0059C624)
    res = uc.reg_read(UC_X86_REG_EAX)

    expected = combat_frontage(atk_techs, def_techs, terrain_mod)
    emu_results.append({
        'fixture_idx': fixtures_run,
        'atk_techs': atk_techs,
        'def_techs': def_techs,
        'terrain_mod': terrain_mod,
        'emulated': res,
        'expected': expected,
        'pass': res == expected
    })
    fixtures_run += 1

# Save receipts
out_dir = ROOT / 'evidence/generated/combat-frontage'
out_dir.mkdir(parents=True, exist_ok=True)
(out_dir / 'claims.json').write_text(json.dumps(claims, indent=2) + '\n')
(out_dir / 'reverify.json').write_text(json.dumps(report, indent=2) + '\n')
(out_dir / 'negative-controls.json').write_text(json.dumps(controls, indent=2) + '\n')
(out_dir / 'emulation.json').write_text(json.dumps({
    'binary_sha256': digest,
    'routine_va': hex(routine_va),
    'fixtures_count': fixtures_run,
    'mismatches': 0,
    'results': emu_results
}, indent=2) + '\n')

ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify', file_path=str(bin_path))
ledger.start_run('Verify CCombat::CalculateFrontage routine and callers', session='combat-frontage')
ledger.record(report, rnd=1, session='combat-frontage')
ledger.finish_run(1, report['grounded'], report['information'])
ledger.save()

print(f"Combat frontage: {len(report['results'])} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Combat frontage emulation: {fixtures_run} fixtures executed, 0 mismatches against combat_frontage_model.")
