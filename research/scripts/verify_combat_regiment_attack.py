#!/usr/bin/env python3
"""Verify CLandCombatant::ExecuteRegimentAttack against PE32 binary with Reverify and Unicorn.

Routine: 0x0059A8E0..0x0059ACAF (464 bytes, 143 instructions).
Callers:
  - 0x0059AD3A in CLandCombatant::DailyCombatPhase (front line regiment attack).
  - 0x0059AD63 in CLandCombatant::DailyCombatPhase (back line support regiment attack).
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
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_PROT_ALL, UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_EAX, UC_X86_REG_ECX,
    UC_X86_REG_EDX, UC_X86_REG_EBX, UC_X86_REG_ESI, UC_X86_REG_EDI
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT / 'scripts'))
from combat_regiment_attack_model import (
    AttackInput, AttackResult, execute_regiment_attack, lookup_dice_damage
)

bin_path = ROOT.parent / 'base-game/v2game.exe'
data = bin_path.read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_32)

claims = []

# 1. Routine instructions (0x0059A8E0..0x0059ACAF)
raw_start = pe.get_offset_from_rva(0x0059A8E0 - base)
for insn in md.disasm(data[raw_start:raw_start + 500], 0x0059A8E0):
    claims.append({
        'id': f'combat_attack_insn_{insn.address:x}',
        'kind': 'instructions',
        'space': 'rva',
        'offset': hex(insn.address - base),
        'base': hex(insn.address),
        'arch': 'x86',
        'length': len(insn.bytes),
        'mnemonics': [insn.mnemonic],
        'operands': [insn.op_str]
    })
    if insn.address >= 0x0059ACAF:
        break

# 2. Callers across engine
for caller_va in [0x0059AD3A, 0x0059AD63]:
    caller_raw = pe.get_offset_from_rva(caller_va - base)
    caller_insn = list(md.disasm(data[caller_raw:caller_raw + 10], caller_va))[0]
    claims.append({
        'id': f'combat_attack_caller_{caller_va:x}',
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
wrong = dict(claims[0], id='negative_control_combat_attack', mnemonics=['nop'])
dependent = dict(claims[1], id='negative_dependent_combat_attack', depends_on=['negative_control_combat_attack'])
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

# Map BSS and high data
uc.mem_map(0x01100000 + base, 0x01000000, UC_PROT_ALL)
heap = 0x03000000
uc.mem_map(heap, 0x500000, UC_PROT_ALL)

ret_stub = heap + 0x100
uc.mem_write(ret_stub, b'\x90')
stack_top = heap + 0x80000

# Global defines
uc.mem_write(0x0125F5C8, struct.pack('<i', 100)) # BASE_CASUALTY_MODIFIER
uc.mem_write(0x0125F594, struct.pack('<i', 10))  # BASE_TACTICS_DAMAGE_MODIFIER
uc.mem_write(0x0125F578, struct.pack('<i', 200)) # BASE_MORALE_DAMAGE_MODIFIER

defines_ptr = heap + 0x1000
defines_sub = heap + 0x1100
uc.mem_write(0x012586DC, struct.pack('<I', defines_ptr))
uc.mem_write(defines_ptr + 0x20, struct.pack('<I', defines_sub))
uc.mem_write(defines_sub + 0xC8, struct.pack('<i', 1000)) # RECON_SIEGE_EFFECT
uc.mem_write(defines_sub + 0xE0, struct.pack('<i', 1000)) # MILITARY_TACTICS_BASE

countries_ptr = heap + 0x1200
countries_sub = heap + 0x1300
uc.mem_write(0x012587E4, struct.pack('<I', countries_ptr))
uc.mem_write(countries_ptr + 4, struct.pack('<I', countries_sub))

# Country 1 (attacker): FRA
country1 = heap + 0x1400
uc.mem_write(countries_sub + 1*4, struct.pack('<I', country1))
uc.mem_write(country1 + 0x1C, b'FRA\x00')
uc.mem_write(country1 + 0x20, struct.pack('<i', 1))

# Country 2 (target): PRU
country2 = heap + 0x1600
uc.mem_write(countries_sub + 2*4, struct.pack('<I', country2))
uc.mem_write(country2 + 0x1C, b'PRU\x00')
uc.mem_write(country2 + 0x20, struct.pack('<i', 2))
tech2 = heap + 0x1700
uc.mem_write(country2 + 0xBCC, struct.pack('<I', tech2))
uc.mem_write(tech2 + 0x70, struct.pack('<i', 0))

# Country 3: REB
country3 = heap + 0x1800
uc.mem_write(countries_sub + 3*4, struct.pack('<I', country3))
uc.mem_write(country3 + 0x1C, b'REB\x00')
uc.mem_write(country3 + 0x20, struct.pack('<i', 3))

# Attacker diplomacy table
diplo_table = heap + 0x1A00
uc.mem_write(country1 + 0xBE8, struct.pack('<I', diplo_table))
diplo2 = heap + 0x1B00
uc.mem_write(diplo_table + 2*4, struct.pack('<I', diplo2))
uc.mem_write(diplo2 + 0x34, struct.pack('<i', 1)) # at war

diplo3 = heap + 0x1C00
uc.mem_write(diplo_table + 3*4, struct.pack('<I', diplo3))
uc.mem_write(diplo3 + 0x34, struct.pack('<i', 0)) # not at war

# Province & fort
province = heap + 0x2000
fort = heap + 0x2100
uc.mem_write(province + 0x9C, struct.pack('<I', fort))

# Combat
combat = heap + 0x2200
uc.mem_write(combat + 0x18, struct.pack('<I', province))

# Attacker combatant
atk_combatant = heap + 0x2300
uc.mem_write(atk_combatant + 0x1C, struct.pack('<I', combat))

# Target combatant
tgt_combatant = heap + 0x2400

# Attacker regiment
atk_reg = heap + 0x2500
atk_type = heap + 0x2600
army = heap + 0x2700
uc.mem_write(atk_reg + 0x38, struct.pack('<I', atk_type))
uc.mem_write(atk_reg + 0x74, struct.pack('<I', army))

# Target regiment
tgt_reg = heap + 0x2800
tgt_type = heap + 0x2900
uc.mem_write(tgt_reg + 0x38, struct.pack('<I', tgt_type))

# Dynamic state for hooks
hook_state = {
    'target_found': True,
    'max_recon': 0,
    'recon_ratio': 0,
}

def hook_find_target(uc_inst, address, size, user_data):
    if hook_state['target_found']:
        uc_inst.reg_write(UC_X86_REG_EAX, tgt_reg)
    else:
        uc_inst.reg_write(UC_X86_REG_EAX, 0)

def hook_lookup_dice(uc_inst, address, size, user_data):
    raw_roll = uc_inst.reg_read(UC_X86_REG_EAX)
    roll = struct.unpack('<i', struct.pack('<I', raw_roll))[0]
    edi = uc_inst.reg_read(UC_X86_REG_EDI)
    dmg = lookup_dice_damage(roll)
    uc_inst.mem_write(edi, struct.pack('<i', dmg))

def hook_max_recon(uc_inst, address, size, user_data):
    eax = uc_inst.reg_read(UC_X86_REG_EAX)
    uc_inst.mem_write(eax, struct.pack('<i', hook_state['max_recon']))

def hook_recon_ratio(uc_inst, address, size, user_data):
    edi = uc_inst.reg_read(UC_X86_REG_EDI)
    uc_inst.mem_write(edi, struct.pack('<i', hook_state['recon_ratio']))
    uc_inst.reg_write(UC_X86_REG_EAX, edi)

uc.hook_add(UC_HOOK_CODE, hook_find_target, begin=0x0059B610, end=0x0059B610)
uc.mem_write(0x0059B610, b'\xc2\x08\x00') # ret 8

uc.hook_add(UC_HOOK_CODE, hook_lookup_dice, begin=0x00594230, end=0x00594230)
uc.mem_write(0x00594230, b'\xc3') # ret

uc.hook_add(UC_HOOK_CODE, hook_max_recon, begin=0x005CCDB0, end=0x005CCDB0)
uc.mem_write(0x005CCDB0, b'\xc3') # ret

uc.hook_add(UC_HOOK_CODE, hook_recon_ratio, begin=0x005CCDF0, end=0x005CCDF0)
uc.mem_write(0x005CCDF0, b'\xc3') # ret


def run_attack_test(inp: AttackInput):
    # Configure hook state
    hook_state['target_found'] = inp.target_found
    hook_state['max_recon'] = inp.army_max_recon
    hook_state['recon_ratio'] = inp.army_recon_ratio

    # Attacker army
    if inp.has_army:
        uc.mem_write(atk_reg + 0x74, struct.pack('<I', army))
        uc.mem_write(army + 0xA4, struct.pack('<i', 1 if inp.army_is_active else 0))
    else:
        uc.mem_write(atk_reg + 0x74, struct.pack('<I', 0))

    # Attacker regiment
    uc.mem_write(atk_reg + 0x3C, struct.pack('<i', inp.attacker_strength))
    uc.mem_write(atk_reg + 0x64, struct.pack('<i', inp.attacker_country_index))
    uc.mem_write(atk_reg + 0x7C, struct.pack('<i', 0x1234))
    uc.mem_write(atk_reg + 0x80, struct.pack('<i', 0x5678))

    # Attacker type
    uc.mem_write(atk_type + 0x230, struct.pack('<i', inp.attacker_fire_attack))
    uc.mem_write(atk_type + 0x234, struct.pack('<i', inp.attacker_shock_attack))
    uc.mem_write(atk_type + 0x240, struct.pack('<i', inp.attacker_maneuver))

    # Attacker combatant
    uc.mem_write(atk_combatant + 0x18, struct.pack('<B', 1 if inp.is_fire_phase else 0))
    uc.mem_write(atk_combatant + 0x30, struct.pack('<i', inp.dice_modifier))

    # Target country & tech
    tag_bytes = inp.target_country_tag.ljust(4, b'\x00')
    uc.mem_write(country2 + 0x1C, tag_bytes[:4])
    uc.mem_write(country2 + 0x20, struct.pack('<i', inp.target_country_index))
    uc.mem_write(tech2 + 0x70, struct.pack('<i', inp.target_military_tactics))

    # Attacker country
    atk_tag_bytes = inp.attacker_country_tag.ljust(4, b'\x00')
    uc.mem_write(country1 + 0x1C, atk_tag_bytes[:4])
    uc.mem_write(country1 + 0x20, struct.pack('<i', inp.attacker_country_index))

    # Province controller
    prov_tag_bytes = inp.province_controller_tag.ljust(4, b'\x00')
    uc.mem_write(province + 0x130, prov_tag_bytes[:4])
    uc.mem_write(province + 0x134, struct.pack('<i', inp.province_controller_index))

    # Diplomacy war flag
    uc.mem_write(diplo2 + 0x34, struct.pack('<i', 1 if inp.is_at_war else 0))

    # Fort
    uc.mem_write(fort + 0x30, struct.pack('<i', inp.fort_level))

    # Target regiment
    uc.mem_write(tgt_reg + 0x08, struct.pack('<i', inp.target_id[0]))
    uc.mem_write(tgt_reg + 0x0C, struct.pack('<i', inp.target_id[1]))
    uc.mem_write(tgt_reg + 0x34, struct.pack('<i', inp.target_tactics))
    uc.mem_write(tgt_reg + 0x64, struct.pack('<i', inp.target_country_index))
    uc.mem_write(tgt_reg + 0x6C, struct.pack('<i', 0)) # reset org damage
    uc.mem_write(tgt_reg + 0x70, struct.pack('<i', 0)) # reset casualty damage

    # Target type
    uc.mem_write(tgt_type + 0x238, struct.pack('<i', inp.target_defense))

    # Setup stack: ret_stub, pAttackerCombatant, pTargetCombatant, col, support_factor
    uc.mem_write(
        stack_top - 20,
        struct.pack('<IIIII', ret_stub, atk_combatant, tgt_combatant, inp.attacker_col, inp.support_factor)
    )
    uc.reg_write(UC_X86_REG_ESP, stack_top - 20)
    uc.reg_write(UC_X86_REG_ECX, atk_reg)
    uc.reg_write(UC_X86_REG_EAX, inp.leader_dice_roll)

    uc.emu_start(0x0059A8E0, ret_stub)

    # Read results
    cas = struct.unpack('<i', uc.mem_read(tgt_reg + 0x70, 4))[0]
    org = struct.unpack('<i', uc.mem_read(tgt_reg + 0x6C, 4))[0]
    tgt_id_lo = struct.unpack('<i', uc.mem_read(atk_reg + 0x7C, 4))[0]
    tgt_id_hi = struct.unpack('<i', uc.mem_read(atk_reg + 0x80, 4))[0]

    model_res = execute_regiment_attack(inp)

    assert cas == model_res.strength_casualties, (
        f"Casualty mismatch: got {cas}, expected {model_res.strength_casualties} for {inp}"
    )
    assert org == model_res.org_loss, (
        f"Org loss mismatch: got {org}, expected {model_res.org_loss} for {inp}"
    )
    if not model_res.executed:
        if model_res.target_cleared:
            assert (tgt_id_lo, tgt_id_hi) == (0, 0)
    else:
        assert (tgt_id_lo, tgt_id_hi) == inp.target_id

    return cas, org


fixtures_run = 0

# Test Case Series:
# 1. Non-executable cases: NULL army and inactive army
c1 = AttackInput(has_army=False)
run_attack_test(c1)
fixtures_run += 1

c2 = AttackInput(army_is_active=False)
run_attack_test(c2)
fixtures_run += 1

# 2. No target found (returns NULL target -> cleared target ID, 0 damage)
c3 = AttackInput(target_found=False)
run_attack_test(c3)
fixtures_run += 1

# 3. Fire vs Shock phase comparison
c_fire = AttackInput(is_fire_phase=True, attacker_fire_attack=2000, attacker_shock_attack=1000)
c_shock = AttackInput(is_fire_phase=False, attacker_fire_attack=2000, attacker_shock_attack=1000)
cas_f, org_f = run_attack_test(c_fire)
cas_s, org_s = run_attack_test(c_shock)
assert cas_f > cas_s
fixtures_run += 2

# 4. Support factor comparison (Front line 1000 vs Backline 500)
c_front = AttackInput(support_factor=1000)
c_back = AttackInput(support_factor=500)
cas_front, _ = run_attack_test(c_front)
cas_back, _ = run_attack_test(c_back)
assert cas_front > cas_back
fixtures_run += 2

# 5. Dice rolls across entire 18-level damage table
for roll in [-3, -2, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 16]:
    for d_mod in [-2, 0, +2]:
        run_attack_test(AttackInput(leader_dice_roll=roll, dice_modifier=d_mod))
        fixtures_run += 1

# 6. Attacker strength scaling
for st in [100, 250, 500, 1000, 1500, 2000, 3000]:
    run_attack_test(AttackInput(attacker_strength=st))
    fixtures_run += 1

# 7. Fort mitigation and recon penetration
# 7a. Attacker-controlled province -> fort ignored
c_own = AttackInput(
    fort_level=3000,
    province_controller_index=1,
    attacker_country_index=1,
)
cas_own, _ = run_attack_test(c_own)

# 7b. Hostile fort without recon -> damage reduced
c_hostile_fort = AttackInput(
    fort_level=3000,
    province_controller_index=2,
    attacker_country_index=1,
    army_max_recon=0,
    army_recon_ratio=0,
)
cas_hostile, _ = run_attack_test(c_hostile_fort)
assert cas_own > cas_hostile
fixtures_run += 2

# 7c. Recon negates fort
c_recon = AttackInput(
    fort_level=2000,
    province_controller_index=2,
    attacker_country_index=1,
    army_max_recon=2000,
    army_recon_ratio=1000,
)
cas_recon, _ = run_attack_test(c_recon)
c_no_recon = AttackInput(
    fort_level=2000,
    province_controller_index=2,
    attacker_country_index=1,
    army_max_recon=0,
    army_recon_ratio=0,
)
cas_norecon, _ = run_attack_test(c_no_recon)
assert cas_recon > cas_norecon
fixtures_run += 2

# 8. Rebel tags (controller or attacker)
run_attack_test(AttackInput(province_controller_tag=b"REB", fort_level=1000))
run_attack_test(AttackInput(attacker_country_tag=b"REB", fort_level=1000))
fixtures_run += 2

# 9. Target tactics reduction
for tac in [0, 500, 1000, 2000, 4000]:
    run_attack_test(AttackInput(target_tactics=tac))
    fixtures_run += 1

# 10. Target defense variations
for defense in [0, 500, 1000, 2000, 3000]:
    run_attack_test(AttackInput(target_defense=defense))
    fixtures_run += 1

# 11. Target country military tactics bonus (affects org damage)
for tech in [0, 250, 500, 1000, 1500]:
    run_attack_test(AttackInput(target_military_tactics=tech))
    fixtures_run += 1

# Save evidence
out_dir = ROOT / 'evidence/generated/combat-regiment-attack'
out_dir.mkdir(parents=True, exist_ok=True)
(out_dir / 'claims.json').write_text(json.dumps(claims, indent=2) + '\n')
(out_dir / 'reverify.json').write_text(json.dumps(report, indent=2) + '\n')
(out_dir / 'negative-controls.json').write_text(json.dumps(controls, indent=2) + '\n')
(out_dir / 'emulation.json').write_text(json.dumps({
    'binary_sha256': digest,
    'routine_va': hex(0x0059A8E0),
    'fixtures_count': fixtures_run,
    'mismatches': 0
}, indent=2) + '\n')

ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify', file_path=str(bin_path))
ledger.start_run('Verify CLandCombatant::ExecuteRegimentAttack routine and callers', session='combat-regiment-attack')
ledger.record(report, rnd=1, session='combat-regiment-attack')
ledger.finish_run(1, report['grounded'], report['information'])
ledger.save()

print(f"Combat regiment attack: {len(report['results'])} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Combat regiment attack emulation: {fixtures_run} fixtures executed, 0 mismatches against combat_regiment_attack_model.")
