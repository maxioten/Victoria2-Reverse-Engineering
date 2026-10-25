"""
Analytical model for CLandCombatant::ExecuteRegimentAttack (0x0059A8E0..0x0059ACAF).

Victoria II 3.04 (v2game.exe):
Core regiment daily attack execution inside land combat.
Integrates:
- Target regiment acquisition via CLandCombatant::FindTargetRegiment (0x0059B610)
- Combat phase attack stat selection (Fire vs Shock: 0x230 vs 0x234)
- Dice roll damage lookup via CCombat::LookupDiceDamage (0x00594230)
- Attack modifier scaling (BASE_CASUALTY_MODIFIER = 100 at 0x0125F5C8)
- Support factor scaling (1000 front vs backline support stat at 0x23C)
- Attacker regiment current strength scaling (0x3C)
- Fort damage reduction via province controller, REB tag, and army recon/engineer
- Target regiment tactics reduction (BASE_TACTICS_DAMAGE_MODIFIER = 10 at 0x0125F594)
- Target regiment defense reduction (0x238)
- Target nation military tactics tech bonus reduction (0x70)
- Final casualty and morale loss scaling (BASE_MORALE_DAMAGE_MODIFIER = 200 at 0x0125F578)
- Daily accumulation into target regiment (casualties: +0x70, morale loss: +0x6C)
"""

from dataclasses import dataclass
from typing import Optional, Tuple


def _alldiv(a: int, b: int) -> int:
    """Emulate MSVC 64-bit signed integer division (_alldiv)."""
    if b == 0:
        raise ZeroDivisionError("_alldiv with b=0")
    # C99 / MSVC truncates toward zero
    neg = (a < 0) ^ (b < 0)
    res = abs(a) // abs(b)
    return -res if neg else res


def _allmul(a: int, b: int) -> int:
    """Emulate MSVC 64-bit signed integer multiplication (_allmul)."""
    res = a * b
    # 64-bit wrap-around
    res &= 0xFFFFFFFFFFFFFFFF
    if res & 0x8000000000000000:
        res -= (1 << 64)
    return res


@dataclass
class AttackInput:
    # Attacker regiment
    has_army: bool = True
    army_is_active: bool = True
    attacker_strength: int = 1000  # milésimas, e.g. 1000 = 1000 men
    attacker_maneuver: int = 1000  # milésimas (at 0x240)
    attacker_fire_attack: int = 1000  # milésimas (at 0x230)
    attacker_shock_attack: int = 1000  # milésimas (at 0x234)
    attacker_country_tag: bytes = b"FRA"
    attacker_country_index: int = 1
    
    # Combat context
    is_fire_phase: bool = True  # True if Fire phase (!= 0), False if Shock phase (== 0)
    leader_dice_roll: int = 4   # Dice roll (passed in EAX)
    dice_modifier: int = 0      # Attacker combatant modifier at +0x30
    support_factor: int = 1000  # 1000 for front line, or support stat for backline
    attacker_col: int = 15      # Attacker column (0..29)
    
    # Target acquisition result
    target_found: bool = True
    target_id: Tuple[int, int] = (101, 202)
    target_tactics: int = 1000  # target regiment tactics at +0x34 (milésimas)
    target_defense: int = 1000  # target unit type defense at +0x238 (milésimas)
    target_country_tag: bytes = b"PRU"
    target_country_index: int = 2
    target_military_tactics: int = 0  # target country military tactics tech at +0x70 (milésimas)
    
    # Province & fort context
    province_controller_tag: bytes = b"PRU"
    province_controller_index: int = 2
    is_at_war: bool = True
    fort_level: int = 0         # milésimas (at +0x30 of fort), e.g. 1000 for level 1
    army_max_recon: int = 0     # milésimas (from FindMaxRecon)
    army_recon_ratio: int = 0   # milésimas (from CalculateReconRatio, 0..1000)
    recon_siege_effect: int = 1000 # defines constant at 0x12586DC + 0x20 + 0xC8
    military_tactics_base: int = 1000 # defines constant at 0x12586DC + 0x20 + 0xE0
    
    # Defines constants
    base_casualty_modifier: int = 100  # at 0x0125F5C8
    base_tactics_damage_modifier: int = 10 # at 0x0125F594
    base_morale_damage_modifier: int = 200 # at 0x0125F578


@dataclass
class AttackResult:
    executed: bool
    target_cleared: bool
    target_id: Tuple[int, int]
    strength_casualties: int
    org_loss: int


DICE_DAMAGE_TABLE = [
    20, 40, 60, 80, 100, 120, 160, 200, 250, 300, 350, 400, 450, 500, 600, 700, 800, 900
]


def lookup_dice_damage(roll: int) -> int:
    idx = roll + 2
    if idx < 0:
        idx = 0
    elif idx > 17:
        idx = 17
    return DICE_DAMAGE_TABLE[idx]


def execute_regiment_attack(inp: AttackInput) -> AttackResult:
    # 1. Check army validity (0x0059A8ED..0x0059A8FF)
    if not inp.has_army or not inp.army_is_active:
        return AttackResult(
            executed=False,
            target_cleared=False,
            target_id=(0, 0),
            strength_casualties=0,
            org_loss=0,
        )

    # 2. Target Acquisition (0x0059A905..0x0059A930)
    if not inp.target_found:
        return AttackResult(
            executed=False,
            target_cleared=True,
            target_id=(0, 0),
            strength_casualties=0,
            org_loss=0,
        )

    # 3. Unit attack stat selection: Fire vs Shock (0x0059A936..0x0059A953)
    if inp.is_fire_phase:
        attack_stat = inp.attacker_fire_attack
    else:
        attack_stat = inp.attacker_shock_attack

    # 4. Lookup dice damage (0x0059A956..0x0059A973)
    # roll conversion: (leader_dice_roll * 1000) // 1000 with truncation toward zero
    val = inp.leader_dice_roll * 1000
    roll = abs(val) // 1000 if val >= 0 else -(abs(val) // 1000)
    effective_roll = roll + inp.dice_modifier
    dice_damage = lookup_dice_damage(effective_roll)

    # 5. Base damage scaling (0x0059A978..0x0059A9CD)
    # attack_multiplier = 1000 + (base_casualty_modifier * attack_stat) // 1000
    prod1 = inp.base_casualty_modifier * attack_stat
    attack_mult = _alldiv(prod1, 1000) + 1000

    # supp_damage = (dice_damage * support_factor) // 1000
    supp_damage = _alldiv(dice_damage * inp.support_factor, 1000)

    # stat_damage = (supp_damage * attack_mult) // 1000
    stat_damage = _alldiv(supp_damage * attack_mult, 1000)

    # raw_damage = (stat_damage * attacker_strength) // 1000
    damage = _alldiv(stat_damage * inp.attacker_strength, 1000)

    # 6. Fort & Recon reduction (0x0059A9DB..0x0059AB37)
    # Skip fort if province controlled by attacker country
    apply_fort = False
    if inp.province_controller_index != inp.attacker_country_index:
        is_reb = (
            inp.province_controller_tag.startswith(b"REB")
            or inp.attacker_country_tag.startswith(b"REB")
        )
        if inp.is_at_war or is_reb:
            apply_fort = True

    if apply_fort:
        fort_level_int = (inp.fort_level * 0x10624DD3) >> 38
        # Army recon ratio scaling
        if inp.army_recon_ratio < inp.recon_siege_effect:
            scaled_ratio = (
                _alldiv((1000000 // inp.recon_siege_effect) * inp.army_recon_ratio, 1000)
                if inp.recon_siege_effect != 0
                else 0
            )
            effective_recon = _alldiv(scaled_ratio * inp.army_max_recon, 1000)
        else:
            effective_recon = inp.army_max_recon

        # Recon reduction from fort using division by 1000
        recon_int = (effective_recon * 0x10624DD3) >> 38
        effective_fort = fort_level_int - recon_int
        if effective_fort < 0:
            effective_fort = 0

        fort_divisor = 1000 + _alldiv(effective_fort * 1000 * inp.base_casualty_modifier, 1000)
        if fort_divisor > 1000:
            prod_fort = _allmul(damage, 1000)
            damage = _alldiv(prod_fort, fort_divisor)

    # 7. Target tactics reduction (0x0059AB49..0x0059AB83)
    tactics_delta = _alldiv(inp.target_tactics * inp.base_tactics_damage_modifier, 1000)
    tactics_factor = 1000 + tactics_delta
    prod_tactics = _allmul(damage, 1000)
    damage = _alldiv(prod_tactics, tactics_factor)

    # 8. Target defense scaling for strength casualties (0x0059AB88..0x0059ABE9)
    # damage * 10
    prod_ten = _allmul(damage, 10000)
    damage_ten = _alldiv(prod_ten, 1000)
    if inp.target_defense > 0:
        prod_def = _allmul(damage_ten, 1000)
        strength_casualties = _alldiv(prod_def, inp.target_defense)
    else:
        strength_casualties = damage_ten

    # 9. Military tactics bonus org scaling (0x0059AC01..0x0059AC40)
    if inp.target_military_tactics > 0:
        org_tactics_div = inp.military_tactics_base + inp.target_military_tactics
        prod_org = _allmul(damage, 1000)
        org_damage = _alldiv(prod_org, org_tactics_div)
    else:
        org_damage = damage

    # 10. Final casualties and morale loss scaling (0x0059AC42..0x0059AC90)
    final_strength_casualties = _alldiv(
        _allmul(strength_casualties, inp.base_morale_damage_modifier), 1000
    )
    final_org_loss = _alldiv(
        _allmul(org_damage, inp.base_morale_damage_modifier), 1000
    )

    return AttackResult(
        executed=True,
        target_cleared=False,
        target_id=inp.target_id,
        strength_casualties=final_strength_casualties,
        org_loss=final_org_loss,
    )
