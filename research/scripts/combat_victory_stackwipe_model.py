"""
Analytical model for CCombat::EvaluateVictoryAndStackwipe (0x0059C630..0x0059C8A7).

Victoria II 3.04 (v2game.exe):
Combat vtable slot 11 (0x2C) in CCombat, CLandCombat, CNavalCombat.
Evaluates battle termination, decisive victory, ratio overrun, and stackwipes:
1. Aggregates total strength for both combatants.
2. If defender morale collapses (HasOperationalUnits == false):
   checks 2:1 ratio (attacker_strength // 2 > defender_strength) or pocket encirclement
   (retreat_province_id == -1); if met, stackwipes defender (defender_strength = 0).
3. If attacker morale collapses:
   checks 2:1 ratio (defender_strength // 2 > attacker_strength) or pocket encirclement;
   if met, stackwipes attacker (attacker_strength = 0).
4. Sets victory eligibility:
   - attacker_eligible = (attacker_strength > 0 and defender_strength == 0)
   - defender_eligible = (defender_strength > 0 and attacker_strength == 0)
5. Checks ratio overrun gate against ratio_threshold (e.g. 10:1):
   - For attacker: (attacker_strength * 1000) // (threshold * 1000) > defender_strength.
     If eligible and retreat check passes, concludes battle with Attacker victory (winner=0).
   - For defender: (defender_strength * 1000) // (threshold * 1000) > attacker_strength.
     If eligible and retreat check passes, concludes battle with Defender victory (winner=1).
"""

from dataclasses import dataclass
from typing import Optional


def _alldiv(a: int, b: int) -> int:
    """Emulate MSVC 64-bit signed integer division (_alldiv)."""
    if b == 0:
        raise ZeroDivisionError("_alldiv with b=0")
    neg = (a < 0) ^ (b < 0)
    res = abs(a) // abs(b)
    return -res if neg else res


def _allmul(a: int, b: int) -> int:
    """Emulate MSVC 64-bit signed integer multiplication (_allmul)."""
    res = a * b
    res &= 0xFFFFFFFFFFFFFFFF
    if res & 0x8000000000000000:
        res -= (1 << 64)
    return res


@dataclass
class VictoryInput:
    attacker_raw_strength: int = 10000
    defender_raw_strength: int = 10000
    defender_has_morale: bool = True
    attacker_has_morale: bool = True
    retreat_province_id: int = 100      # [ebx + 0x1C], -1 if pocket/encircled
    ratio_threshold: int = 10           # [ebp + 8], e.g. 10
    check_can_retreat: bool = False      # [ebp + 0x0C]
    defender_can_retreat: bool = True   # virtual call 0x54 on defender
    attacker_can_retreat: bool = True   # virtual call 0x54 on attacker
    is_debug_pause: bool = False        # [0x012588E8 + 0xD11]


@dataclass
class VictoryResult:
    battle_ended: bool
    winner: Optional[str] = None        # "attacker", "defender", or None
    winner_code: int = -1               # 0 for attacker, 1 for defender, -1 none
    attacker_final_strength: int = 0
    defender_final_strength: int = 0
    defender_stackwiped: bool = False
    attacker_stackwiped: bool = False


def evaluate_victory_and_stackwipe(inp: VictoryInput) -> VictoryResult:
    # 0. Check debug pause flag (0x0059C63E..0x0059C64A)
    if inp.is_debug_pause:
        return VictoryResult(
            battle_ended=False,
            attacker_final_strength=inp.attacker_raw_strength,
            defender_final_strength=inp.defender_raw_strength,
        )

    attacker_str = inp.attacker_raw_strength
    defender_str = inp.defender_raw_strength
    defender_stackwiped = False
    attacker_stackwiped = False

    # 1. Defender morale collapse check (0x0059C672..0x0059C6E4)
    if not inp.defender_has_morale:
        # Compute attacker_str // 2
        # Using division by 2000 (0x7D0) in 15-bit fixed / magic division
        if inp.attacker_raw_strength + 0x189373 <= 0x39580D:
            ecx = inp.attacker_raw_strength * 1000
            att_half = (ecx * 0x10624DD3) >> 39
        else:
            att_half = _alldiv(_allmul(inp.attacker_raw_strength, 1000), 2000)

        # If attacker >= 2x defender or defender trapped in pocket (-1)
        if att_half > defender_str or inp.retreat_province_id == -1:
            defender_str = 0
            defender_stackwiped = True

    # 2. Attacker morale collapse check (0x0059C6F0..0x0059C758)
    if not inp.attacker_has_morale:
        # Compute defender_str // 2
        if defender_str + 0x189373 <= 0x39580D:
            ecx = defender_str * 1000
            def_half = (ecx * 0x10624DD3) >> 39
        else:
            def_half = _alldiv(_allmul(defender_str, 1000), 2000)

        if def_half > attacker_str or inp.retreat_province_id == -1:
            attacker_str = 0
            attacker_stackwiped = True

    # 3. Determine victory eligibility (0x0059C75C..0x0059C776)
    attacker_eligible = False
    defender_eligible = False

    if attacker_str != 0:
        if defender_str == 0:
            attacker_eligible = True
    else:
        if defender_str != 0:
            defender_eligible = True

    # 4. Check Attacker decisive victory / ratio overrun (0x0059C77B..0x0059C809)
    can_eval_attacker = True
    if inp.check_can_retreat:
        if not inp.defender_can_retreat:
            can_eval_attacker = False

    if can_eval_attacker:
        ratio_scale = inp.ratio_threshold * 1000
        if ratio_scale == 0:
            quota = -1
        else:
            if attacker_str + 0x189373 <= 0x39580D:
                quota = (attacker_str * 1000) // ratio_scale
            else:
                quota = _alldiv(_allmul(attacker_str, 1000), ratio_scale)

        # In assembly: cmp eax, [esp + 0x10]; jle ...; cmp [esp + 0xe], 1; jne ...
        # [esp + 0x10] is the defender strength before stackwipe!
        # Specifically, [esp + 0x10] was stored at line 0x0059C664, and if stackwiped was cleared to 0 at 0x0059C6E4!
        # So it compares quota against defender_str!
        if quota > defender_str and attacker_eligible:
            return VictoryResult(
                battle_ended=True,
                winner="attacker",
                winner_code=0,
                attacker_final_strength=attacker_str,
                defender_final_strength=defender_str,
                defender_stackwiped=defender_stackwiped,
                attacker_stackwiped=attacker_stackwiped,
            )

    # 5. Check Defender decisive victory / ratio overrun (0x0059C80C..0x0059C89C)
    can_eval_defender = True
    if inp.check_can_retreat:
        if not inp.attacker_can_retreat:
            can_eval_defender = False

    if can_eval_defender:
        ratio_scale = inp.ratio_threshold * 1000
        if ratio_scale == 0:
            quota = -1
        else:
            if defender_str + 0x189373 <= 0x39580D:
                quota = (defender_str * 1000) // ratio_scale
            else:
                quota = _alldiv(_allmul(defender_str, 1000), ratio_scale)

        if quota > attacker_str and defender_eligible:
            return VictoryResult(
                battle_ended=True,
                winner="defender",
                winner_code=1,
                attacker_final_strength=attacker_str,
                defender_final_strength=defender_str,
                defender_stackwiped=defender_stackwiped,
                attacker_stackwiped=attacker_stackwiped,
            )

    return VictoryResult(
        battle_ended=False,
        winner=None,
        winner_code=-1,
        attacker_final_strength=attacker_str,
        defender_final_strength=defender_str,
        defender_stackwiped=defender_stackwiped,
        attacker_stackwiped=attacker_stackwiped,
    )
