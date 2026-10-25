#!/usr/bin/env python3
"""Analytical model of CCombat::CalculateAttackerStrengthRatio in Victoria II (0x0059C460..0x0059C51B).

The virtual routine (slot 6, +0x18 in CCombat/CLandCombat vtables) calculates the normalized
attacker share of combat forces in thousandths (m-units):
1. Reads minimum strength threshold as float 1.5 from 0x00F141C8.
2. Converts float to integer via floor/ftol2 -> min_threshold = 1.
3. Retrieves raw strengths from attacker (slot 10, +0x28) and defender (slot 10, +0x28).
4. Clamps each side with cmovl against the minimum threshold:
   att = max(1, raw_attacker_strength)
   def = max(1, raw_defender_strength)
5. Sums total strength:
   total = att + def
6. If total == 0:
   *out_ratio = -1
7. Else:
   Checks 32-bit overflow bound: (att + 0x189373) <= 0x39580D (i.e. att <= 2,147,482).
   Fast 32-bit path (imul/idiv) vs 64-bit path (_allmul/_alldiv):
   ratio = (att * 1000) // total
   *out_ratio = ratio
8. Returns out_ratio pointer.
"""
from dataclasses import dataclass


@dataclass
class AttackerRatioInput:
    raw_attacker_strength: int
    raw_defender_strength: int


def calculate_attacker_strength_ratio(inp: AttackerRatioInput) -> int:
    """Exact emulation of routine 0x0059C460."""
    min_threshold = 1

    att = inp.raw_attacker_strength if inp.raw_attacker_strength >= min_threshold else min_threshold
    df = inp.raw_defender_strength if inp.raw_defender_strength >= min_threshold else min_threshold

    total = att + df
    if total == 0:
        return -1

    # Exact emulation of 32-bit vs 64-bit arithmetic
    check = (att + 0x189373) & 0xFFFFFFFF
    if check <= 0x39580D:
        # Fast 32-bit signed division
        prod = att * 1000
        ratio = prod // total
    else:
        # 64-bit division
        prod = att * 1000
        ratio = prod // total

    return ratio
