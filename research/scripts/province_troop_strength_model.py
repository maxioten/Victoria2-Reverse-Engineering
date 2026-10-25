#!/usr/bin/env python3
"""Analytical model for provincial troop strength aggregation routines.

Routines:
  CProvince::CalculateFriendlyTroopStrength (0x005DC200..0x005DC297)
  CProvince::CalculateTotalTroopStrength (0x005DC2A0..0x005DC322)
"""
from dataclasses import dataclass
import math

@dataclass
class ArmyInput:
    is_active: bool
    country_id: int
    regiments: list[int]

def friendly_troop_strength(target_country_id: int, armies: list[ArmyInput]) -> int:
    """Computes total troop strength of active armies belonging to target_country_id."""
    init_val = int(math.floor(0.0005000000237487257 * 1000.0))
    total = init_val
    for army in armies:
        if not army.is_active:
            continue
        if army.country_id != target_country_id:
            continue
        army_strength = sum(army.regiments)
        total = (total + army_strength) & 0xFFFFFFFF
    if total >= 0x80000000:
        total -= 0x100000000
    return total

def total_troop_strength(armies: list[ArmyInput]) -> int:
    """Computes total troop strength of all active armies regardless of nationality."""
    init_val = int(math.floor(0.0005000000237487257 * 1000.0))
    total = init_val
    for army in armies:
        if not army.is_active:
            continue
        army_strength = sum(army.regiments)
        total = (total + army_strength) & 0xFFFFFFFF
    if total >= 0x80000000:
        total -= 0x100000000
    return total
