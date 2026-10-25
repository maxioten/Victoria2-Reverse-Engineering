"""
Analytical model for CCombatant::CalculateEffectiveStrength and CCombatant::CalculateTotalCurrentStrength
Reverse-engineered from base-game/v2game.exe:
- 0x005DC0E0..0x005DC17C (CCombatant::CalculateEffectiveStrength)
- 0x005DC180..0x005DC1F3 (CCombatant::CalculateTotalCurrentStrength)
"""

from dataclasses import dataclass
from typing import List, Optional

@dataclass
class SubUnit:
    is_land: bool
    current_strength: int
    type_max_strength: int = 0

@dataclass
class Army:
    subunits: List[SubUnit]

def calculate_effective_strength(armies: Optional[List[Army]]) -> int:
    """
    Simulates CCombatant::CalculateEffectiveStrength (0x005DC0E0).
    Initializes to floor(0.0005 * 1000.0) = 0.
    For each army, for each subunit:
      if subunit.is_land (vtable slot 9 returns true):
        army_acc += subunit.current_strength
      else:
        army_acc += subunit.type_max_strength
    total += army_acc
    """
    if not armies:
        return 0
    total = 0
    for army in armies:
        army_acc = 0
        for sub in army.subunits:
            if sub.is_land:
                army_acc = (army_acc + sub.current_strength) & 0xFFFFFFFF
            else:
                army_acc = (army_acc + sub.type_max_strength) & 0xFFFFFFFF
        total = (total + army_acc) & 0xFFFFFFFF
    
    if total >= 0x80000000:
        total -= 0x100000000
    return total

def calculate_total_current_strength(armies: Optional[List[Army]]) -> int:
    """
    Simulates CCombatant::CalculateTotalCurrentStrength (0x005DC180).
    Initializes to floor(0.0005 * 1000.0) = 0.
    For each army, for each subunit:
      army_acc += subunit.current_strength
    total += army_acc
    """
    if not armies:
        return 0
    total = 0
    for army in armies:
        army_acc = 0
        for sub in army.subunits:
            army_acc = (army_acc + sub.current_strength) & 0xFFFFFFFF
        total = (total + army_acc) & 0xFFFFFFFF
    
    if total >= 0x80000000:
        total -= 0x100000000
    return total
