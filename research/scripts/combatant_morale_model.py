"""
Analytical model for CCombatant::CalculateAverageMorale and CCombatant::CalculateAverageMaxMorale
Reverse-engineered from base-game/v2game.exe:
- 0x005DC630..0x005DC6FD (CCombatant::CalculateAverageMorale)
- 0x005DC710..0x005DC7B2 (CCombatant::CalculateAverageMaxMorale)
"""
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class ArmyMoraleInfo:
    count: int          # [army + 0x40]
    morale: int         # returned by CalculateAverageMorale (slot 37)
    max_morale: int     # returned by CalculateMaxMorale (slot 17)

def calculate_combatant_average_morale(armies: Optional[List[ArmyMoraleInfo]]) -> int:
    """
    Simulates CCombatant::CalculateAverageMorale (0x005DC630).
    Initializes *out_val = 0 via floor(0.0005 * 1000.0) = 0.
    For each army:
      weighted = (count * 1000 * morale) // 1000 = count * morale
      *out_val += weighted
      total_count += count
    If total_count > 0:
      *out_val = (*out_val * 1000) // (total_count * 1000)
    """
    if not armies:
        return 0
    total_val = 0
    total_count = 0
    for a in armies:
        prod = (a.count * 1000) * a.morale
        weighted = prod // 1000
        total_val = (total_val + weighted) & 0xFFFFFFFF
        total_count = (total_count + a.count) & 0xFFFFFFFF
    
    if total_val >= 0x80000000:
        total_val -= 0x100000000
    if total_count >= 0x80000000:
        total_count -= 0x100000000
        
    if total_count > 0:
        num = total_val * 1000
        den = total_count * 1000
        total_val = num // den
        if total_val >= 0x80000000:
            total_val -= 0x100000000
    return total_val

def calculate_combatant_average_max_morale(armies: Optional[List[ArmyMoraleInfo]]) -> int:
    """
    Simulates CCombatant::CalculateAverageMaxMorale (0x005DC710).
    Initializes *out_val = 0.
    For each army:
      weighted = (count * 1000 * max_morale) // 1000 = count * max_morale
      *out_val += weighted
      total_count += count
    If total_count > 0:
      *out_val = (*out_val * 1000) // (total_count * 1000)
    """
    if not armies:
        return 0
    total_val = 0
    total_count = 0
    for a in armies:
        prod = (a.count * 1000) * a.max_morale
        weighted = prod // 1000
        total_val = (total_val + weighted) & 0xFFFFFFFF
        total_count = (total_count + a.count) & 0xFFFFFFFF
    
    if total_val >= 0x80000000:
        total_val -= 0x100000000
    if total_count >= 0x80000000:
        total_count -= 0x100000000

    if total_count > 0:
        num = total_val * 1000
        den = total_count * 1000
        total_val = num // den
        if total_val >= 0x80000000:
            total_val -= 0x100000000
    return total_val
