"""
Analytical model for subunit counting and transport/supply weight computation
Reverse-engineered from base-game/v2game.exe:
- 0x005DC560..0x005DC58F (CCombatant::CountTotalRegiments)
- 0x005DC590..0x005DC5CB (CArmy::CalculateSupplyWeight)
- 0x005DC5D0..0x005DC621 (CCombatant::CalculateSupplyWeight)
"""
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class SubUnitWeightInfo:
    supply_consumption: int # [type + 0x258] in milésimas

@dataclass
class ArmyWeightInfo:
    subunits: List[SubUnitWeightInfo]

def count_total_regiments(armies: Optional[List[ArmyWeightInfo]]) -> int:
    """
    Simulates CCombatant::CountTotalRegiments (0x005DC560).
    Iterates armies, for each army counts subunits.
    Returns total count.
    """
    if not armies:
        return 0
    total = 0
    for a in armies:
        total = (total + len(a.subunits)) & 0xFFFFFFFF
    if total >= 0x80000000:
        total -= 0x100000000
    return total

def calculate_army_supply_weight(subunits: Optional[List[SubUnitWeightInfo]]) -> int:
    """
    Simulates CArmy::CalculateSupplyWeight (0x005DC590).
    For each subunit:
      weight = consumption // 1000
      total += weight
    """
    if not subunits:
        return 0
    total = 0
    for s in subunits:
        w = s.supply_consumption // 1000
        total = (total + w) & 0xFFFFFFFF
    if total >= 0x80000000:
        total -= 0x100000000
    return total

def calculate_combatant_supply_weight(armies: Optional[List[ArmyWeightInfo]]) -> int:
    """
    Simulates CCombatant::CalculateSupplyWeight (0x005DC5D0).
    For each army, for each subunit:
      weight = consumption // 1000
      army_total += weight
    combatant_total += army_total
    """
    if not armies:
        return 0
    total = 0
    for a in armies:
        army_w = 0
        for s in a.subunits:
            w = s.supply_consumption // 1000
            army_w = (army_w + w) & 0xFFFFFFFF
        total = (total + army_w) & 0xFFFFFFFF
    if total >= 0x80000000:
        total -= 0x100000000
    return total
