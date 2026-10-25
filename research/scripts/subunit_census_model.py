#!/usr/bin/env python3
"""Analytical model for military subunit census and classification routines.

Routines:
  CCombatant::CountRegimentsByFilterObject (0x005DC050..0x005DC093)
  CCombatant::CountRegimentsByDirectId (0x005DC0A0..0x005DC0DF)
"""
from dataclasses import dataclass

@dataclass
class SubUnitTypeInfo:
    category: int   # offset +0x24 in CUnitType
    type_id: int    # offset +0x34 in CUnitType

def count_regiments_by_category(armies: list[list[SubUnitTypeInfo]], target_category: int) -> int:
    """Counts regiments whose category matches target_category (0x005DC050)."""
    count = 0
    for army in armies:
        for reg in army:
            if reg.category == target_category:
                count += 1
    return count

def count_regiments_by_type_id(armies: list[list[SubUnitTypeInfo]], target_type_id: int) -> int:
    """Counts regiments whose type_id matches target_type_id (0x005DC0A0)."""
    count = 0
    for army in armies:
        for reg in army:
            if reg.type_id == target_type_id:
                count += 1
    return count
