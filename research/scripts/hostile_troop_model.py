"""
Analytical model for CProvince::CalculateHostileTroopDivisions and CProvince::CountHostileRegiments
Reverse-engineered from base-game/v2game.exe:
- 0x005DC7C0..0x005DC8AD (CProvince::CalculateHostileTroopDivisions)
- 0x005DC8B0..0x005DC938 (CProvince::CountHostileRegiments)
"""
from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class Regiment:
    strength: int

@dataclass
class Army:
    is_navy: bool
    country_id: int
    country_tag: bytes # 3 bytes
    is_at_war: bool    # with target country
    subunit_count: int
    regiments: List[Regiment] = field(default_factory=list)

def calculate_hostile_troop_divisions(
    armies: Optional[List[Army]],
    target_country_id: int,
    target_country_tag: bytes
) -> int:
    """
    Simulates CProvince::CalculateHostileTroopDivisions (0x005DC7C0).
    Filters out navies (is_navy == True).
    Filters out same country (country_id == target_country_id).
    Hostile if:
      is_at_war == True
      OR target_country_tag == b'REB'
      OR country_tag == b'REB'
    If hostile:
      sums regiment.strength across all regiments in army.
    At end: divides total by 1000 using floor division (0x10624DD3).
    """
    if not armies:
        return 0
    total_strength = 0
    for a in armies:
        if a.is_navy:
            continue
        if a.country_id == target_country_id:
            continue
        is_hostile = (
            a.is_at_war
            or target_country_tag[:3] == b'REB'
            or a.country_tag[:3] == b'REB'
        )
        if not is_hostile:
            continue
        army_str = 0
        for r in a.regiments:
            army_str = (army_str + r.strength) & 0xFFFFFFFF
        total_strength = (total_strength + army_str) & 0xFFFFFFFF
    
    if total_strength >= 0x80000000:
        total_strength -= 0x100000000
    
    divisions = total_strength // 1000
    if divisions >= 0x80000000:
        divisions -= 0x100000000
    return divisions

def count_hostile_regiments(
    armies: Optional[List[Army]],
    target_country_id: int,
    target_country_tag: bytes
) -> int:
    """
    Simulates CProvince::CountHostileRegiments (0x005DC8B0).
    Filters out navies and same country.
    Hostile if at war or either tag is 'REB'.
    Sums army.subunit_count.
    """
    if not armies:
        return 0
    total_count = 0
    for a in armies:
        if a.is_navy:
            continue
        if a.country_id == target_country_id:
            continue
        is_hostile = (
            a.is_at_war
            or target_country_tag[:3] == b'REB'
            or a.country_tag[:3] == b'REB'
        )
        if not is_hostile:
            continue
        total_count = (total_count + a.subunit_count) & 0xFFFFFFFF
    
    if total_count >= 0x80000000:
        total_count -= 0x100000000
    return total_count
