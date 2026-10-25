#!/usr/bin/env python3
"""Analytical model of CNavy::CalculateSupplyLimit (0x005D81A0).

Routine:
  CNavy::CalculateSupplyLimit (slot 30 in CNavy vtable at 0x00E03044).
"""

def navy_supply_limit(
    country_id: int,
    naval_base_registered: bool,
    is_water: bool,
    docking_denied: bool,
    has_naval_base: bool,
    is_hostile_or_blockaded: bool,
    naval_base_level: int,
    leader_has_trait: bool,
    leader_bonus: int,
    tech_naval_supply: int
) -> int:
    """Calculates fleet supply limit in thousandths according to Victoria II rules."""
    # 1. Base infrastructure check in CGameState
    if not naval_base_registered:
        return 0

    # 2. Water / open sea check: fleets have no provincial supply limit at sea
    if is_water:
        return 0

    # 3. Port / docking access check (0x004B7DB0 returning non-zero means denied)
    if docking_denied:
        return 0

    # 4. Naval base hostility / blockade check (0x00539260)
    if has_naval_base:
        if is_hostile_or_blockaded:
            return 0

    # 5. Base supply from naval base level: 2000 per level + 1000
    base_supply = (naval_base_level * 2000) + 1000

    # 6. Admiral trait bonus
    if leader_has_trait:
        base_supply += leader_bonus

    # 7. Clamping to non-negative
    if base_supply < 0:
        base_supply = 0

    # 8. Tech scaling in milésimas (using 64-bit integer product and division)
    scaled = (base_supply * (tech_naval_supply + 1000)) // 1000
    return scaled
