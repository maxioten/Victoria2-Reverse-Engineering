#!/usr/bin/env python3
"""Ground-truth model for CCombat::CalculateFrontage (0x0059C520..0x0059C624)."""

def combat_frontage(
    attacker_tech_mods: list[int],
    defender_tech_mods: list[int],
    terrain_mod: int,
    base_frontage: int = 30000
) -> int:
    """Calculate front line frontage slots according to Victoria II rules.
    
    Args:
        attacker_tech_mods: Tech frontage deltas for attacker participants (fixed point 1000).
        defender_tech_mods: Tech frontage deltas for defender participants (fixed point 1000).
        terrain_mod: Provincial terrain modifier delta (fixed point 1000, e.g. -500 for -50%).
        base_frontage: Base frontage defined globally (default 30000).
    Returns:
        Integer number of regiment columns on the battle line.
    """
    min_frontage = 30000
    for tech in attacker_tech_mods:
        cand = base_frontage + tech
        if cand < 2000:
            cand = 2000
        if cand < min_frontage:
            min_frontage = cand

    for tech in defender_tech_mods:
        cand = base_frontage + tech
        if cand < 2000:
            cand = 2000
        if cand < min_frontage:
            min_frontage = cand

    mult = 1000 + terrain_mod
    scaled = min_frontage * mult
    if scaled < 0:
        divided = -((-scaled) // 1000)
    else:
        divided = scaled // 1000

    if divided < 2000:
        divided = 2000

    # Native fast division by 1000 using compiler magic constant 0x10624DD3
    magic = 0x10624DD3
    prod = (divided * magic) & 0xFFFFFFFFFFFFFFFF
    edx = prod >> 32
    if edx >= 0x80000000:
        sar6 = (edx - 0x100000000) >> 6
    else:
        sar6 = edx >> 6
    slots = sar6 + (1 if sar6 < 0 else 0)

    return slots
