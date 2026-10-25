#!/usr/bin/env python3
"""
Python reference model for CRegiment::CalculateMaxMorale (0x005BFFA0..0x005C010C).
Simulates regiment and subunit maximum organization and morale calculations,
including ruling party doctrine, leader personality traits, the rebel ("REB") exception,
and the [25%, 100%] military spending slider scaling.
"""

def compute_regiment_max_morale(
    base_morale: int,
    is_army: bool,
    doctrine_bonus: int,
    leader_bonus: int | None,
    is_rebel: bool,
    spending_slider: int
) -> int:
    """
    Simulates CRegiment::CalculateMaxMorale.
    
    Args:
        base_morale: Base morale from CSubUnitType (+0xB4), scaled by 1000.
        is_army: True if army regiment, False if naval unit.
        doctrine_bonus: Ruling party doctrine bonus (naval +0x68, army +0x70).
        leader_bonus: Assigned leader trait bonus (+0x20) or None if no leader.
        is_rebel: True if tag matches "REB", skipping the spending slider adjustment.
        spending_slider: Military spending slider value (30-bit fixed point, 32,768,000 for 100%).
        
    Returns:
        Final integer maximum morale value persisted in *out_morale.
    """
    # 0x005BFFC0: mov [esi], ecx (base_morale)
    val = base_morale

    # Doctrine adjustment (0x005C0000..0x005C0018)
    val = (val * (doctrine_bonus + 1000)) // 1000

    # Leader trait adjustment (0x005C001A..0x005C0045)
    if leader_bonus is not None:
        val = (val * (leader_bonus + 1000)) // 1000

    # Rebel check (0x005C0075..0x005C0088)
    # If tag is "REB", jump to 0x005C0104 (skip spending slider)
    if is_rebel:
        return val

    # Spending slider adjustment (0x005C008A..0x005C0102)
    # 1. Scaled slider: (spending_slider * 32,768,000) >> 30
    scaled = (spending_slider * 0x01F40000) >> 30

    # 2. Variable component (750.5 truncated by floorf to 750)
    part1 = (scaled * 750) // 1000

    # 3. Base floor component (250.5 truncated by floorf to 250)
    spending_mult = part1 + 250

    # 4. Final morale scaling
    final_val = (val * spending_mult) // 1000
    return final_val
