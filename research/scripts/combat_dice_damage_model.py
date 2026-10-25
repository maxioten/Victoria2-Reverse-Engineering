#!/usr/bin/env python3
"""Ground-truth model for CCombat::LookupDiceDamage (0x00594230..0x005944A9)."""

DICE_DAMAGE_TABLE = [
    20,   # index 0 (roll <= -2)
    40,   # index 1 (roll = -1)
    60,   # index 2 (roll = 0)
    80,   # index 3 (roll = 1)
    100,  # index 4 (roll = 2)
    120,  # index 5 (roll = 3)
    160,  # index 6 (roll = 4)
    200,  # index 7 (roll = 5)
    250,  # index 8 (roll = 6)
    300,  # index 9 (roll = 7)
    350,  # index 10 (roll = 8)
    400,  # index 11 (roll = 9)
    450,  # index 12 (roll = 10)
    500,  # index 13 (roll = 11)
    600,  # index 14 (roll = 12)
    700,  # index 15 (roll = 13)
    800,  # index 16 (roll = 14)
    900,  # index 17 (roll >= 15)
]

def combat_dice_damage(roll: int) -> int:
    """Calculate the base combat damage multiplier from modified dice roll.
    
    Args:
        roll: Effective combat dice roll (base d10 roll + leader bonus - terrain penalty).
    Returns:
        Integer damage factor from the engine table (20..900).
    """
    raw_index = roll + 2
    if raw_index < 0:
        index = 0
    elif raw_index >= 18:
        index = 17
    else:
        index = raw_index

    return DICE_DAMAGE_TABLE[index]
