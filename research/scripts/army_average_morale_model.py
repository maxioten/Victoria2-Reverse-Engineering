#!/usr/bin/env python3
"""Reference Python implementation of CUnit::CalculateAverageMorale.

Binary address: 0x005C8DC0..0x005C8F08 in base-game/v2game.exe.
"""

def alldiv(dividend: int, divisor: int) -> int:
    """Signed 64-bit integer division with truncation towards zero (MSVC _alldiv)."""
    if divisor == 0:
        raise ZeroDivisionError("_alldiv by zero")
    sign = -1 if (dividend < 0) ^ (divisor < 0) else 1
    return sign * (abs(dividend) // abs(divisor))

def army_average_morale(
    regiment_morales: list[int],
    count: int,
    branch: str,  # 'army', 'navy', 'none'
    doctrine_bonus: int | None,
    leader_bonus: int | None
) -> int:
    """Calculate collective average morale for a unit (army or navy)."""
    # 1. Initial conversion value (floor(0.0005 * 1000.0) = 0)
    val = 0

    # 2. Accumulate base morale of all subunits in the linked list
    if regiment_morales:
        val = sum(regiment_morales)

    # 3. Normalize by subunit count
    if count != 0:
        dividend = val * 1000
        divisor = count * 1000
        val = alldiv(dividend, divisor)

    # 4. Service branch doctrine bonus (Navy: +0x68, Army: +0x70)
    if branch in ('navy', 'army') and doctrine_bonus is not None:
        factor = doctrine_bonus + 1000
        val = alldiv(val * factor, 1000)

    # 5. Assigned leader modifier bonus (+0x20)
    if leader_bonus is not None:
        factor = leader_bonus + 1000
        val = alldiv(val * factor, 1000)

    # 6. Result is stored in 32-bit signed buffer
    return (val & 0xFFFFFFFF) if val >= 0 else -((-val) & 0xFFFFFFFF)
