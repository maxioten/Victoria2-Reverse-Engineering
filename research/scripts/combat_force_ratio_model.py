#!/usr/bin/env python3
"""Reference Python model of CCombat::CalculateForceRatio.

Binary address: 0x0059C460..0x0059C51E in base-game/v2game.exe.
"""
import ctypes

def alldiv(dividend: int, divisor: int) -> int:
    """Signed 64-bit integer division with truncation towards zero (MSVC _alldiv)."""
    if divisor == 0:
        raise ZeroDivisionError("_alldiv by zero")
    sign = -1 if (dividend < 0) ^ (divisor < 0) else 1
    return sign * (abs(dividend) // abs(divisor))

def combat_force_ratio(attacker_strength: int, defender_strength: int) -> int:
    """Calculate relative combat force ratio in thousandths ([0, 1000])."""
    # 1. Floor minimum of 1 from float 1.5 constant
    a = max(1, attacker_strength)
    d = max(1, defender_strength)

    # 2. Total force
    total = a + d
    if total == 0:
        return -1

    # 3. Branching check: (a + 0x189373) & 0xFFFFFFFF <= 0x39580D
    check = (a + 0x189373) & 0xFFFFFFFF
    if check <= 0x39580D:
        # Fast path 32-bit idiv
        ratio = int((a * 1000) / total)
    else:
        # Safe path 64-bit _allmul / _alldiv
        ratio = alldiv(a * 1000, total)

    return ctypes.c_int32(ratio).value
