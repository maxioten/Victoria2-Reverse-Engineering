#!/usr/bin/env python3
"""Reference Python model of CArmy::CalculateSupplyLimit.

Binary address: 0x005D63E0..0x005D6574 in base-game/v2game.exe.
"""
import ctypes

def alldiv(dividend: int, divisor: int) -> int:
    """Signed 64-bit integer division with truncation towards zero (MSVC _alldiv)."""
    if divisor == 0:
        raise ZeroDivisionError("_alldiv by zero")
    sign = -1 if (dividend < 0) ^ (divisor < 0) else 1
    return sign * (abs(dividend) // abs(divisor))

def normalize_mil(val: int) -> int:
    """Fixed-point normalization via 0x10624DD3 magic multiplier in x86."""
    val32 = ctypes.c_int32(val).value
    prod64 = val32 * 0x10624DD3
    edx32 = ctypes.c_int32(prod64 >> 32).value
    shifted = edx32 >> 6
    sign_bit = (shifted >> 31) & 1
    return (shifted + sign_bit) * 1000

def army_supply_limit(
    is_retreating_or_moving: bool,
    province_controller_id: int,
    army_country_id: int,
    is_sieged: bool,
    is_in_combat: bool,
    friendly_base: int,
    hostile_base: int,
    leader_has_trait: bool,
    leader_supply_bonus: int,
    tech_supply_bonus: int,
    terrain_mod: int,
    infra_bonus: int,
    base_buffer: int,
    province_cap_raw: int,
    is_stationed: bool,
    defines_supply_bonus: int
) -> int:
    """Calculate provincial army supply limit matching x86 routine exactly."""
    # 1. Early exit if retreating or fast moving
    if is_retreating_or_moving:
        return 0

    # 2. Friendly vs hostile base supply
    is_friendly = (
        province_controller_id == army_country_id and
        not is_sieged and
        not is_in_combat
    )
    base_supply = friendly_base if is_friendly else hostile_base

    # 3. Leader trait bonus
    if leader_has_trait:
        base_supply += leader_supply_bonus

    # 4. Tech multiplier
    tech_factor = tech_supply_bonus + 1000
    scaled = alldiv(base_supply * tech_factor, 1000)

    # 5. Terrain penalty & infrastructure
    terrain_penalty = normalize_mil(terrain_mod)
    infra_scaled = infra_bonus * 1000

    # Accumulate raw supply: scaled tech + infrastructure - terrain penalty
    accum = scaled - terrain_penalty + infra_scaled

    # 6. Province cap clamping
    province_cap = normalize_mil(province_cap_raw)
    if accum > province_cap:
        accum = province_cap

    # 7. Non-negative floor
    if accum < 0:
        accum = 0

    # 8. Stationed bonus from defines
    if is_stationed:
        accum += defines_supply_bonus

    return ctypes.c_int32(accum).value
