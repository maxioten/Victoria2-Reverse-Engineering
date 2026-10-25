"""
Modelo formal en Python del cálculo de factores de suministro y reseteo de mantenimiento militar
en CCountry::DailyUpdateMilitarySupply (VA 0x005203E3..0x00520478).
"""


def scale30_by_defines_divisor(val: int) -> int:
    """Normaliza un valor entero a punto fijo de 15 bits mediante división entera por 32,768,000."""
    shifted = val << 30
    divisor = 32768000
    sign = -1 if (shifted < 0) ^ (divisor < 0) else 1
    return sign * (abs(shifted) // abs(divisor))


def calculate_military_supply_factors(
    party_bonus: int,
    global_base: int,
    tech_bonus: int,
    secondary_supply: int,
) -> tuple[int, int]:
    """Calcula el factor de suministro militar primario y secundario."""
    total_bonus = party_bonus + global_base + tech_bonus
    f1 = scale30_by_defines_divisor(total_bonus)
    f2 = scale30_by_defines_divisor(secondary_supply)
    return f1, f2
