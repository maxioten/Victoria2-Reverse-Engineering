"""
Modelo formal en Python de la doble acotación del slider de gasto nacional
en CCountry::SetCategorySpendingSlider (VA 0x00538070..0x00538147).
"""


def normalize_policy_bound(raw_val: int) -> int:
    """Normaliza el límite de gasto de la política gubernamental a escala de punto fijo de 15 bits."""
    if raw_val >= 0x80000000:
        raw_val -= 0x100000000
    shifted = raw_val << 30
    divisor = 32768000
    sign = -1 if (shifted < 0) ^ (divisor < 0) else 1
    return sign * (abs(shifted) // abs(divisor))


def clamp_spending_slider(proposed: int, policy_min_raw: int, policy_max_raw: int) -> int:
    """Aplica la doble acotación [min_bound, max_bound] al slider de gasto propuesto."""
    min_bound = normalize_policy_bound(policy_min_raw)
    max_bound = normalize_policy_bound(policy_max_raw)

    val = min_bound if min_bound > proposed else proposed
    if val > max_bound:
        val = max_bound
    return val
