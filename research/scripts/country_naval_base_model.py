"""
Modelo formal en Python del cálculo de puntuación y eficiencia de base naval
en CCountry::CalculateNavalBaseScore (VA 0x0052FF12..0x0052FFB9).
"""


def trunc_div100(val: int) -> int:
    """División entera por 100 con redondeo hacia cero (MSVC imul 0x51eb851f)."""
    sign = -1 if val < 0 else 1
    return sign * (abs(val) // 100)


def calculate_naval_base_contribution(
    val_14: int,
    val_28: int,
    base_weight: int,
    init_score: int,
) -> int:
    """Calcula la contribución de eficiencia costera y acumula en la puntuación naval nacional."""
    c_14 = trunc_div100(val_14)
    c_28 = trunc_div100(val_28)

    num = c_14 << 30
    den = c_28 << 15
    sign = -1 if (num < 0) ^ (den < 0) else 1
    ratio = sign * (abs(num) // abs(den))

    # Clamping canónico [1638 (5%), 32768 (100%)]
    if ratio < 1638:
        ratio = 1638
    if ratio > 32768:
        ratio = 32768

    contrib = (ratio * base_weight) >> 15
    return init_score + contrib
