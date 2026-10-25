"""Modelo analítico de referencia para la evaluación de cohesión y ratios promedio
de fuerza y moral en formaciones militares (Suite 84).

Implementa la semántica exacta observada en el binario PE32 `v2game.exe`:
- CUnit::CalculateAverageSubunitStrengthRatio (0x005CFE90..0x005CFF85)
- CUnit::CalculateAverageSubunitMoraleRatio (0x005CFF90..0x005D0099)
"""

from typing import List, Tuple, Optional


def _c_idiv(dividend: int, divisor: int) -> int:
    """División entera signed según convención C/C++ (truncamiento hacia cero)."""
    if divisor == 0:
        raise ZeroDivisionError("C integer division by zero")
    sign = -1 if (dividend < 0) ^ (divisor < 0) else 1
    return sign * (abs(dividend) // abs(divisor))


def _compute_subunit_ratio(val: int, max_val: int) -> int:
    """Calcula el ratio de un atributo en milésimas respetando la ramificación 32/64 bits."""
    if max_val == 0:
        return -1

    # Rango de seguridad de 32 bits en el binario:
    # lea ecx, [val + 0x189373]; cmp ecx, 0x39580d
    # 0x189373 = 1610611, 0x39580d = 3758093
    # Si uint32(val + 1610611) <= 3758093: ejecuta imul/idiv de 32 bits
    # En cualquier otro caso: ejecuta __allmul / __alldiv de 64 bits.
    # En ambos caminos aritméticos el resultado formal coincide con (val * 1000) / max_val.
    scaled = val * 1000
    return _c_idiv(scaled, max_val)


def calculate_average_subunit_strength_ratio(
    subunits: List[Tuple[int, int]],
    count: int
) -> int:
    """Calcula el ratio promedio de fuerza de las subunidades de una formación.

    Args:
        subunits: Lista de tuplas (fuerza_actual, fuerza_maxima) para cada subunidad.
        count: Número de subunidades de la formación (campo [unit + 0x40]).

    Returns:
        Ratio promedio de fuerza en milésimas (int32).
    """
    sum_ratio = 0
    for current_strength, max_strength in subunits:
        ratio = _compute_subunit_ratio(current_strength, max_strength)
        sum_ratio += ratio

    if count <= 0:
        return sum_ratio if subunits else 0

    return _c_idiv(sum_ratio * 1000, count * 1000)


def calculate_average_subunit_morale_ratio(
    subunits: List[Tuple[int, int, bool]],
    count: int
) -> int:
    """Calcula el ratio promedio de moral de las subunidades de una formación.

    Args:
        subunits: Lista de tuplas (moral_actual, moral_maxima, es_pop_rebelde).
                  Si es_pop_rebelde es True ([pop + 0x164] != 0), la moral efectiva es 0.
        count: Número de subunidades de la formación (campo [unit + 0x40]).

    Returns:
        Ratio promedio de moral en milésimas (int32).
    """
    sum_ratio = 0
    for current_morale, max_morale, is_rebel_pop in subunits:
        effective_morale = 0 if is_rebel_pop else current_morale
        ratio = _compute_subunit_ratio(effective_morale, max_morale)
        sum_ratio += ratio

    if count <= 0:
        return sum_ratio if subunits else 0

    return _c_idiv(sum_ratio * 1000, count * 1000)
