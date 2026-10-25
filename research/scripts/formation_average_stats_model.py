"""Modelo analítico de referencia para la evaluación de moral media y fuerza media
de formaciones militares (Suite 89).

Implementa la semántica exacta observada en el binario PE32 `v2game.exe`:
- CUnit::CalculateAverageMorale (0x005CFA90..0x005CFB03, slot 17 en CArmy y CNavy)
- CUnit::CalculateAverageStrength (0x005CFB10..0x005CFB73, slot 18 en CArmy y CNavy)
"""

from typing import List, Dict, Any


def _c_idiv(dividend: int, divisor: int) -> int:
    """División entera signed según convención C/C++ (truncamiento hacia cero)."""
    if divisor == 0:
        raise ZeroDivisionError("C integer division by zero")
    sign = -1 if (dividend < 0) ^ (divisor < 0) else 1
    return sign * (abs(dividend) // abs(divisor))


def calculate_average_morale(
    subunits: List[Dict[str, Any]],
    subunit_count: int
) -> int:
    """Calcula la moral media de la formación considerando el filtro rebelde (0x005CFA90).

    Args:
        subunits: Lista de diccionarios con 'morale' (int32) y opcionalmente 'is_rebel' (bool).
        subunit_count: Conteo registrado en la formación ([unit + 0x40]).

    Returns:
        Moral media en milésimas (int32).
    """
    total_morale = 0
    for sub in subunits:
        is_rebel = sub.get('is_rebel', False)
        eff_morale = 0 if is_rebel else sub.get('morale', 0)
        total_morale += eff_morale

    if subunit_count == 0:
        return total_morale

    dividend = total_morale * 1000
    divisor = subunit_count * 1000
    return _c_idiv(dividend, divisor)


def calculate_average_strength(
    subunits_strength: List[int],
    subunit_count: int
) -> int:
    """Calcula la fuerza viva media por subunidad en la formación (0x005CFB10).

    Args:
        subunits_strength: Lista de valores de fuerza viva ([subunit + 0x3C]).
        subunit_count: Conteo registrado en la formación ([unit + 0x40]).

    Returns:
        Fuerza media en milésimas (int32).
    """
    total_strength = sum(subunits_strength) if subunits_strength else 0
    if subunit_count == 0:
        return total_strength

    dividend = total_strength * 1000
    divisor = subunit_count * 1000
    return _c_idiv(dividend, divisor)
