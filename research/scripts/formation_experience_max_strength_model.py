"""Modelo analítico de referencia para la evaluación de experiencia media y fuerza máxima
total de formaciones militares (Suite 88).

Implementa la semántica exacta observada en el binario PE32 `v2game.exe`:
- CUnit::CalculateAverageExperience (0x005CF8B0..0x005CF943, slot 19 en CArmy y CNavy)
- CUnit::CalculateTotalMaxStrength (0x005CF950..0x005CF9AF, slot 20 en CArmy y CNavy)
"""

from typing import List


def _c_idiv(dividend: int, divisor: int) -> int:
    """División entera signed según convención C/C++ (truncamiento hacia cero)."""
    if divisor == 0:
        raise ZeroDivisionError("C integer division by zero")
    sign = -1 if (dividend < 0) ^ (divisor < 0) else 1
    return sign * (abs(dividend) // abs(divisor))


def calculate_average_experience(
    subunits_exp: List[int],
    subunit_count: int
) -> int:
    """Calcula la experiencia media de las subunidades en una formación (0x005CF8B0).

    Args:
        subunits_exp: Lista de valores de experiencia militar en milésimas ([subunit + 0x34]).
        subunit_count: Conteo registrado en la formación ([unit + 0x40]).

    Returns:
        Experiencia media en milésimas (int32).
    """
    total_exp = sum(subunits_exp) if subunits_exp else 0
    if subunit_count == 0:
        return total_exp

    # Evaluado como _alldiv(_allmul(total_exp, 1000), count * 1000)
    dividend = total_exp * 1000
    divisor = subunit_count * 1000
    return _c_idiv(dividend, divisor)


def calculate_total_max_strength(
    subunits_max_str: List[int]
) -> int:
    """Calcula la suma nominal de fuerza máxima de todas las subunidades (0x005CF950).

    Args:
        subunits_max_str: Lista de valores de fuerza máxima por tipo ([type + 0xB0]).

    Returns:
        Fuerza máxima acumulada en milésimas (int32).
    """
    return sum(subunits_max_str) if subunits_max_str else 0
