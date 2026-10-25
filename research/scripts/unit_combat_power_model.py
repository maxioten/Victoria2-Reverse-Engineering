"""Modelo analítico de referencia para la evaluación de potencia de combate efectiva
y calificación táctica de subunidades militares (Suite 86).

Implementa la semántica exacta observada en el binario PE32 `v2game.exe`:
- CUnitType::CalculateCombatRating (0x005BDC80..0x005BDD45)
- CUnit::CalculateEffectiveCombatPower (0x005D0500..0x005D05E2)
"""

from typing import List, Dict, Any


def _c_idiv(dividend: int, divisor: int) -> int:
    """División entera signed según convención C/C++ (truncamiento hacia cero)."""
    if divisor == 0:
        raise ZeroDivisionError("C integer division by zero")
    sign = -1 if (dividend < 0) ^ (divisor < 0) else 1
    return sign * (abs(dividend) // abs(divisor))


def calculate_combat_rating(
    is_land: bool,
    is_auxiliary: bool = False,
    recon: int = 0,
    attack: int = 0,
    defense: int = 0,
    support: int = 0,
    discipline: int = 0,
    maneuver: int = 0,
    siege: int = 0,
    gun_power: int = 0,
    hull: int = 0,
    evasion: int = 0,
    torpedo: int = 0,
    armor: int = 0
) -> int:
    """Calcula la calificación táctica de combate intrínseca de un tipo de unidad (0x005BDC80).

    Args:
        is_land: True si es terrestre ([type + 0x39] != 0).
        is_auxiliary: True si es buque auxiliar / no combativo ([type + 0x38] != 0).
        recon: Reconocimiento ([type + 0x228]).
        attack: Ataque ([type + 0x22C]).
        defense: Defensa ([type + 0x230]).
        support: Apoyo ([type + 0x234]).
        discipline: Disciplina ([type + 0x238]).
        maneuver: Maniobra ([type + 0x23C]).
        siege: Asedio ([type + 0x240]).
        gun_power: Artillería naval / cañones ([type + 0x244]).
        hull: Resistencia de casco ([type + 0x248]).
        evasion: Evasión naval ([type + 0x24C]).
        torpedo: Torpedos / alcance ([type + 0x250]).
        armor: Blindaje / coraza ([type + 0x25C]).

    Returns:
        Calificación táctica en milésimas (int32).
    """
    if is_land:
        stat_sum = recon + attack + defense + support + maneuver + siege
        return _c_idiv(stat_sum * discipline, 1000)

    if is_auxiliary:
        return 0

    # Buque de combate
    base_factor = gun_power + hull + armor
    tech_factor = 1000 + evasion + torpedo
    return _c_idiv(base_factor * tech_factor, 1000)


def calculate_effective_combat_power(
    subunits: List[Dict[str, Any]]
) -> int:
    """Calcula la potencia de combate efectiva acumulada de una formación militar (0x005D0500).

    Args:
        subunits: Lista de diccionarios con la especificación de cada subunidad:
            - 'current_strength': Fuerza viva actual (int32).
            - 'max_strength': Fuerza máxima (int32).
            - 'rating': Calificación de combate del tipo (int32).

    Returns:
        Potencia de combate efectiva total en milésimas (int32).
    """
    total_power = 0
    for sub in subunits:
        curr_str = sub['current_strength']
        max_str = sub['max_strength']
        rating = sub['rating']

        if max_str == 0:
            health_ratio = -1
        else:
            health_ratio = _c_idiv(curr_str * 1000, max_str)

        power = _c_idiv(health_ratio * rating, 1000)
        total_power += power

    return total_power
