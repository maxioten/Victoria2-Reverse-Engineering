"""Modelo analítico de referencia para la evaluación de potencia de combate completa
con moral, experiencia y tecnología de subunidades y formaciones militares (Suite 87).

Implementa la semántica exacta observada en el binario PE32 `v2game.exe`:
- CUnit::CalculateFullCombatPower (0x005D02F0..0x005D04FB)
- Integración con CUnitType::CalculateCombatRating (0x005BDC80)
- Slot 26 en CArmy (0x00DF8934) y CNavy (0x00E03034)
"""

from typing import List, Dict, Any


def _c_idiv(dividend: int, divisor: int) -> int:
    """División entera signed según convención C/C++ (truncamiento hacia cero)."""
    if divisor == 0:
        raise ZeroDivisionError("C integer division by zero")
    sign = -1 if (dividend < 0) ^ (divisor < 0) else 1
    return sign * (abs(dividend) // abs(divisor))


def calculate_subunit_full_power(
    rating: int,
    current_strength: int,
    max_strength: int,
    current_morale: int,
    max_morale: int,
    experience: int,
    is_rebel: bool = False,
    exp_factor: int = 10,
    min_strength: int = 100
) -> int:
    """Calcula la potencia de combate táctica completa de una subunidad individual.

    Args:
        rating: Calificación táctica intrínseca del tipo de unidad (0x005BDC80).
        current_strength: Fuerza actual en milésimas ([subunit + 0x3C]).
        max_strength: Fuerza máxima en milésimas (slot 12 vtable).
        current_morale: Moral actual en milésimas ([subunit + 0x40]).
        max_morale: Moral máxima en milésimas (slot 13 vtable).
        experience: Experiencia de la subunidad ([subunit + 0x34]).
        is_rebel: True si proviene de un POP rebelde ([pop + 0x164] != 0).
        exp_factor: Factor multiplicador de experiencia global ([0x0125FED8], default 10).
        min_strength: Umbral de fuerza mínima (floor(100.5f) = 100).

    Returns:
        Potencia de combate calculada (int32).
    """
    # 1. Health ratio
    if max_strength == 0:
        health_ratio = -1
    else:
        health_ratio = _c_idiv(current_strength * 1000, max_strength)

    # 2. Health power
    health_power = _c_idiv(health_ratio * rating, 1000)

    # 3. Morale ratio (con filtro rebelde)
    eff_morale = 0 if is_rebel else current_morale
    if max_morale == 0:
        morale_ratio = -1
    else:
        morale_ratio = _c_idiv(eff_morale * 1000, max_morale)

    # 4. Experience multiplier
    exp_bonus = _c_idiv(experience * exp_factor, 1000)
    exp_mult = 1000 + exp_bonus

    # 5. Combined power
    morale_power = _c_idiv(morale_ratio * health_power, 1000)
    power = _c_idiv(morale_power * exp_mult, 1000)

    # 6. Demoralization / broken unit penalty (50% reduction)
    # cmp dword ptr [esi + 0x3c], edx (current_strength < min_strength)
    # cmp dword ptr [esi + 0x40], 0x3e8 (current_morale < 1000)
    if current_strength < min_strength or current_morale < 1000:
        power = _c_idiv(power * 1000, 2000)

    return power


def calculate_formation_full_combat_power(
    selected_subunits: List[Dict[str, Any]],
    country_tech_bonus: int = 0,
    base_tech_define: int = 1000,
    exp_factor: int = 10,
    min_strength: int = 100
) -> int:
    """Calcula la potencia de combate total de subunidades seleccionadas en formación (0x005D02F0).

    Args:
        selected_subunits: Lista de subunidades seleccionadas.
        country_tech_bonus: Bono de combate del país propietario ([military_stats + 0x70]).
        base_tech_define: Factor base de combate de MilitaryDefines ([defines + 0xE0]).
        exp_factor: Factor multiplicador de experiencia global ([0x0125FED8]).
        min_strength: Umbral de fuerza mínima.

    Returns:
        Potencia de combate efectiva escalada por tecnología nacional (int32).
    """
    total_power = 0
    for sub in selected_subunits:
        p = calculate_subunit_full_power(
            rating=sub['rating'],
            current_strength=sub['current_strength'],
            max_strength=sub['max_strength'],
            current_morale=sub.get('current_morale', 0),
            max_morale=sub.get('max_morale', 1000),
            experience=sub.get('experience', 0),
            is_rebel=sub.get('is_rebel', False),
            exp_factor=exp_factor,
            min_strength=min_strength
        )
        total_power += p

    # Country tech scaling:
    # total_power = _alldiv(total_power * (base_tech_define + country_tech_bonus), 1000)
    tech_factor = base_tech_define + country_tech_bonus
    total_power = _c_idiv(total_power * tech_factor, 1000)
    return total_power
