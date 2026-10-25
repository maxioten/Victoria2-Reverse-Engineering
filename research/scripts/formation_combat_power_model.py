"""Modelo analítico de referencia para la evaluación de potencia de combate de formación directa y agregada (Suite 90).

Implementa la semántica exacta observada en el binario PE32 `v2game.exe`:
- CUnit::CalculateDirectFormationCombatPower (0x005D00E0..0x005D02E8, slot 23)
- CUnit::CalculateAggregateFormationCombatPower (0x005D00A0..0x005D00D5, slot 24)
- Integración con CUnitType::CalculateCombatRating (0x005BDC80)
- Vtables de CArmy (0x00DF8928 / 0x00DF892C) y CNavy (0x00E03028 / 0x00E0302C)
"""

from typing import List, Dict, Any


def _c_idiv(dividend: int, divisor: int) -> int:
    """División entera signed según convención C/C++ (truncamiento hacia cero)."""
    if divisor == 0:
        raise ZeroDivisionError("C integer division by zero")
    sign = -1 if (dividend < 0) ^ (divisor < 0) else 1
    return sign * (abs(dividend) // abs(divisor))


def calculate_subunit_direct_power(
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
    """Calcula la potencia de combate táctica completa de una subunidad individual en 0x005D00E0.

    Args:
        rating: Calificación táctica del tipo de unidad (0x005BDC80).
        current_strength: Fuerza actual en milésimas ([subunit + 0x3C]).
        max_strength: Fuerza máxima en milésimas (slot 12 vtable).
        current_morale: Moral actual en milésimas ([subunit + 0x40]).
        max_morale: Moral máxima en milésimas (slot 13 vtable).
        experience: Experiencia militar ([subunit + 0x34]).
        is_rebel: True si proviene de un POP rebelde ([pop + 0x164] != 0).
        exp_factor: Factor multiplicador de experiencia global ([0x0125FED8], default 10).
        min_strength: Umbral de fuerza mínima (floor(100.5f) = 100).

    Returns:
        Potencia de combate de la subunidad (int32).
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
    if current_strength < min_strength or current_morale < 1000:
        power = _c_idiv(power * 1000, 2000)

    return power


def calculate_direct_formation_combat_power(
    subunits: List[Dict[str, Any]],
    country_tech_bonus: int = 0,
    base_tech_define: int = 1000,
    exp_factor: int = 10,
    min_strength: int = 100
) -> int:
    """Calcula la potencia de combate directa de toda la formación (0x005D00E0, slot 23).

    Evalúa todas las subunidades de la formación ([ecx + 0x38]), sumando sus potencias
    individuales y aplicando el factor de escalado tecnológico nacional:
        total_tech_factor = base_tech_define + country_tech_bonus
        final_power = (total_power * total_tech_factor) // 1000

    Args:
        subunits: Lista de todas las subunidades directas de la formación ([ecx + 0x38]).
        country_tech_bonus: Bono de combate del país propietario ([military_stats + 0x70]).
        base_tech_define: Factor base de combate de MilitaryDefines ([defines + 0xE0]).
        exp_factor: Factor multiplicador de experiencia global ([0x0125FED8]).
        min_strength: Umbral de fuerza mínima (100).

    Returns:
        Potencia de combate directa escalada (int32).
    """
    total_power = 0
    for sub in subunits:
        p = calculate_subunit_direct_power(
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

    tech_factor = base_tech_define + country_tech_bonus
    final_power = _c_idiv(total_power * tech_factor, 1000)
    return final_power


def calculate_aggregate_formation_combat_power(
    child_formations: List[Dict[str, Any]],
    exp_factor: int = 10,
    min_strength: int = 100
) -> int:
    """Calcula la potencia agregada iterando formaciones subordinadas (0x005D00A0, slot 24).

    Recorre la lista enlazada de unidades secundarias/hijas ([ecx + 0x4C]) e invoca
    polimórficamente el slot 23 (CalculateDirectFormationCombatPower) de cada una:
        *out_total += child->CalculateDirectFormationCombatPower()

    Args:
        child_formations: Lista de formaciones secundarias, cada una con su lista de subunidades
                          y modificadores nacionales de su propio propietario.
        exp_factor: Factor multiplicador de experiencia global.
        min_strength: Umbral de fuerza mínima.

    Returns:
        Potencia acumulada total de todas las formaciones subordinadas (int32).
    """
    total_aggregate = 0
    for child in child_formations:
        child_power = calculate_direct_formation_combat_power(
            subunits=child.get('subunits', []),
            country_tech_bonus=child.get('country_tech_bonus', 0),
            base_tech_define=child.get('base_tech_define', 1000),
            exp_factor=exp_factor,
            min_strength=min_strength
        )
        total_aggregate += child_power
    return total_aggregate
