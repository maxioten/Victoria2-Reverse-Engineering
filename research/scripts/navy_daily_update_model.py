"""Modelo analítico de referencia para el ciclo diario de mantenimiento naval
y la aplicación de daño por atrición en buques (Suite 85).

Implementa la semántica exacta observada en el binario PE32 `v2game.exe`:
- CNavy::DailyUpdate (0x005C7AE0..0x005C7B79)
- CSubUnit::SetStrength (0x005C02F0..0x005C036A)
"""

from typing import List, Tuple
from navy_attrition_resupply_model import calculate_sea_attrition


def subunit_set_strength(max_strength: int, new_strength: int) -> int:
    """Implementación analítica de CSubUnit::SetStrength (0x005C02F0).

    Aplica acotación dura al intervalo [0, max_strength]:
    clamped = min(max_strength, new_strength)
    if clamped < 0: clamped = 0
    """
    clamped = new_strength
    if clamped > max_strength:
        clamped = max_strength
    if clamped < 0:
        clamped = 0
    return clamped


def navy_daily_update(
    supply_efficiency: int,
    time_at_sea: int,
    range_divisor: int,
    grace_period_ms: int,
    max_naval_attrition: int,
    min_ship_strength: int,
    ships: List[Tuple[int, int]],
    attrition_enabled: bool = True
) -> Tuple[int, List[int], int]:
    """Ejecuta el ciclo diario de mantenimiento y atrición de una flota naval.

    Args:
        supply_efficiency: Eficiencia de aprovisionamiento / distancia ([navy + 0xB0]).
        time_at_sea: Días en alta mar acumulados ([navy + 0x1BC]).
        range_divisor: Umbral y divisor de alcance naval ([defines + 0xE4]).
        grace_period_ms: Periodo de gracia en milésimas ([defines + 0xF0]).
        max_naval_attrition: Atrición máxima diaria ([defines + 0xEC]).
        min_ship_strength: Piso de fuerza de supervivencia ([defines + 0xE8]).
        ships: Lista de tuplas (fuerza_actual, fuerza_maxima) para cada buque.
        attrition_enabled: Estado del conmutador global ([0x12588E8] + 0xD1C).

    Returns:
        Tupla (nuevo_time_at_sea, lista_fuerzas_actualizadas, atricion_aplicada).
    """
    initial_strengths = [s[0] for s in ships]

    # Si la simulación de atrición naval está desactivada globalmente:
    if not attrition_enabled:
        return time_at_sea, initial_strengths, 0

    # Actualizar contador de días sin suministro
    if supply_efficiency >= range_divisor:
        new_time_at_sea = 0
    else:
        new_time_at_sea = time_at_sea + 1

    # Calcular atrición por travesía marítima (invoca CalculateSeaAttrition)
    attrition = calculate_sea_attrition(
        time_at_sea=new_time_at_sea,
        grace_period_ms=grace_period_ms,
        naval_range_divisor=range_divisor,
        supply_distance=supply_efficiency,
        max_naval_attrition=max_naval_attrition
    )

    if attrition <= 0:
        return new_time_at_sea, initial_strengths, 0

    # Aplicar daño por atrición a cada buque
    updated_strengths = []
    for curr_str, max_str in ships:
        if curr_str <= min_ship_strength:
            # Si el buque ya está en o por debajo del umbral mínimo, no recibe daño
            updated_strengths.append(curr_str)
        else:
            damaged = curr_str - attrition
            if damaged < min_ship_strength:
                damaged = min_ship_strength
            final_str = subunit_set_strength(max_str, damaged)
            updated_strengths.append(final_str)

    return new_time_at_sea, updated_strengths, attrition
