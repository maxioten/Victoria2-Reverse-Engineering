"""
Modelo formal en Python de la rutina CCountry::CalculateNationalInfrastructure
(VA 0x00530C70..0x00530E3B).

Calcula la agregación de unidades provinciales ponderadas por modificadores
tecnológicos normalizados a 30 bits y el bono nacional base en punto fijo de 15 bits.
"""

SCALE_32M = 32_768_000


def calculate_national_infrastructure(
    province_units: list[int],
    tech_entries: list[tuple[bool, int, int, int]],  # (active, v234, v230, v238)
    base_bonus: int,
) -> int:
    """Calcula el valor de 64 bits de infraestructura conforme a 0x00530C70."""
    # Etapa 1: suma de unidades de provincias
    total_prov_units = sum(province_units)

    # Etapa 2: normalización tecnológica
    sum_terms = 0
    valid_count = 0

    for active, v234, v230, v238 in tech_entries:
        if not active:
            continue
        raw1 = v234 + v230
        norm1 = (raw1 << 30) // SCALE_32M
        norm2 = (v238 << 30) // SCALE_32M
        term = (norm1 * norm2) >> 15
        sum_terms += term
        valid_count += 1

    # Etapa 3: promedio ponderado
    if valid_count > 0:
        # En la máquina x86: (sum_terms << 15) // (valid_count << 15)
        # que preserva la división entera con truncamiento
        avg_mod = (sum_terms << 15) // (valid_count << 15)
    else:
        avg_mod = 0

    # Etapa 4: producto ponderado con total_prov_units
    scaled_units = total_prov_units << 15
    prod = (scaled_units * avg_mod) >> 15

    # Suma de base_bonus << 15
    final_val = prod + (base_bonus << 15)
    return final_val
