"""
Modelo formal en Python de la asignación y distribución de cuotas por estrato
en CProvincePromotionBuffer::AllocateTargetQuota (VA 0x004EE150..0x004EE2FB).
"""


def normalize_define_to_fixed15(define_val: int) -> int:
    """Normaliza define de milésimos a escala de punto fijo de 15 bits."""
    shifted = define_val << 30
    divisor = 32768000
    sign = -1 if (shifted < 0) ^ (divisor < 0) else 1
    return sign * (abs(shifted) // abs(divisor))


def calculate_target_quota_allocations(
    desired: int,
    current: int,
    rate_weight: int,
    target_capacities: list[int],
    define_promo: int = 1000,
    define_demote: int = 1000,
) -> list[int]:
    """Calcula el vector de cuotas asignadas secuencialmente a los objetivos candidatos."""
    delta = desired - current
    if delta == 0 or rate_weight == 0 or len(target_capacities) == 0:
        return [0] * len(target_capacities)

    prod = (delta << 15) * rate_weight

    if delta >= 0:
        raw_step = prod >> 30
        norm_def = normalize_define_to_fixed15(define_promo)
        scaled_step = ((current << 15) * norm_def) >> 30
        step_clamped = max(50, scaled_step)
        edi = max(raw_step, step_clamped)
        total_quota = min(delta, edi)
    else:
        raw_step = prod >> 30
        sign = -1 if raw_step < 0 else 1
        edi = sign * (abs(raw_step) // 4)
        norm_def = normalize_define_to_fixed15(define_demote)
        scaled_step = ((current << 15) * norm_def) >> 30
        step_clamped = -max(50, scaled_step)
        edi = min(raw_step, step_clamped)
        if edi < delta:
            edi = delta
        total_quota = abs(edi)

    remaining = total_quota
    allocations = []
    for cap in target_capacities:
        alloc = min(remaining, cap)
        allocations.append(alloc)
        remaining -= alloc
    return allocations
