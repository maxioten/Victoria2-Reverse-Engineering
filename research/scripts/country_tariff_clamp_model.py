"""
Modelo formal en Python de la rutina CCountry::SetTariffRateAndClamp (VA 0x00538070..0x00538147).

Firma original en el ejecutable PE32:
void __thiscall CCountry::SetTariffRateAndClamp(CCountry* this, int64_t new_rate)
- ECX: CCountry* (esi)
- [ebp + 8]:  new_rate.lo (uint32)
- [ebp + 0xC]: new_rate.hi (int32) -> new_rate (int64_t)

Estructura de CCountry*:
- +0x1440: current_tariff_rate (int64_t)
- +0x0A60: economic_policy* (puntero a política económica de gobierno)
  - +0x0E8: min_tariff_limit (int32_t)
  - +0x0F0: max_tariff_limit (int32_t)

Lógica de cálculo:
1. Asignación preliminar:
   this->tariff_rate = new_rate

2. Límite inferior (Lower bound clamping):
   raw_min = economic_policy->min_tariff_limit
   min_scaled = (int64_t(raw_min) << 30) // 32768000  (usando división de 64 bits con signo __alldiv)
   Si min_scaled >= this->tariff_rate:
     this->tariff_rate = min_scaled

3. Límite superior (Upper bound clamping):
   raw_max = economic_policy->max_tariff_limit
   max_scaled = (int64_t(raw_max) << 30) // 32768000  (usando división de 64 bits con signo __alldiv)
   Si this->tariff_rate >= max_scaled:
     this->tariff_rate = max_scaled

Retorna la tasa final acotada (int64_t) guardada en this->tariff_rate (+0x1440).
"""

DIVISOR_64 = 32768000  # 0x01F40000


def alldiv_64(dividend: int, divisor: int) -> int:
    """Emula fielmente la llamada a __alldiv (0x00AC02A0) de MSVC CRT."""
    if divisor == 0:
        raise ZeroDivisionError("__alldiv division by zero")
    if (dividend < 0) ^ (divisor < 0):
        res = -(-dividend // divisor) if dividend < 0 else -(dividend // -divisor)
    else:
        res = abs(dividend) // abs(divisor)
    return (res + (1 << 63)) % (1 << 64) - (1 << 63)


def scale_tariff_limit(raw_limit_32: int) -> int:
    """Calcula el escalado a punto fijo del límite entero de la política comercial."""
    shifted = raw_limit_32 << 30
    shifted_64 = (shifted + (1 << 63)) % (1 << 64) - (1 << 63)
    return alldiv_64(shifted_64, DIVISOR_64)


def set_tariff_rate_and_clamp(new_rate: int, min_limit_raw: int, max_limit_raw: int) -> int:
    """
    Ejecuta el doble clamping de aranceles:
    1. min_bound = scale(min_limit_raw)
    2. clamped_1 = max(new_rate, min_bound)
    3. max_bound = scale(max_limit_raw)
    4. final = min(clamped_1, max_bound)
    """
    # 1. Asignación preliminar
    current_rate = (new_rate + (1 << 63)) % (1 << 64) - (1 << 63)

    # 2. Clamping por límite inferior
    min_scaled = scale_tariff_limit(min_limit_raw)
    if min_scaled >= current_rate:
        current_rate = min_scaled

    # 3. Clamping por límite superior
    max_scaled = scale_tariff_limit(max_limit_raw)
    if current_rate >= max_scaled:
        current_rate = max_scaled

    return current_rate
