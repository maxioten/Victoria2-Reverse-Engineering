"""
Modelo formal en Python de la rutina CCountry::CalculateTotalTaxRevenue (VA 0x0052B780..0x0052B859).

Firma original de la rutina en el ejecutable PE32:
int64_t* __stdcall CCountry::CalculateTotalTaxRevenue(CCountry* country)
(ESI es el puntero implícito struct-return int64_t* out_tax_total)

Estructura de entrada:
- CCountry* (ebx)
  - Offset +0xA0: std::vector<CTaxSetting*> tax_settings (punteros a poor [0], middle [1], rich [2])
    - CTaxSetting:
      - +0x60: rate_lo (uint32)
      - +0x64: rate_hi (int32) -> rate (int64_t)
      - +0x48 + edi*8 (edi=1 => +0x50): base_lo (uint32)
      - +0x4C + edi*8 (edi=1 => +0x54): base_hi (int32) -> tax_base (int64_t)
  - Offset +0x0E0 (ecx = (1 + 13) << 4 = 224 = 0x0E0): std::vector<int64_t> buckets
    - buckets.begin at [country + 0x0E0]
    - buckets.end   at [country + 0x0E4]
    - count = (end - begin) / 8

Lógica de cálculo:
out_tax_total = 0 (int64_t)
Para i en 0 .. count-1:
  Si i == 0, 1, 2:
    setting = tax_settings[i]
    rate = setting.rate (int64_t)
    base = setting.tax_base (int64_t)
    product = __allmul(base, rate)  # producto directo de 64 bits
    masked_lo = product.lo & 0xFFFF8000
    masked_product = (product.hi << 32) | masked_lo
    class_tax = __alldiv(masked_product, 32768000)  # división entera de 64 bits truncada a cero
    out_tax_total += class_tax
  Si i >= 3:
    bucket_val = buckets[i] (int64_t)
    out_tax_total += bucket_val

Retorna out_tax_total (int64_t truncado a 64 bits con signo).
"""

DIVISOR_64 = 32768000  # 0x1F40000


def allmul_64(a: int, b: int) -> int:
    """Emula fielmente la llamada a 0x00AC9F20 (__allmul producto de 64 bits con signo en x86 MSVC CRT)."""
    prod = a * b
    # wrap to signed 64-bit
    res = (prod + (1 << 63)) % (1 << 64) - (1 << 63)
    return res


def alldiv_64(dividend: int, divisor: int) -> int:
    """Emula fielmente la llamada a 0x00AC02A0 (__alldiv división de enteros de 64 bits con signo truncando a 0)."""
    if divisor == 0:
        raise ZeroDivisionError("__alldiv division by zero")
    # División entera con truncamiento hacia cero de C/MSVC
    if (dividend < 0) ^ (divisor < 0):
        res = -(-dividend // divisor) if dividend < 0 else -(dividend // -divisor)
    else:
        res = abs(dividend) // abs(divisor)
    # wrap to signed 64-bit
    res = (res + (1 << 63)) % (1 << 64) - (1 << 63)
    return res


def calculate_total_tax_revenue(
    tax_settings_rates: list[int],
    tax_settings_bases: list[int],
    buckets: list[int]
) -> int:
    """
    tax_settings_rates: [rate_poor, rate_middle, rate_rich] (int64)
    tax_settings_bases: [base_poor, base_middle, base_rich] (int64)
    buckets: lista de int64_t en buckets del país.
    """
    count = len(buckets)
    if count <= 0:
        return 0

    total = 0

    for i in range(count):
        if i in (0, 1, 2):
            rate = tax_settings_rates[i] if i < len(tax_settings_rates) else 0
            base = tax_settings_bases[i] if i < len(tax_settings_bases) else 0
            
            # call 0xac9f20 (__allmul)
            product = allmul_64(base, rate)
            
            # and eax, 0xffff8000
            prod_lo = product & 0xFFFFFFFF
            prod_hi = (product >> 32) & 0xFFFFFFFF
            
            masked_lo = prod_lo & 0xFFFF8000
            
            # Reconstruir int64 con signo a partir de (prod_hi, masked_lo)
            raw_64 = (prod_hi << 32) | masked_lo
            if raw_64 >= (1 << 63):
                signed_masked = raw_64 - (1 << 64)
            else:
                signed_masked = raw_64
                
            # call 0xac02a0 (__alldiv)
            class_tax = alldiv_64(signed_masked, DIVISOR_64)
            
            total = (total + class_tax) & 0xFFFFFFFFFFFFFFFF
        else:
            bucket_val = buckets[i] & 0xFFFFFFFFFFFFFFFF
            total = (total + bucket_val) & 0xFFFFFFFFFFFFFFFF

    # Convert to signed 64-bit
    if total >= (1 << 63):
        return total - (1 << 64)
    return total
