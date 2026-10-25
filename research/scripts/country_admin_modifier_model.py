"""
Modelo formal en Python de la rutina CCountry::CalculateAdministrativeSpendingModifier (VA 0x00538150..0x005381F2).

Firma original de la rutina en el ejecutable PE32:
int32_t* __thiscall CCountry::CalculateAdministrativeSpendingModifier(CCountry* this, int32_t* out_modifier)
- ECX: CCountry* (esi)
- EDI: int32_t* out_modifier (puntero de salida donde se escribe el resultado de 32 bits)

Lógica de cálculo:
1. Obtiene la tecnología administrativa/comercial:
   tech_val = this->tech_container[+0x7C] (int32_t)
   tech_fp = (int64_t(tech_val) << 30) // 32768000  (usando división de enteros con signo __alldiv)
   (tech_fp se prepara en la pila como struct temporal de 64 bits para el cálculo o evaluación)

2. Evalúa la política de gobierno:
   Si this->ruling_party_flag (+0x4CC) > 0:
     utiliza el buffer de política A (+0x14)
   Si no:
     utiliza el buffer de política B (+0x1C)
   Llama a CCountry::GetPolicyModifier(0x0096A2C0) pasando &this->policies (+0xA48) y el buffer seleccionado.
   El helper retorna un puntero a int64_t policy_mod (64 bits).

3. Multiplicación escalar CRT:
   product = __allmul(policy_mod, 32768000)

4. Normalización a punto fijo (desplazamiento aritmético de 30 bits a la derecha):
   result = product >> 30  (con signo de 64 bits, truncado a 32 bits con signo)

5. Almacena en *out_modifier = result (int32)
   Retorna EAX = out_modifier
"""

DIVISOR_64 = 32768000  # 0x01F40000


def alldiv_64(dividend: int, divisor: int) -> int:
    """Emula fielmente __alldiv (0x00AC02A0) de MSVC CRT."""
    if divisor == 0:
        raise ZeroDivisionError("__alldiv division by zero")
    if (dividend < 0) ^ (divisor < 0):
        res = -(-dividend // divisor) if dividend < 0 else -(dividend // -divisor)
    else:
        res = abs(dividend) // abs(divisor)
    return (res + (1 << 63)) % (1 << 64) - (1 << 63)


def allmul_64(a: int, b: int) -> int:
    """Emula fielmente __allmul (0x00AC9F20) de MSVC CRT."""
    prod = a * b
    return (prod + (1 << 63)) % (1 << 64) - (1 << 63)


def compute_admin_spending_modifier(
    tech_val: int,
    ruling_party_flag: int,
    policy_mod_a: int,
    policy_mod_b: int
) -> tuple[int, int]:
    """
    Retorna una tupla:
    (tech_scaled_fp, final_modifier_32)
    """
    # 1. Escalado de tecnología administrativa (shl/shld 30 bits y división entre 32768000)
    raw_shifted = tech_val << 30
    # wrap to signed 64-bit
    raw_shifted_64 = (raw_shifted + (1 << 63)) % (1 << 64) - (1 << 63)
    tech_scaled_fp = alldiv_64(raw_shifted_64, DIVISOR_64)

    # 2. Selección de modificador según política comercial/gobierno
    selected_policy = policy_mod_a if ruling_party_flag > 0 else policy_mod_b

    # 3. Multiplicación CRT por 32,768,000
    prod = allmul_64(selected_policy, DIVISOR_64)

    # 4. Normalización shrd/sar 30 bits
    res = prod >> 30
    res_32 = (res + (1 << 31)) % (1 << 32) - (1 << 31)

    return tech_scaled_fp, res_32
