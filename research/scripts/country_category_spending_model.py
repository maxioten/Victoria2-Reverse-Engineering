"""
Modelo formal en Python de la rutina CCountry::CalculateCategorySpending
(VA 0x00539760..0x00539874).

Calcula la agregación ponderada de 4 canales de gasto público con escalado a 15 bits
y clamping inferior estricto a cero (non-negative spending).
"""


def calculate_category_spending(
    slider1: int,
    slider2: int,
    slider3: int,
    base1: int,
    base2: int,
    base3: int,
    base4: int,
) -> int:
    """Calcula el gasto de la categoría conforme a la rutina en 0x00539760."""
    # 1. Canal 1: (base1 * slider1) >> 15 con signo de 64 bits
    term1 = (base1 * slider1) >> 15

    # 2. Canal 2: (base2 * slider2) >> 15 con signo de 64 bits
    term2 = (base2 * slider2) >> 15

    # 3. Canal 3: adición directa de base3
    term3 = base3

    # 4. Canal 4: (base4 * slider3) >> 15 con signo de 64 bits
    term4 = (base4 * slider3) >> 15

    # Suma acumulada de 64 bits
    raw_total = term1 + term2 + term3 + term4

    # Clamping inferior a cero (0x0053983D..0x0053985E)
    if raw_total <= 0:
        return 0
    return raw_total
