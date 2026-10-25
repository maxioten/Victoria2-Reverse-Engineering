"""Modelo analítico formal de la curva de elasticidad y sensibilidad de precios de mercado.

Rutinas en Victoria II v2game.exe (SHA-256 62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648):
- VA 0x00482610..0x0048292B (CMarket::CalculateSensitivityMultiplier / GetPriceFactorFromRatio)
- VA 0x0048C080..0x0048C0C8 (HelperSqrtSensitivity)
- Llamador en tick de mercado: VA 0x00482B65 en bucle de actualización de bienes.

Entrada:
- ratio (int64): ratio oferta/demanda escalado a 15 bits fraccionarios:
                 ratio = (supply * 32768) / demand

Salida:
- multiplier (int64): factor de escala de precio escalado a 15 bits fraccionarios.
"""

from typing import Final

# Constantes de punto fijo
FP_ONE: Final[int] = 32768
HALF: Final[float] = 0.5


def to_fixed_point(val: float) -> int:
    """Conversión float a CFixedPoint con redondeo simétrico y escala 32768."""
    if val >= 0.0:
        return int(val * 32768.0 + HALF)
    else:
        return int(val * 32768.0 - HALF)


# Tabla de umbrales y factores en el binario
# Tramos 1..3: constantes double en 0x00E45820..0x00E45800 convertidas con ftol2
# Tramo 4: umbral double en 0x00E457F0, factor float en 0x00E457E8
# Tramos 5..13: constantes float construidas mediante CFixedPoint(float)
T1: Final[int] = int(1638.9000244140625)   # 1638 (~0.050)
R1: Final[int] = int(7307.76416015625)     # 7307 (~0.2230)

T2: Final[int] = int(2163.18798828125)     # 2163 (~0.066)
R2: Final[int] = int(8454.6435546875)      # 8454 (~0.2580)

T3: Final[int] = int(2720.243896484375)    # 2720 (~0.083)
R3: Final[int] = int(9437.68359375)        # 9437 (~0.2880)

T4: Final[int] = int(3277.300048828125)    # 3277 (~0.100)
R4: Final[int] = to_fixed_point(0.3160000145435333)    # 10355 (~0.3160)

T5: Final[int] = to_fixed_point(0.11100000143051147)   # 3637 (~0.1110)
R5: Final[int] = to_fixed_point(0.3330000042915344)    # 10912 (~0.3330)

T6: Final[int] = to_fixed_point(0.125)                  # 4096 (0.1250)
R6: Final[int] = to_fixed_point(0.3529999852180481)    # 11567 (~0.3530)

T7: Final[int] = to_fixed_point(0.1420000046491623)    # 4653 (~0.1420)
R7: Final[int] = to_fixed_point(0.37700000405311584)   # 12354 (~0.3770)

T8: Final[int] = to_fixed_point(0.16599999368190765)   # 5439 (~0.1660)
R8: Final[int] = to_fixed_point(0.40799999237060547)   # 13369 (~0.4080)

T9: Final[int] = to_fixed_point(0.20000000298023224)   # 6554 (~0.2000)
R9: Final[int] = to_fixed_point(0.44699999690055847)   # 14647 (~0.4470)

T10: Final[int] = to_fixed_point(0.25)                 # 8192 (0.2500)
R10: Final[int] = to_fixed_point(0.5)                  # 16384 (0.5000)

T11: Final[int] = to_fixed_point(0.3330000042915344)   # 10912 (~0.3330)
R11: Final[int] = to_fixed_point(0.5770000219345093)   # 18907 (~0.5770)

T12: Final[int] = to_fixed_point(0.5)                  # 16384 (0.5000)
R12: Final[int] = to_fixed_point(0.699999988079071)    # 22938 (~0.7000)

T13: Final[int] = to_fixed_point(0.6660000085830688)   # 21823 (~0.6660)
R13: Final[int] = to_fixed_point(0.8159999847412109)   # 26739 (~0.8160)


def calculate_price_sensitivity(ratio: int) -> int:
    """Calcula el factor de sensibilidad/elasticidad de precios de mercado.
    
    Reproduce con precisión de bit la rutina 0x00482610..0x0048292B.
    """
    if ratio < T1:
        return R1
    if ratio < T2:
        return R2
    if ratio < T3:
        return R3
    if ratio < T4:
        return R4
    if ratio < T5:
        return R5
    if ratio < T6:
        return R6
    if ratio < T7:
        return R7
    if ratio < T8:
        return R8
    if ratio < T9:
        return R9
    if ratio < T10:
        return R10
    if ratio < T11:
        return R11
    if ratio < T12:
        return R12
    if ratio < T13:
        return R13

    # Fallback sub-lineal por raíz cuadrada: 0x0048C080
    # sqrt(ratio / 32768.0) * 32768.0
    val = (ratio / 32768.0) ** 0.5
    return to_fixed_point(val)
