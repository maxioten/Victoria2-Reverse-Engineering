"""Modelo analítico formal del cálculo de producción y consumo de insumos de fábricas.

Rutina en Victoria II v2game.exe (SHA-256 62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648):
- VA 0x004DD470..0x004DD5D0 (CProductionType::ProduceGoods / UpdateProductionGoods)

Entrada:
- base_output (int64): cantidad base de output en punto fijo (escala 32768)
- throughput_bonus (int64): multiplicador de rendimiento/empleo (escala 32768, 1.0 = 32768)
- factory_level (int32): nivel entero de la fábrica (1, 2, 3...)
- input_base (int64): requerimiento base de cada insumo (escala 32768)
- efficiency_mult (int64): multiplicador de eficiencia de insumos (escala 32768)

Salida:
- effective_output (int64): producción final inyectada al mercado
- effective_input (int64): insumo consumido por la fábrica
"""

from typing import Tuple

FP_SCALE: int = 32768


def fixed_point_multiply(a: int, b: int) -> int:
    """Multiplicación exacta de punto fijo MSVC 64-bit (0x00AC9F20).
    
    (a * b) >> 15
    """
    prod = a * b
    return prod >> 15


def compute_factory_production(
    base_output: int,
    throughput_bonus: int,
    factory_level: int,
    input_base: int = 0,
    efficiency_mult: int = FP_SCALE
) -> Tuple[int, int]:
    """Calcula la producción efectiva de output y el consumo de input de la fábrica.
    
    Reproduce con precisión de bit la secuencia en 0x004DD470..0x004DD560.
    """
    # 1. base_output * throughput_bonus
    # En asm: 0x004DD489: call 0xac9f20 -> shrd eax, edx, 0xf
    step1 = fixed_point_multiply(base_output, throughput_bonus)
    
    # 2. Conversión de level (int32) a punto fijo: level << 15
    level_fp = factory_level << 15
    
    # 3. step1 * level_fp
    # En asm: 0x004DD4A8: call 0xac9f20 -> shrd eax, edx, 0xf
    effective_output = fixed_point_multiply(step1, level_fp)
    
    # 4. Cálculo de consumo de insumo (si input_base > 0)
    effective_input = 0
    if input_base > 0:
        # En asm: 0x004DD539: input_base * efficiency_mult
        step_inp = fixed_point_multiply(input_base, efficiency_mult)
        # En asm: 0x004DD54F: step_inp * effective_output
        effective_input = fixed_point_multiply(step_inp, effective_output)

    return effective_output, effective_input
