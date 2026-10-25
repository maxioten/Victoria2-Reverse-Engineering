"""Modelo analítico formal del cálculo de Life Rating provincial efectivo.

Rutina en Victoria II v2game.exe (SHA-256 62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648):
- VA 0x004B9BD0..0x004B9C5F (CProvince::CalculateEffectiveLifeRating)

Entrada:
- base_life_rating (int32): calificación de vida base de la provincia (provincia + 0x1A4, e.g. 10..35)
- health_tech_modifier (int32): bonificador tecnológico/médico (país + 0x260, en milésimas)

Salida:
- effective_life_rating (int64): valor de Life Rating efectivo en punto fijo (escala 32768)
  restringido estrictamente al rango [0, 40.0 * 32768] = [0, 1310720].
"""

from typing import Final

FP_SCALE: Final[int] = 32768
MAX_EFFECTIVE_LIFE_RATING: Final[int] = 0x140000  # 40.0 * 32768 = 1,310,720
DIVISOR_TECH: Final[int] = 0x1F40000            # 32,768,000 = 1000 * 32768


def compute_effective_life_rating(base_life_rating: int, health_tech_modifier: int = 0) -> int:
    """Calcula el Life Rating efectivo de una provincia con modificadores tecnológicos.
    
    Reproduce con precisión de bit la rutina 0x004B9BD0..0x004B9C5F.
    """
    # 1. Base life rating a punto fijo de 15 bits
    life_rating_fp = base_life_rating << 15
    
    # 2. Modificador tecnológico escalado
    # En asm: (health_tech << 30) / 0x1F40000
    tech_scaled_64 = (health_tech_modifier << 30)
    # División entera con signo de 64 bits (_alldiv)
    tech_scaled = tech_scaled_64 // DIVISOR_TECH if tech_scaled_64 >= 0 else -(-tech_scaled_64 // DIVISOR_TECH)
    
    # 3. Factor multiplicador: 1.0 (0x8000 = 32768) + tech_scaled
    tech_factor = tech_scaled + FP_SCALE
    
    # 4. Multiplicación de punto fijo de 64 bits: (life_rating_fp * tech_factor) >> 15
    raw_effective = (life_rating_fp * tech_factor) >> 15
    
    # 5. Clamping al rango [0, 40.0]: [0, 0x140000]
    if raw_effective < 0:
        return 0
    if raw_effective > MAX_EFFECTIVE_LIFE_RATING:
        return MAX_EFFECTIVE_LIFE_RATING
        
    return raw_effective
