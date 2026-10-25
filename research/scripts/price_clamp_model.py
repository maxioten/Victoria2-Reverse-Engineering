"""Analytical model of Victoria II World Market price clamping.

Prices in the engine use 2^15 (32768) fixed-point representation.
Constants:
  kPriceMinFactor at 0x00E45C30 = 6554.10009765625 (0.2 * 32768 + 0.5)
  kPriceMaxFactor at 0x00E45C28 = 163840.5 (5.0 * 32768 + 0.5)
The floats are converted to 64-bit integer via CRT helper 0x00B31C36 (truncating),
multiplied by the 64-bit base_price via 0x00AC9F20 (__allmul),
and shifted right arithmetically by 15 bits.
"""

MIN_FACTOR_INT = 6554
MAX_FACTOR_INT = 163840

def compute_price_bounds(base_price: int) -> tuple[int, int]:
    """Compute (min_price, max_price) in 2^15 fixed point for a given base_price."""
    # 64-bit integer arithmetic
    min_price = (base_price * MIN_FACTOR_INT) >> 15
    max_price = (base_price * MAX_FACTOR_INT) >> 15
    return min_price, max_price

def clamp_price(base_price: int, raw_price: int) -> tuple[int, bool]:
    """Clamp raw_price to [min_price, max_price] according to 0x00482CCE..0x00482D1E.
    
    Returns (clamped_price, was_clamped).
    """
    min_price, max_price = compute_price_bounds(base_price)
    if raw_price < min_price:
        return min_price, True
    elif raw_price > max_price:
        return max_price, True
    else:
        return raw_price, False
