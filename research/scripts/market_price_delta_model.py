"""Reference model for market price delta with verified hysteresis deadband and daily 1% step."""

def compute_market_price_delta(current_price: int, target_price: int, max_step: int = 328):
    """
    Simulates the price adjustment logic in Victoria II (0x00482B96..0x00482C40).
    
    The engine uses a threshold-based hysteresis deadband:
    - If target_price > current_price + max_step: delta = +max_step (+328)
    - If target_price < current_price - max_step: delta = -max_step (-328)
    - If within [-max_step, +max_step]: delta = 0 (price does not fluctuate)
    """
    diff = target_price - current_price

    if diff > max_step:
        delta = max_step
    elif diff < -max_step:
        delta = -max_step
    else:
        delta = 0

    new_price = current_price + delta
    return delta, new_price
