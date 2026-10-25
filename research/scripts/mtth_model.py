"""Analytical model of Victoria II event MTTH (Mean Time To Happen) to daily probability.

Routine: Event_ComputeMTTHProbability at 0x008AE380.
Formula:
  days = mtth_milli // 1000
  If days <= 1:
      probability = 1,000,000 (100% daily chance)
  Else:
      raw = (mode * 1,000,000) // days
      probability = max(1, min(1,000,000, raw))

Probability is expressed in parts-per-million (per million), which is compared
against a uniform random roll from Mersenne Twister [0, 999999].
"""

def compute_mtth_probability(mtth_milli: int, mode: int = 1) -> int:
    """Compute daily event probability per million from MTTH in milli-days and mode.
    
    Returns an integer clamped to [1, 1000000].
    """
    days = mtth_milli // 1000
    if days <= 1:
        return 1000000
    raw = (mode * 1000000) // days
    if raw > 1000000:
        return 1000000
    elif raw <= 0:
        return 1
    return raw
