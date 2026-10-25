"""Analytical model of Victoria II AI event option weight evaluation.

Routine: EventOption_EvaluateAIChance at 0x008AEB00.
Formula:
  v = block.base
  For each modifier m:
      If all m.conditions evaluate to true:
          v = (v * m.factor) // 1000
          If v <= 0:
              break
  *out = (block.multiplier * v) // 1000
  Return out pointer.
"""

def evaluate_ai_chance(base_val: int, multiplier: int, modifiers: list[tuple[int, list[bool]]]) -> int:
    """Compute option AI weight from base value, multiplier, and list of modifiers.
    
    Each modifier is a tuple (factor, [cond_1, cond_2, ...]).
    Factors and multipliers are integers in milli-units (1000 = 1.0x).
    """
    v = base_val
    for factor, conditions in modifiers:
        if all(conditions):
            # Signed 64-bit integer division by 1000
            v = (v * factor) // 1000
            if v <= 0:
                break
    return (multiplier * v) // 1000
