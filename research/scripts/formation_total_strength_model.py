#!/usr/bin/env python3
"""Analytical model for CUnit::CalculateTotalStrength (CArmy and CNavy).

CArmy at 0x005D61A0 (slot 10, +0x28 in CArmy vtable 0x00DF88F4):
  Initializes *out_strength = floor(0.0005 * 1000.0) = 0
  Iterates linked list of regiments at [army + 0x38], adding [regiment + 0x3C] to *out_strength.
  Returns out_strength pointer.

CNavy at 0x005D91D0 (slot 10, +0x28 in CNavy vtable 0x00E02FF4):
  Reads ship_count at [navy + 0x40].
  Multiplies by 1000: *out_strength = (ship_count * 1000) (mod 2^32, signed int32).
  Returns out_strength pointer.
"""
import math

def army_total_strength(regiments: list[int]) -> int:
    """Computes total strength of an army from its list of regiments' strengths."""
    # Step 1: FP initialization: floor(0.0005 * 1000.0) = 0
    init_val = int(math.floor(0.0005000000237487257 * 1000.0))
    total = init_val
    for s in regiments:
        total = (total + s) & 0xFFFFFFFF
    if total >= 0x80000000:
        total -= 0x100000000
    return total

def navy_total_strength(ship_count: int) -> int:
    """Computes total strength of a navy from its ship count."""
    total = (ship_count * 1000) & 0xFFFFFFFF
    if total >= 0x80000000:
        total -= 0x100000000
    return total
