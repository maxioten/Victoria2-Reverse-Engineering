#!/usr/bin/env python3
"""Analytical model of CNavalCombat::CalculateForceRatio in Victoria II (0x005AB710..0x005AB75F).

The virtual routine (slot 6, +0x18 in CNavalCombat vtable at 0x00E02450) computes the naval
combat positioning / force ratio based on sea zone congestion / penalty (+0x114 in CProvince):
1. Reads raw sea zone penalty from [sea_province + 0x114].
2. Computes quotient via compiler magic constant 0x10624DD3:
   quotient = penalty // 1000
3. Re-scales to thousands:
   truncated = quotient * 1000
4. Computes baseline complement from 100,000 (0x186A0):
   delta = 100000 - truncated
5. Multiplies by 1000 in 64-bit (_allmul):
   prod = delta * 1000
6. Divides by 100,000 in 64-bit (_alldiv):
   ratio = prod // 100000
7. Writes *out_ratio = ratio and returns out_ratio pointer.
"""


def calculate_naval_force_ratio(sea_penalty: int) -> int:
    """Exact emulation of routine 0x005AB710."""
    # Magic division by 1000
    prod = sea_penalty * 0x10624DD3
    edx = prod >> 32
    sar = edx >> 6
    sign = (sar >> 31) & 1
    quotient = sar + sign

    truncated = quotient * 1000
    delta = 100000 - truncated

    # 64-bit multiplication and division
    prod64 = delta * 1000
    ratio = prod64 // 100000

    return ratio
