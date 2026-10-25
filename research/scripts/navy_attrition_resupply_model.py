#!/usr/bin/env python3
"""Analytical model of CNavy::CalculateSeaAttrition and CNavy::EvaluateResupplyNecessity.

Routines:
  CNavy::CalculateSeaAttrition (slot 31 at 0x00E03048, 0x005D7EC0).
  CNavy::EvaluateResupplyNecessity (0x005D8120).
"""

def calculate_sea_attrition(
    time_at_sea: int,
    grace_period_ms: int,
    naval_range_divisor: int,
    supply_distance: int,
    max_naval_attrition: int
) -> int:
    """Computes daily naval attrition rate in milésimas based on time at sea and range."""
    # 1. Grace period check (using division by 1000 via 0x10624DD3)
    grace_threshold = grace_period_ms // 1000
    if time_at_sea < grace_threshold:
        return 0

    # 2. Distance ratio check
    if naval_range_divisor == 0:
        ratio = -1
    else:
        # Note: 32-bit vs 64-bit bifurcation produces identical integer result
        ratio = (supply_distance * 1000) // naval_range_divisor

    # 3. Maximum attrition scaling
    delta = 1000 - ratio
    attrition = (delta * max_naval_attrition) // 1000
    return attrition


def evaluate_resupply_necessity(
    attrition: int,
    has_port_table: bool,
    port_capacity: int,
    ship_count: int,
    health_ratio_ms: int
) -> bool:
    """Determines whether a fleet requires immediate resupply or repair in port."""
    # 1. Active attrition check
    if attrition > 0:
        return True

    # 2. Port environment and active ship presence check
    if not has_port_table or port_capacity <= 0 or ship_count <= 0:
        return False

    # 3. Health ratio threshold check (850.5 floor = 850 milésimas / 85.0%)
    if health_ratio_ms < 850:
        return True

    return False
