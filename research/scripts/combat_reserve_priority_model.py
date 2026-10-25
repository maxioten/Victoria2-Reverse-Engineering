#!/usr/bin/env python3
"""Analytical model of CSubUnit::CompareTacticalValue in Victoria II (0x0059B780..0x0059B833).

The routine evaluates the tactical priority score of two candidate reserve regiments (A and B)
and returns True if regiment A has strictly lower priority than regiment B (i.e. A < B, standard
strict weak ordering for descending priority queue insertion):
1. Stat sum of unit type:
   stat_sum = fire_attack + shock_attack + maneuver
2. Effective organization:
   If pLeader != NULL and leader.is_inoperative != 0:
       effective_org = 0
   Else:
       effective_org = regiment.organization
3. Intermediate scaling via 64-bit integer division (_alldiv with 1000):
   step1 = (effective_org * stat_sum) // 1000
4. Final tactical score scaled by physical strength:
   score = (step1 * regiment.strength) // 1000
5. Comparison:
   return score_A < score_B
"""
from dataclasses import dataclass


@dataclass
class SubUnitTacticalInput:
    strength: int  # in m-units (e.g. 3,000,000 = 3000 men or 3,000 = 3.0 men)
    organization: int  # in m-units (e.g. 30,000 = 30.0 morale)
    fire_attack: int  # in m-units (e.g. 1,000 = 1.0)
    shock_attack: int  # in m-units (e.g. 1,500 = 1.5)
    maneuver: int  # in m-units (e.g. 1,000 = 1.0)
    has_leader: bool = False
    leader_inoperative: bool = False


def calculate_tactical_score(u: SubUnitTacticalInput) -> int:
    """Computes tactical score according to 0x0059B780..0x0059B7D7."""
    stat_sum = u.fire_attack + u.shock_attack + u.maneuver

    if u.has_leader and u.leader_inoperative:
        effective_org = 0
    else:
        effective_org = u.organization

    step1 = (effective_org * stat_sum) // 1000
    score = (step1 * u.strength) // 1000
    return score


def compare_tactical_value(a: SubUnitTacticalInput, b: SubUnitTacticalInput) -> bool:
    """Exact emulation of CSubUnit::CompareTacticalValue (0x0059B780..0x0059B833).

    Returns True if score(A) < score(B), False otherwise.
    """
    score_a = calculate_tactical_score(a)
    score_b = calculate_tactical_score(b)
    return score_a < score_b
