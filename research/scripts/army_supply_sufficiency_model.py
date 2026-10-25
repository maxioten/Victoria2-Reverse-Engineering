#!/usr/bin/env python3
"""Analytical model of CArmy::EvaluateSupplySufficiency in Victoria II (0x005D5E30..0x005D5EE3).

The virtual routine (slot 3, +0x0C in CArmy vtable at 0x00DF8944) determines whether an army
has adequate supply coverage in a target province or suffers logistical deficit / attrition:
1. Terrain check:
   If province.terrain.is_water != 0 (sea zone):
       If army.is_embarked != 0:
           return True (safe inside transport fleet)
       Else:
           return army.can_traverse_sea (fallback traversal check)
2. Land province logistical aggregation:
   Initializes:
       demanded_weight = this_army.supply_weight
       provided_capacity = 0
   Iterates through all other armies stationed in province:
       If army == this_army: skip
       If army.is_allied and army.country_id == this_army.country_id:
           demanded_weight += army.supply_weight
       If army.is_supply_source and army.country_id == this_army.country_id:
           provided_capacity += army.effective_capacity
   Final sufficiency test:
       return provided_capacity >= demanded_weight
"""
from dataclasses import dataclass, field
from typing import List


@dataclass
class ArmyStationedState:
    army_id: int
    country_id: int
    supply_weight: int
    effective_capacity: int
    is_allied: bool = True
    is_supply_source: bool = True


@dataclass
class SupplySufficiencyInput:
    this_army_country_id: int
    this_army_weight: int
    is_water_province: bool = False
    is_embarked: bool = False
    can_traverse_sea: bool = False
    stationed_armies: List[ArmyStationedState] = field(default_factory=list)


def evaluate_supply_sufficiency(inp: SupplySufficiencyInput) -> bool:
    """Exact emulation of CArmy::EvaluateSupplySufficiency (0x005D5E30..0x005D5EE3)."""
    if inp.is_water_province:
        if inp.is_embarked:
            return True
        return inp.can_traverse_sea

    demanded_weight = inp.this_army_weight
    provided_capacity = 0

    for a in inp.stationed_armies:
        if a.country_id == inp.this_army_country_id:
            if a.is_allied:
                demanded_weight += a.supply_weight
            if a.is_supply_source:
                provided_capacity += a.effective_capacity

    return provided_capacity >= demanded_weight
