#!/usr/bin/env python3
"""Analytical model of CRegiment::CanReinforce in Victoria II (0x005CC4D0..0x005CC529).

The virtual routine (slot 20, +0x50 in CRegiment vtable at 0x00DF8884) evaluates whether a
regiment is legally and logistically able to receive manpower reinforcements from its home POP:
1. Home Soldier POP existence check:
   If regiment.home_pop_ptr == NULL (POP dissolved / wiped out):
       return False
2. Home POP territorial jurisdiction:
   Invokes virtual method on home POP (slot 22, +0x58) to retrieve pop_residence_info (pop_country_id).
   If regiment.country_id == pop_country_id:
       return True (unrestricted domestic replenishment)
3. Military access / supply corridor fallback:
   If home POP province is under hostile control / foreign territory:
       Invokes HasMilitaryAccessOrSupplyRoute(regiment.location, pop.location).
       If accessible:
           return True
       Else:
           return False
"""
from dataclasses import dataclass


@dataclass
class RegimentReinforceInput:
    has_home_pop: bool
    regiment_country_id: int
    pop_country_id: int
    has_access_corridor: bool = False


def can_regiment_reinforce(inp: RegimentReinforceInput) -> bool:
    """Exact emulation of routine 0x005CC4D0."""
    if not inp.has_home_pop:
        return False

    if inp.regiment_country_id == inp.pop_country_id:
        return True

    return inp.has_access_corridor
