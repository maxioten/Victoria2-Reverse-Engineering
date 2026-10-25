#!/usr/bin/env python3
"""Analytical model of CProvince::CalculateHostileNavalDivisions and CProvince::CountHostileUnitsDirect.

Formulas:
  CalculateHostileNavalDivisions (0x005DC940):
    For each unit U_k in province:
      If U_k->IsLand() != 0: skip (only evaluate navies)
      If U_k.country_id == target_country_id: skip (friendly)
      is_hostile = (rel.is_at_war != 0) or (target_tag == "REB") or (U_k.country.tag == "REB")
      If is_hostile:
        men = sum(subunit.strength for subunit in U_k)
        total_men += men
    divisions = total_men // 1000  (using compiler magic 0x10624DD3)
    return divisions

  CountHostileUnitsDirect (0x005DCA30):
    For each unit U_k in province:
      (No IsLand() / IsNavy() check, evaluates all formations)
      If U_k.country_id == target_country_id: skip (friendly)
      is_hostile = (rel.is_at_war != 0) or (target_tag == "REB") or (U_k.country.tag == "REB")
      If is_hostile:
        total_units += U_k.subunit_count
    return total_units
"""
from dataclasses import dataclass, field
from typing import List, Dict


@dataclass
class SubUnit:
    strength: int = 1000


@dataclass
class Unit:
    is_land: bool = False
    is_navy: bool = True
    subunits: List[SubUnit] = field(default_factory=list)
    subunit_count: int = 0
    country_id: int = 0


@dataclass
class Country:
    country_id: int = 0
    tag: bytes = b"ENG"
    relations: Dict[int, bool] = field(default_factory=dict)


def calculate_hostile_naval_divisions(
    units: List[Unit],
    countries: Dict[int, Country],
    target_tag: bytes,
    target_country_id: int
) -> int:
    total_men = 0
    for u in units:
        # Step 1: Filter out land units
        if u.is_land:
            continue

        # Step 2: Filter out units of target country
        country = countries.get(u.country_id)
        if country is None:
            continue
        if country.country_id == target_country_id:
            continue

        # Step 3: Check diplomatic hostility or rebel faction
        is_at_war = country.relations.get(target_country_id, False)
        is_target_reb = (len(target_tag) >= 3 and target_tag[:3] == b"REB")
        is_country_reb = (len(country.tag) >= 3 and country.tag[:3] == b"REB")

        if is_at_war or is_target_reb or is_country_reb:
            fleet_men = sum(s.strength for s in u.subunits)
            total_men += fleet_men

    return total_men // 1000


def count_hostile_units_direct(
    units: List[Unit],
    countries: Dict[int, Country],
    target_tag: bytes,
    target_country_id: int
) -> int:
    total_units = 0
    for u in units:
        # Step 1: No branch filter (evaluates all formations)
        country = countries.get(u.country_id)
        if country is None:
            continue
        if country.country_id == target_country_id:
            continue

        # Step 2: Check diplomatic hostility or rebel faction
        is_at_war = country.relations.get(target_country_id, False)
        is_target_reb = (len(target_tag) >= 3 and target_tag[:3] == b"REB")
        is_country_reb = (len(country.tag) >= 3 and country.tag[:3] == b"REB")

        if is_at_war or is_target_reb or is_country_reb:
            total_units += u.subunit_count

    return total_units
