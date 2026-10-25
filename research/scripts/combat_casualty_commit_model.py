#!/usr/bin/env python3
"""Analytical model for daily combat casualties and morale loss commit routines.

Routines:
  CCombatant::CommitCasualtiesAndMoraleLoss (0x005DC330..0x005DC3BD)
  CCombatant::CommitCasualtiesByUnitType (0x005DC3C0..0x005DC45B)
"""
from dataclasses import dataclass
import math

@dataclass
class RegimentDamageState:
    category: int
    strength: int
    pending_casualties: int
    morale: int
    pending_morale_loss: int

def commit_casualties_total(armies_regiments: list[list[RegimentDamageState]]) -> tuple[int, list[list[RegimentDamageState]]]:
    """Applies pending casualties to all regiments across all armies in combat."""
    init_val = int(math.floor(0.0005000000237487257 * 1000.0))
    total_loss = init_val
    updated_armies = []
    
    for army in armies_regiments:
        updated_army = []
        for reg in army:
            eff_cas = min(reg.strength, max(0, reg.pending_casualties))
            eff_mor = min(reg.morale, max(0, reg.pending_morale_loss))
            new_reg = RegimentDamageState(
                category=reg.category,
                strength=reg.strength - eff_cas,
                pending_casualties=0,
                morale=reg.morale - eff_mor,
                pending_morale_loss=0
            )
            updated_army.append(new_reg)
            total_loss = (total_loss + eff_cas) & 0xFFFFFFFF
        updated_armies.append(updated_army)
        
    if total_loss >= 0x80000000:
        total_loss -= 0x100000000
    return total_loss, updated_armies

def commit_casualties_by_type(target_category: int, armies_regiments: list[list[RegimentDamageState]]) -> tuple[int, list[list[RegimentDamageState]]]:
    """Applies pending casualties only to regiments matching target_category."""
    init_val = int(math.floor(0.0005000000237487257 * 1000.0))
    type_loss = init_val
    updated_armies = []
    
    for army in armies_regiments:
        updated_army = []
        for reg in army:
            if reg.category == target_category:
                eff_cas = min(reg.strength, max(0, reg.pending_casualties))
                eff_mor = min(reg.morale, max(0, reg.pending_morale_loss))
                new_reg = RegimentDamageState(
                    category=reg.category,
                    strength=reg.strength - eff_cas,
                    pending_casualties=0,
                    morale=reg.morale - eff_mor,
                    pending_morale_loss=0
                )
                type_loss = (type_loss + eff_cas) & 0xFFFFFFFF
            else:
                # Untouched
                new_reg = RegimentDamageState(
                    category=reg.category,
                    strength=reg.strength,
                    pending_casualties=reg.pending_casualties,
                    morale=reg.morale,
                    pending_morale_loss=reg.pending_morale_loss
                )
            updated_army.append(new_reg)
        updated_armies.append(updated_army)
        
    if type_loss >= 0x80000000:
        type_loss -= 0x100000000
    return type_loss, updated_armies
