"""
Analytical model for CLandCombatant::PruneAndConsolidateLine (0x0059AEF0..0x0059B0D9).

Victoria II 3.04 (v2game.exe):
Performs post-attack maintenance on the combat front line:
1. Scans the 30 front line columns in center-alternating order (16, 15, 17, 14, 18, 13...).
2. Evaluates each frontline unit against collapse criteria:
   - strength < 100 (floor(100.5))
   - organization < 1000 (1.0 in milésimas)
3. If collapsed:
   - If tactical retreat allowed: unit moves to shattered/routed pool (0x17C / 0x180).
   - If tactical retreat not allowed: checked for target acquisition (FindTargetRegiment).
     If no target found and collapsed, moves to retreat pool (0x16C / 0x170).
   - Vacates front line slot: front_line[col] = None.
   - Immediately invokes AdvanceColumnReinforcement (0x0059B0E0) for that column.
   - Marks line_changed = True.
4. After scanning 30 columns: invokes DeployFromReserve (0x0059B190).
5. Centripetal Gap Closing:
   Iterates columns 1 to 28:
   - For left wing (1 <= col < 15):
     if front_line[col] is empty and front_line[col - 1] is occupied:
       front_line[col] = front_line[col - 1]
       front_line[col - 1] = None
   - For right wing (15 <= col < 29):
     if front_line[col] is empty and front_line[col + 1] is occupied:
       front_line[col] = front_line[col + 1]
       front_line[col + 1] = None
"""

from dataclasses import dataclass, field
from typing import List, Optional, Tuple


@dataclass
class UnitState:
    uid: int
    strength: int  # soldiers, e.g. 1000
    org: int       # milésimas, e.g. 30000
    support: int = 0  # milésimas
    maneuver: int = 1000  # milésimas


@dataclass
class CombatantLineState:
    front_line: List[Optional[UnitState]] = field(default_factory=lambda: [None] * 32)
    back_line: List[Optional[UnitState]] = field(default_factory=lambda: [None] * 32)
    retreat_list: List[int] = field(default_factory=list)  # UIDs in 0x16C
    routed_list: List[int] = field(default_factory=list)   # UIDs in 0x17C


def generate_alternating_columns() -> List[int]:
    """Generates the 30-column sweep: 16, 15, 17, 14, 18, 13... 30, 1 (0-indexed)."""
    cols = []
    for k in range(30):
        step = (k + 1) // 2
        sign = -1 if (k % 2 == 1) else 1
        # In assembly: 16 + sign * step (1-indexed base 16, so 15 in 0-indexed)
        # Specifically:
        # k=0: bl=1, eax=0, imul eax, ebx -> 0 + 16 = 16 (0-indexed: 15)
        # k=1: bl=0, ebx=-1, eax=1, imul -> -1 + 16 = 15 (0-indexed: 14)
        # k=2: bl=1, ebx=1, eax=1, imul -> +1 + 16 = 17 (0-indexed: 16)
        c = 16 + sign * step if (k % 2 == 1) else 16 + step
        # Assembly does:
        # ebx = 0; sete bl (bl = 1 if k even, 0 if k odd)
        # eax = k + 1; sar eax, 1 -> (k+1)//2
        # ebx = ebx*2 - 1 -> +1 if k even, -1 if k odd
        # eax = eax * ebx -> signed offset
        # eax + 0x10 -> column index 1..30 (0-indexed: col - 1)
        # For k=0: eax = 0, ebx = 1 -> 0 + 16 = 16
        # For k=1: eax = 1, ebx = -1 -> -1 + 16 = 15
        # For k=2: eax = 1, ebx = 1 -> +1 + 16 = 17
        # For k=3: eax = 2, ebx = -1 -> -2 + 16 = 14
        offset = ((k + 1) // 2) * (1 if (k % 2 == 0) else -1)
        col_1based = 16 + offset
        cols.append(col_1based - 1)
    return cols


def advance_column_reinforcement(state: CombatantLineState, col: int) -> bool:
    """Emulates CLandCombatant::AdvanceColumnReinforcement (0x0059B0E0)."""
    back_unit = state.back_line[col]
    if back_unit is None:
        return False
    # If front is empty, advance directly
    if state.front_line[col] is None:
        state.front_line[col] = back_unit
        state.back_line[col] = None
        return True
    # If front occupied, artillery (support > 0) stays in back line
    if back_unit.support > 0:
        return False
    # Infantry flaking advance
    if col + 1 < 30 and state.front_line[col + 1] is None:
        state.front_line[col + 1] = back_unit
        state.back_line[col] = None
        return True
    if col - 1 >= 0 and state.front_line[col - 1] is None:
        state.front_line[col - 1] = back_unit
        state.back_line[col] = None
        return True
    return False


def prune_and_consolidate_line(
    state: CombatantLineState,
    is_tactical_retreat_allowed: bool = True,
    target_has_operational_units: bool = True,
) -> None:
    """Emulates CLandCombatant::PruneAndConsolidateLine (0x0059AEF0..0x0059B0D9)."""
    line_changed = False
    columns = generate_alternating_columns()

    # Pass 1: Pruning collapsed units
    for col in columns:
        unit = state.front_line[col]
        if unit is None:
            # Empty column calls advance reinforcement
            advance_column_reinforcement(state, col)
            continue

        is_collapsed = (unit.strength < 100) or (unit.org < 1000)

        if is_tactical_retreat_allowed:
            if is_collapsed:
                # Add to routed list
                state.routed_list.append(unit.uid)
                state.front_line[col] = None
                advance_column_reinforcement(state, col)
                line_changed = True
        else:
            if not line_changed:
                # If no tactical retreat allowed:
                # Collapsed units, OR healthy units with no operational targets, move to normal retreat list
                if is_collapsed or not target_has_operational_units:
                    state.retreat_list.append(unit.uid)
                    state.front_line[col] = None
                    advance_column_reinforcement(state, col)
                    line_changed = True

    # Pass 2: Centripetal Gap Closing (0x0059B09B..0x0059B0D1)
    # edx goes from 1 to 28 (representing columns in front line)
    for edx in range(1, 29):
        if edx < 15:  # Left wing: shifts inward to the right
            if state.front_line[edx] is None and state.front_line[edx - 1] is not None:
                state.front_line[edx] = state.front_line[edx - 1]
                state.front_line[edx - 1] = None
        else:  # Right wing: shifts inward to the left
            if state.front_line[edx] is None and state.front_line[edx + 1] is not None:
                state.front_line[edx] = state.front_line[edx + 1]
                state.front_line[edx + 1] = None
