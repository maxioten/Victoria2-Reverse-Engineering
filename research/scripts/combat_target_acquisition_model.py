#!/usr/bin/env python3
"""Ground-truth model for CLandCombatant::FindTargetRegiment (0x0059B610..0x0059B779)."""

def is_regiment_operational(regiment_info: dict | None) -> bool:
    """Return True if the target regiment satisfies strength >= 100 and org >= 1000."""
    if not regiment_info:
        return False
    strength = regiment_info.get('strength', 0)
    org = regiment_info.get('org', 0)
    return strength >= 100 and org >= 1000

def find_target_regiment(
    front_line: list[dict | None],
    back_line: list[dict | None],
    col: int,
    maneuver: int
) -> int | None:
    """Find target enemy regiment according to Victoria II 4-phase hierarchy.
    
    Args:
        front_line: Enemy front line array (up to 31 slots: index 0..30).
        back_line: Enemy back line array (up to 31 slots: index 0..30).
        col: Attacker column index (0..30).
        maneuver: Maneuver flanking distance.
    Returns:
        Index of the target unit in front_line or back_line, or None if no target.
    """
    # Phase 1: Direct front line
    if 0 <= col <= 30 and col < len(front_line):
        if is_regiment_operational(front_line[col]):
            return ('front', col)

    # Phase 2: Flanking scan in front line
    left_bound = col - maneuver
    right_bound = col + maneuver
    for c in range(left_bound, right_bound + 1):
        if 0 <= c <= 30 and c < len(front_line):
            if is_regiment_operational(front_line[c]):
                return ('front', c)

    # Phase 3: Direct back line (artillery)
    if 0 <= col <= 30 and col < len(back_line):
        if is_regiment_operational(back_line[col]):
            return ('back', col)

    # Phase 4: Flanking scan in back line
    for c in range(left_bound, right_bound + 1):
        if 0 <= c <= 30 and c < len(back_line):
            if is_regiment_operational(back_line[c]):
                return ('back', c)

    # Phase 5: No target within range
    return None
