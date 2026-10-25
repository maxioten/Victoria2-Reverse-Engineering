#!/usr/bin/env python3
"""Ground-truth model for CLandCombatant reinforcement advance (0x0059B0E0 & 0x0059B150)."""

def get_column_sweep_sequence() -> list[int]:
    """Return the 30-column center-outward alternating sweep sequence."""
    cols = []
    for k in range(30):
        # k=0 -> col 16; k=1 -> col 15; k=2 -> col 17...
        sign = 1 if (k % 2 == 0) else -1
        delta = (k + 1) // 2
        # x86 implementation:
        # eax = k (0..29)
        # ecx = (k is even ? 1 : 0)
        # esi = k + 1
        # eax = (esi // 2)
        # ecx = (ecx * 2 - 1) * eax + 16
        col = (1 if (k % 2 == 0) else -1) * delta + 16
        cols.append(col)
    return cols

def advance_column(
    front_line: list[int | None],
    back_line: list[int | None],
    support_flags: dict[int, int],
    col: int
) -> None:
    """Advance reinforcement unit in column `col` if possible according to 0x0059B0E0."""
    unit = back_line[col]
    if unit is None:
        return

    # Direct front
    if front_line[col] is None:
        front_line[col] = unit
        back_line[col] = None
        return

    # Front occupied: check support attribute
    is_support = support_flags.get(unit, 0) > 0
    if is_support:
        # Artillery stays in back line
        return

    # Try right flank (col + 1)
    right = col + 1
    if 0 <= right < 30 and front_line[right] is None:
        front_line[right] = unit
        back_line[col] = None
        return

    # Try left flank (col - 1)
    left = col - 1
    if 0 <= left <= 30 and left < len(front_line) and front_line[left] is None:
        front_line[left] = unit
        back_line[col] = None
        return

def advance_reinforcements(
    front_line: list[int | None],
    back_line: list[int | None],
    support_flags: dict[int, int]
) -> tuple[list[int | None], list[int | None]]:
    """Run full reinforcement sweep over all 30 columns according to 0x0059B150."""
    f = list(front_line)
    b = list(back_line)
    for col in get_column_sweep_sequence():
        if col < len(f) and col < len(b):
            advance_column(f, b, support_flags, col)
    return f, b
