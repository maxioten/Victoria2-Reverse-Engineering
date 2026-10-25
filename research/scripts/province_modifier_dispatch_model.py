"""
Modelo formal en Python del despachador de modificadores provinciales de 8 slots
en CProvince::UpdateModifiers (VA 0x004D3FF5..0x004D4067).
"""


def dispatch_province_modifier(
    current_acc: int,
    modifier_raw: int,
    slot_values: list[int],  # 8 elements corresponding to +0x524 .. +0x540
) -> int:
    """Simula el switch de modificadores y acumulación aditiva en 0x004D3FF5."""
    idx = modifier_raw - 1
    if 0 <= idx <= 7 and idx < len(slot_values):
        return current_acc + slot_values[idx]
    return current_acc
