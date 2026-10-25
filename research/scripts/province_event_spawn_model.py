"""Reference model for province event spawn and dispatch logic (0x0088D6B0)."""

def lcg_step(seed: int) -> int:
    return (seed * 0x343FD + 0x269EC3) & 0xFFFFFFFF

def compute_province_event_spawn(seed: int, delay: int, event_id: int, province_id: int, registry_has_event: bool):
    """
    Simulates CProvinceEventEffect::Execute (0x0088D6B0).
    Returns (next_seed, roll, action, action_args).
    """
    s1 = lcg_step(seed)
    s2 = lcg_step(s1)
    r1 = (s1 >> 16) & 0x7FFF
    r2 = (s2 >> 16) & 0x7FFF
    roll = r1 * r2
    next_seed = s2

    if not registry_has_event:
        return next_seed, roll, "NONE", {}

    if delay <= 0:
        return next_seed, roll, "FIRE_IMMEDIATE", {
            "event_id": event_id,
            "roll": roll,
            "delay": delay,
        }
    else:
        return next_seed, roll, "ENQUEUE_DELAYED", {
            "event_id": event_id,
            "province_id": province_id,
            "delay": delay,
            "roll": roll,
        }
