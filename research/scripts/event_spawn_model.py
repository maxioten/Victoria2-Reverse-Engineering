"""Reference model for event spawn and dispatch logic (0x0088D370)."""

def lcg_step(seed: int) -> int:
    return (seed * 0x343FD + 0x269EC3) & 0xFFFFFFFF

def compute_event_spawn(seed: int, delay: int, event_id: int, tag_index: int, registry_has_event: bool):
    """
    Simulates CCountryEventEffect::Execute (0x0088D370).
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
            "tag_index": tag_index,
            "delay": delay,
            "roll": roll,
        }
