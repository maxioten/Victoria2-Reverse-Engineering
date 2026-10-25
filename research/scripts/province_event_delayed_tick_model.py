"""Reference model for province delayed event queue processing (0x004B1E16..0x004B1FA5)."""
from dataclasses import dataclass
from typing import List, Tuple

@dataclass
class ProvinceDelayedEventEntry:
    event_id: int
    delay: int
    event_ptr: int = 0

def process_province_delayed_events_tick(events: List[ProvinceDelayedEventEntry]) -> Tuple[List[int], List[ProvinceDelayedEventEntry]]:
    """
    Simulates the daily tick scan over province->delayed_events (province + 0x384).
    
    Note on engine semantics:
    Unlike country delayed events which accumulate deletion nodes into a secondary
    list before erasing, CProvince::ProcessDelayedEvents (0x004B1E16) performs an
    immediate inline memmove shift when an event expires, without adjusting the
    running pointer [esp + 0x28]. Thus, the element shifted into the current index
    is skipped on this tick and evaluated on the subsequent day.
    """
    vec = [ProvinceDelayedEventEntry(e.event_id, e.delay, e.event_ptr) for e in events]
    fired = []
    i = 0

    while i < len(vec):
        entry = vec[i]
        new_delay = entry.delay - 1
        entry.delay = new_delay
        if new_delay <= 0:
            fired.append(entry.event_id)
            del vec[i]
            # Pointer was already advanced (add ecx, 4), so the shifted item is bypassed
            i += 1
        else:
            i += 1

    return fired, vec
