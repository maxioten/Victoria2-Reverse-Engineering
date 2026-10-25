"""Reference model for country delayed event queue processing (0x0050B5C8..0x0050B696)."""
from dataclasses import dataclass
from typing import List, Tuple

@dataclass
class DelayedEventEntry:
    event_id: int
    delay: int
    is_valid: bool
    event_ptr: int = 0

def process_delayed_events_tick(events: List[DelayedEventEntry]) -> Tuple[List[int], List[int], List[DelayedEventEntry]]:
    """
    Simulates the daily tick scan over country->delayed_events (country + 0x68).
    
    Returns:
        fired_events: list of event_ids fired on this tick (delay reached <= 0)
        discarded_events: list of event_ids removed without firing (invalid target)
        remaining_events: list of events still pending for future ticks
    """
    fired = []
    discarded = []
    remaining = []

    for entry in events:
        if not entry.is_valid:
            # 0x0050B5F4: test al, al; je 0x50b5f8 -> enqueue for deletion without firing
            discarded.append(entry.event_id)
        else:
            # 0x0050B63C: dec dword ptr [edi + 0x54]
            new_delay = entry.delay - 1
            if new_delay > 0:
                # 0x0050B643: jg 0x50b5ce -> keep waiting
                remaining.append(DelayedEventEntry(
                    event_id=entry.event_id,
                    delay=new_delay,
                    is_valid=True,
                    event_ptr=entry.event_ptr
                ))
            else:
                # 0x0050B65C: call Event_Fire -> fire and delete
                fired.append(entry.event_id)

    return fired, discarded, remaining
