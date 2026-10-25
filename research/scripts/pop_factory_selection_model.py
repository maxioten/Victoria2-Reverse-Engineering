"""Consumer's post-search type choice; distinct from the selector inside factory."""
from pop_transfer_model import signed32

def select_factory_type(special,source_level,entries):
    selected=-1
    if special:
        for i,entry in enumerate(entries):
            if entry['predicate'] and not entry['flag3d9'] and signed32(entry['level'])<signed32(source_level):
                selected=i
    return selected
