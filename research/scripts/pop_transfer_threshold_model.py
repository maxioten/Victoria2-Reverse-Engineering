"""
Modelo formal en Python de la transferencia demográfica bilateral y umbral de supervivencia
en CPop::Update (VA 0x009584A6..0x009584FB, 0x0095879C..0x009587F1, 0x00958A5F..0x00958AB4).
"""

from dataclasses import dataclass
from pop_set_size_model import PopState, pop_set_size_model, MAX_POP_SIZE


@dataclass
class TransferResult:
    source_pop: PopState
    target_pop: PopState
    source_acc: int
    target_acc: int
    effective_delta: int
    forced_absorption: bool


def pop_transfer_threshold_model(
    source_pop: PopState,
    target_pop: PopState,
    source_acc: int,
    target_acc: int,
    requested_delta: int,
    min_threshold: int,
) -> TransferResult:
    """Simula la lógica bilateral de transferencia y absorción por umbral mínimo."""
    source_size = source_pop.prev_size
    target_size = target_pop.prev_size

    # 1. Evaluación de remanente
    rem = source_size - requested_delta

    # 2. Clamping por umbral mínimo
    forced_absorption = False
    if rem < min_threshold:
        effective_delta = source_size
        forced_absorption = True
    else:
        effective_delta = requested_delta

    # 3. Deducción en origen
    new_source_size = source_size - effective_delta
    updated_source_pop, _ = pop_set_size_model(source_pop, new_source_size)
    delta_source_actual = new_source_size - source_size
    new_source_acc = source_acc + delta_source_actual

    # 4. Incremento en destino
    new_target_size = target_size + effective_delta
    updated_target_pop, _ = pop_set_size_model(target_pop, new_target_size)
    # El acumulador estadístico nativo usa (ebx - old_target_size) == effective_delta
    new_target_acc = target_acc + effective_delta

    return TransferResult(
        source_pop=updated_source_pop,
        target_pop=updated_target_pop,
        source_acc=new_source_acc,
        target_acc=new_target_acc,
        effective_delta=effective_delta,
        forced_absorption=forced_absorption,
    )
