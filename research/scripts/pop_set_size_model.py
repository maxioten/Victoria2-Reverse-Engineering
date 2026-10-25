"""
Modelo formal en Python de la rutina CPop::SetSize (VA 0x00955FD0..0x00956054).

Rutina que actualiza el tamaño de un POP, aplica el clamping rígido [0, 2_000_000],
dispara la deducción de cuotas cuando procede (flag_40 != 0 y clamped < tracked_size),
y actualiza el historial de tamaño de dos días ([esi + 0x58] y [esi + 0x5c]).
"""

from dataclasses import dataclass

MAX_POP_SIZE = 2_000_000


@dataclass
class PopState:
    prev_size: int       # offset 0x58
    prev_prev_size: int  # offset 0x5C
    tracked_size: int    # offset 0x60
    flag_40: int         # offset 0x40 en pop_type [esi + 0x68]
    prov_id: int         # offset 0x58 en province [esi + 0x64]


def pop_set_size_model(pop: PopState, new_size: int) -> tuple[PopState, dict]:
    """Simula CPop::SetSize exactamente conforme al desensamblado en 0x00955FD0."""
    # 1. Clamping en rango [0, 2_000_000]
    if new_size < 0:
        clamped = 0
    elif new_size > MAX_POP_SIZE:
        clamped = MAX_POP_SIZE
    else:
        clamped = new_size

    called_promotion = False
    delta_out = 0
    new_tracked_size = pop.tracked_size

    # 2. Despacho por flag_40 del estrato
    if pop.flag_40 == 0:
        new_tracked_size = clamped
    else:
        if clamped < pop.tracked_size:
            delta_out = pop.tracked_size - clamped
            called_promotion = True
            # En la máquina real, 0x004ee550 y 0x004d1020 consumen cuotas
            # y tracked_size no se actualiza en esta rama directa

    # 3. Actualización del historial de tamaño
    old_prev = pop.prev_size
    new_prev_prev = old_prev
    new_prev = clamped
    if old_prev == 0:
        new_prev_prev = clamped

    res_pop = PopState(
        prev_size=new_prev,
        prev_prev_size=new_prev_prev,
        tracked_size=new_tracked_size,
        flag_40=pop.flag_40,
        prov_id=pop.prov_id,
    )

    info = {
        "clamped_size": clamped,
        "delta_out": delta_out,
        "called_promotion": called_promotion,
    }
    return res_pop, info
