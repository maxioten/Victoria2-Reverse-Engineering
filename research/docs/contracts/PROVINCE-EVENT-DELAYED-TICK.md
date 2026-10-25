# Procesamiento diario de la cola de eventos provinciales diferidos (`CProvince::ProcessDelayedEvents`)

Perfil `base-game/v2game.exe`, SHA-256
`62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
VA preferidas para base `0x00400000`; RVA = VA − base.

## 1. Bloque objetivo: `0x004B1E16..0x004B1FA5` en `CProvince::DailyUpdate`

Durante la actualización diaria de cada provincia (`CProvince`), el motor procesa el vector de eventos pendientes encolados en `province + 0x384`.

Convención de registros:
- `EDI`: puntero a la instancia `CProvince`.
- `[edi + 0x384]`: inicio del vector de punteros `CDelayedEvent*` (`begin`).
- `[edi + 0x388]`: fin del vector de punteros `CDelayedEvent*` (`end`).

## 2. Bucle de inspección diaria (`0x004B1E20..0x004B1FA0`)

1. **Chequeo de rango iterador**:
   - `cmp eax, [edi + 0x384]; jb 0x4b1fa5`
   - `cmp eax, [edi + 0x388]; jae 0x4b1fa5`
2. **Lectura y decremento de temporizador (`0x004B1E3E..0x004B1E4A`)**:
   - Lee la entrada: `ebx = *iter`.
   - `dec dword ptr [ebx + 0x54]`: decrementa el contador en días restantes.
   - `cmp dword ptr [ebx + 0x54], 0`.
   - Si `delay > 0` (`jg 0x4b1e20`): continúa el recorrido; el evento permanece esperando.
3. **Disparo de evento expirado (`0x004B1F0A..0x004B1F13`)**:
   - Si `delay <= 0`:
     - Prepara contexto y carga payload de instancia en `[ebx + 0x0C]`.
     - Invoca `0x008A8120` (`Event_Fire`), pasando el evento en `ECX` y el contexto en la pila.
4. **Remoción y destrucción inmediata (`0x004B1F18..0x004B1FA0`)**:
   - Localiza la posición del elemento en el vector `[edi + 0x384]..[edi + 0x388]`.
   - Desplaza los elementos posteriores con `0x00AAE480` (`memmove`).
   - Decrementa el puntero final del vector: `[edi + 0x388] -= 4`.
   - Invoca el destructor escalar virtual del objeto `CDelayedEvent` (`[ebx]->vtable[0](1)`).
   - Salta de regreso a `0x004B1E20` para procesar el resto de la cola.

> [!NOTE]
> **Asimetría semántica frente a `CCountry`:**
> En `CCountry::DailyUpdate` (`0x0050B5C8`), los eventos a eliminar se acumulan primero en una lista auxiliar `[ebp - 0x5C]` y se borran en una segunda pasada (`0x0050B663`) con `std::vector::erase` (`0x004BE200`), asegurando que todos los eventos pendientes del vector sean evaluados en el tick.
> En `CProvince::DailyUpdate` (`0x004B1E16`), el borrado se realiza *in-situ* mediante `memmove` dentro del mismo bucle. Dado que el puntero iterador `[esp + 0x28]` ya fue incrementado en `+4` antes del borrado (`0x004B1E43`), el elemento desplazado a la posición actual es saltado en ese tick y procesado en el día siguiente.

## 3. Verificación empírica

* **Reverify**: 25 afirmaciones de instrucciones verificadas para el bucle de recorrido, cotas del iterador, decremento `dec [ebx + 0x54]`, llamada a `Event_Fire`, actualización de `[edi + 0x388]` y llamada a destructor virtual.
* **Controles negativos**: comprobación de refutación de operandos alterados e invalidación dependiente.
* **Unicorn Engine**: 21 series de fixtures emulados (vector vacío, eventos esperando con `delay > 1`, eventos expirando con `delay = 1`, eventos múltiples combinados y eventos contiguos saltados por corrimiento in-situ), contrastados contra `province_event_delayed_tick_model.py` con **0 discrepancias**.
