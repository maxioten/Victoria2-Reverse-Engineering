# Procesamiento diario de la cola de eventos diferidos (`CCountry::ProcessDelayedEvents`)

Perfil `base-game/v2game.exe`, SHA-256
`62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
VA preferidas para base `0x00400000`; RVA = VA − base.

## 1. Bloque objetivo: `0x0050B5C8..0x0050B696` en `CCountry::DailyUpdate`

Durante el tick diario de cada país (`CCountry::DailyUpdate`, `0x005091A0`), el motor procesa el vector de eventos pendientes encolados en `country + 0x68`.

Convención de registros de entrada en `0x0050B5C8`:
- `EBX`: puntero a la instancia `CCountry`.
- `[ebx + 0x68]`: inicio del vector de punteros `CDelayedEvent*` (`begin`).
- `[ebx + 0x6C]`: fin del vector de punteros `CDelayedEvent*` (`end`).

## 2. Estructura de cada entrada `CDelayedEvent`

Instanciada previamente por `0x00540A70` (`CCountry::AddDelayedEvent`):
- `[edi + 0x00]`: vtable `0x00E2C858` (`.?AVCDelayedEvent@@`).
- `[edi + 0x04]`: tipo de evento (`0x18D` = CountryEvent).
- `[edi + 0x08]`: puntero al evento `CCountryEvent*`.
- `[edi + 0x0C]`: bloque de datos/contexto de instancia.
- `[edi + 0x54]`: contador de días restantes (`delay`, entero con signo de 32 bits).

## 3. Bucle de inspección diaria (`0x0050B5CE..0x0050B661`)

1. **Chequeo de fin de rango**:
   - `cmp eax, [ebx + 0x68]; jb 0x50b663`
   - `cmp eax, [ebx + 0x6c]; jae 0x50b663`
2. **Validación del objetivo (`0x0050B5EF`)**:
   - Invoca `0x008A58C0` pasando el puntero `edi = CDelayedEvent*`.
   - Comprueba `test al, al`.
   - **Objetivo inválido (`AL == 0`, `0x0050B5F4..0x0050B5F6`)**: Salta directamente a `0x0050B5F8` para encolar el evento en la lista de eliminación (`[ebp - 0x5c]`) **sin dispararlo**.
3. **Decremento de temporizador (`0x0050B63C..0x0050B643`)**:
   - `dec dword ptr [edi + 0x54]`
   - `cmp dword ptr [edi + 0x54], 0`
   - Si `delay > 0` (`jg 0x50b5ce`): continúa con el siguiente evento; el evento permanece esperando.
4. **Activación de evento expirado (`0x0050B645..0x0050B65C`)**:
   - Si `delay <= 0`:
     - Prepara contexto con `0x008A6620`.
     - Invoca `0x008A8120` (`CCountryEvent::Fire`), pasando el evento en `ECX` y el contexto en la pila.
     - Salta a `0x0050B5F8` para encolar el nodo en la lista de eliminación.

## 4. Fase de borrado y compactación (`0x0050B663..0x0050B690`)

1. Si la lista temporal de eliminación `[ebp - 0x5C]` no está vacía:
   - Para cada nodo, lee el puntero de evento `edx` y llama a `0x004BE200` (`std::vector::erase`), pasando `eax = &country->delayed_events` y `edx = &event_ptr`.
2. Invoca `0x008601B0` para destruir y liberar la lista temporal.

## 5. Verificación empírica

* **Reverify**: 27 afirmaciones de instrucciones verificadas para el bucle de recorrido, comprobación de fin, test de validez, decremento, bifurcación condicional, llamada a `Fire` y borrado de vector.
* **Controles negativos**: comprobación de rechazo de objetivo erróneo con invalidación dependiente.
* **Unicorn Engine**: 120 fixtures emulados cubriendo vectores vacíos, eventos con retención (`delay > 1`), eventos en el día de disparo (`delay = 1`), eventos vencidos (`delay <= 0`), y eventos con objetivo inválido, contrastados contra `delayed_event_tick_model.py` con **0 discrepancias**.
