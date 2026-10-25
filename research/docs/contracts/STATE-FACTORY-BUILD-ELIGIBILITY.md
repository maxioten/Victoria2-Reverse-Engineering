# Contrato: Reglas de Elegibilidad y Cupo Máximo de Fábricas Estatales (`CState::CanBuildFactory`)

## 1. Identificación y Alcance
- **Binario:** `base-game/v2game.exe`
- **SHA-256:** `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`
- **Dirección VA:** `0x004D04B0..0x004D0692` (483 bytes, 151 instrucciones)
- **Símbolo inferido:** `CState::CanBuildFactory(CState* state, CBuildingType* factory_type, bool is_ai)`
- **Llamadores confirmados:**
  - `0x0052CAB1` en `CCountry::DecideIndustrialConstruction` (IA nacional de industrialización)
  - `0x0052CB07` en `CCountry::DecideIndustrialConstruction` (IA de reemplazo de fábricas)
  - `0x008575CE` en `CStateView::UpdateFactoryBuildButtons` (interfaz de usuario de construcción provincial/estatal)

---

## 2. Convención de Llamada y Estructura de Objetos
- **Convención:** `__stdcall` con 3 parámetros en la pila (12 bytes limpios por `ret 0xC`):
  - `arg1` (`[ebp + 0x8]`): Puntero al estado (`CState*`).
  - `arg2` (`[ebp + 0xC]`): Puntero al prototipo de fábrica (`CBuildingType*`).
  - `arg3` (`[ebp + 0x10]`): Booleano (`bool is_ai`), indica si la consulta proviene del motor de IA o del jugador humano.
- **Estructura del Estado (`CState`):**
  - `+0x60`: Puntero a la cabeza de la lista enlazada de fábricas construidas en el estado.
  - `+0x68` (DWORD): Número de fábricas actualmente activas o en construcción en el estado.
  - `+0x84` (DWORD): Indicador de estatus colonial o territorio no incorporado (`is_colonial`).
- **Estructura del Nodo de Fábrica (`CFactoryNode`):**
  - `+0x18`: Puntero al tipo de fábrica (`CBuildingType*`).
  - `+0x20` (DWORD): Nivel de ampliación o trabajadores.
  - `+0x224`: Puntero a la siguiente fábrica en la lista enlazada (`m_next`).
- **Estructura del Prototipo de Fábrica (`CBuildingType`):**
  - `+0x58` (DWORD): Grupo industrial o identificador de tipo.
  - `+0xD8` (BYTE): Indicador de requisito costero / astillero.
  - `+0x12C`: Puntero a la tecnología prerrequisito (`CTechnology*`).
  - `+0x13A` (BYTE): Bandera de categoría industrial estratégica A (militar / aprovisionamiento primario).
  - `+0x13B` (BYTE): Bandera de categoría industrial estratégica B (naval / astillero de vapor).

---

## 3. Comportamiento y Reglas Algorítmicas

1. **Restricción colonial rígida:**
   - Lee `[state + 0x84]`.
   - Si `[state + 0x84] > 0`: el estado es una colonia o territorio ocupado. El motor prohíbe taxativamente la industrialización colonial, retornando `0` (`false`) en `0x004D04C8`.

2. **Tope universal de 8 fábricas por estado:**
   - Calcula las plazas restantes:
     $$\text{remaining\_slots} = 8 - [state + 0\text{x}68]$$
   - Si $\text{remaining\_slots} < 1$: el estado ha alcanzado el límite absoluto de 8 industrias. Retorna `0` (`false`).

3. **Restricción de no duplicidad de tipo en el estado:**
   - Recorre la lista enlazada en `[state + 0x60]` mediante el puntero `+0x224`.
   - Si para alguna fábrica existente se cumple:
     $$\text{existing\_node}\to\text{type} == \text{candidate\_factory\_type}$$
   - Retorna `0` (`false`). Victoria II no permite tener dos fábricas del mismo tipo en un mismo estado (deben ampliarse en nivel, no duplicarse).

4. **Reglas heurísticas y reserva de cupo para la IA (`is_ai == true`):**
   - Recorre las fábricas existentes del estado recolectando banderas de especialización:
     - `dl = 1` si alguna fábrica existente tiene `+0x13A != 0`.
     - `bl = 1` si alguna fábrica existente tiene `+0x13B != 0`.
   - Si la candidata posee bandera `+0x13B` y ya existe una en el estado (`bl == 1`), la IA rechaza la duplicación y retorna `0`.
   - Si la candidata posee bandera `+0x13A` y ya existe una en el estado (`dl == 1`), la IA rechaza la duplicación y retorna `0`.
   - **Reserva de últimos 2 slots:** Si $\text{remaining\_slots} \le 2$, la IA reserva estrictamente las últimas plazas para industrias prioritarias (`+0x13A` o `+0x13B`). Cualquier otra industria ordinaria es rechazada (retorna `0`).
   - Si la fábrica requiere costa (`+0xD8 != 0`), invoca `0x004DAD40` para confirmar acceso marítimo.

5. **Prerrequisito tecnológico:**
   - Si `[candidate + 0x12C] != 0`:
     - Invoca `0x004D0E70(state, tech)`. Si el país no ha investigado la tecnología, retorna `0`.
     - Si la tecnología impone requisito de puerto (`[tech + 0x7C] != 0`), invoca `0x004D0FD0(state)`. Si el estado carece de puerto, retorna `0`.

6. **Aprobación final:**
   - Si todas las restricciones son superadas, retorna `1` (`true`) en el registro `al`.

---

## 4. Garantías de Evidencia
- **Reverify:** 154 afirmaciones formales cubriendo las 151 instrucciones de `0x004D04B0..0x004D0692` y los 3 llamadores (`0x0052CAB1`, `0x0052CB07`, `0x008575CE`).
- **Control Negativo e Invalidación en Cascada:**
  - Modificación de la instrucción de entrada en `0x004D04B0` refutada (`REFUTED`).
  - Claim dependiente invalidado (`INVALIDATED`).
- **Emulación Dinámica con Unicorn:**
  - 140+ fixtures contrastando estados coloniales, estados al límite de 8 fábricas (0..8), duplicados en lista enlazada con 0..5 nodos, modo jugador y modo IA, reserva de cupo $\le 2$ slots, y prerrequisitos tecnológicos con 0 discrepancias frente a `state_factory_build_model.py`.
