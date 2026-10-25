# Contrato: Selección y Adquisición de Objetivos Tácticos por Maniobra (`CLandCombatant::FindTargetRegiment`)

## 1. Identificación y Alcance
- **Binario:** `base-game/v2game.exe` (SHA-256: `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`).
- **Dirección de la rutina:** `0x0059B610..0x0059B779` (364 bytes, 132 instrucciones).
- **Puntos de llamada identificados (xrefs):**
  - `0x0059A927` en `CLandCombatant::ExecuteRegimentAttack` (disparo y asignación de bajas).
  - `0x0059B01F` y `0x0059B588` en rutinas de evaluación y proyección táctica.
- **Convención de llamada:** Registro `eax` con el alcance de maniobra del regimiento (`maneuver`), pila con argumentos `target_combatant` en `[esp + 4]` y columna del atacante `col` en `[esp + 8]`, retorno en `eax` con el puntero al regimiento objetivo (`CRegiment*` o `NULL`), epílogo `ret 8`.

## 2. Descripción Funcional
Modela el algoritmo de adquisición de objetivos en combate terrestre mediante 4 fases jerárquicas estrictas:

1. **Criterio de Unidad Operativa:**
   Un regimiento enemigo es elegible como objetivo si y solo si:
   - Su fuerza actual es $\ge 100$ soldados:
     $$\text{strength} \ge \lfloor 100.5 \rfloor = 100 \quad (\text{constante en } 0x00E45A18)$$
   - Su organización actual es $\ge 1.000$ milésimas ($1.0$ de organización mínima para no estar en desbandada):
     $$\text{organization} \ge 1000$$

2. **Fase 1: Objetivo Frontal Directo:**
   - Comprueba la casilla enemiga en primera línea directamente opuesta: `front_line[col]` en `[target_combatant + col*4 + 0x6C]`.
   - Si la columna $0 \le \text{col} \le 30$ contiene una unidad operativa, la selecciona inmediatamente como objetivo y retorna.

3. **Fase 2: Barrido Frontal por Maniobra (Flanqueo de Primera Línea):**
   - Si el frente directo está desocupado o destruido, escanea el rango de flanqueo:
     $$c \in [\max(0, \text{col} - \text{maneuver}), \min(30, \text{col} + \text{maneuver})]$$
   - Itera de izquierda a derecha en `front_line[c]`.
   - Selecciona el primer regimiento operativo encontrado dentro del radio de maniobra y retorna.

4. **Fase 3: Objetivo Directo en Retaguardia (Perforación a Artillería):**
   - Si toda la primera línea enemiga dentro del radio de maniobra ha colapsado o está vacía:
   - Comprueba la casilla enemiga en segunda línea directamente opuesta: `back_line[col]` en `[target_combatant + col*4 + 0xEC]`.
   - Si contiene una unidad operativa, la selecciona y retorna.

5. **Fase 4: Barrido de Flanco en Retaguardia:**
   - Si el frente y la retaguardia directa están vacíos, escanea la segunda línea enemiga:
     $$c \in [\max(0, \text{col} - \text{maneuver}), \min(30, \text{col} + \text{maneuver})]$$
   - Itera en `back_line[c]` seleccionando el primer regimiento operativo.

6. **Fase 5: Sin Objetivo al Alcance:**
   - Si no se encuentra ninguna unidad operativa en ninguna de las 4 fases, retorna `0` (`NULL`) y el atacante no inflige bajas en esa ronda.

## 3. Criterio de Evidencia y Verificación
- Catálogo de 132 afirmaciones Reverify cubriendo cada instrucción de `0x0059B610..0x0059B779`.
- Afirmaciones de los 3 puntos de llamada en el binario (`0x0059A927`, `0x0059B01F`, `0x0059B588`).
- Control negativo contrastado (`REFUTED`).
- Cascada de invalidación dependiente (`INVALIDATED`).
- Emulación dinámica con Unicorn en memoria sintética verificando las 4 fases y casos de fallo con 0 discrepancias frente a `combat_target_acquisition_model.py`.
