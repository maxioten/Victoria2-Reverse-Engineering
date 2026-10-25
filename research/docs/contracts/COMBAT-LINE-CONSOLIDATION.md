# Contrato: Poda de Regimientos Quebrantados y Compactación Centrípeta de Línea (`CLandCombatant::PruneAndConsolidateLine`)

## 1. Identificación y Alcance
- **Binario:** `base-game/v2game.exe` (SHA-256: `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`).
- **Dirección de la rutina:** `0x0059AEF0..0x0059B0D9` (490 bytes, 157 instrucciones).
- **Punto de llamada identificado (xref):** `0x0059ACD4` en el preámbulo de la fase de combate diario (`CLandCombatant::DailyCombatPhase`).
- **Convención de llamada:**
  - Registro `eax`: puntero al combatiente terrestre (`this` = `CLandCombatant*`).
  - Argumento en pila: `[esp + 4]` puntero al combatiente objetivo (`pTargetCombatant`).
  - Epílogo: `ret 4` (limpieza de 4 bytes en pila).

## 2. Descripción Funcional y Flujo de Ejecución
La rutina garantiza el mantenimiento topológico de la línea de batalla tras las bajas y la pérdida de moral:

1. **Barrido Alternante del Centro a los Flancos:**
   - Itera sobre las 30 columnas tácticas mediante la secuencia alternante:
     $$\text{col}_k = 16 + (-1)^k \cdot \left\lfloor \frac{k + 1}{2} \right\rfloor \quad \implies \quad 16 \to 15 \to 17 \to 14 \to 18 \dots \to 30 \to 1$$
   - Consulta el regimiento desplegado en `front_line[col]` (`[edi + col*4 + 0x6C]`).

2. **Detección de Colapso Moral y Físico:**
   - Comprueba la condición de operatividad del regimiento:
     - Fuerza menor a 100 soldados:
       $$\text{strength} < 100 \quad (\text{comparación con floor}(100.5) \text{ en } 0x00E45A18)$$
     - Organización menor a 1.000 milésimas (1.0 de moral mínima):
       $$\text{organization} < 1000$$

3. **Enrutamiento a Listas de Retirada / Desbandada:**
   - Consulta la función virtual `CCombat::IsTacticalRetreatAllowed` (`[pCombat]->vtable[0x2C]`):
     - **Vía A (Retirada táctica permitida):**
       El regimiento quebrado se desvincula de la primera línea (`front_line[col] = NULL`) y se enlaza como nodo de 16 bytes a la lista de unidades desbandadas (`routed_list` en `[edi + 0x17C]`, cola `0x180`, contador `0x184`).
     - **Vía B (Retirada táctica prohibida):**
       Si la bandera de cambio de línea no ha sido activada, evalúa la existencia de objetivos operativos mediante `CLandCombatant::FindTargetRegiment` (`0x0059B610`). Si no hay objetivos y la unidad colapsó, se transfiere a la lista de retirada estándar (`retreat_list` en `[edi + 0x16C]`, cola `0x170`, contador `0x174`).
   - Tras liberar la casilla frontal, invoca inmediatamente a `CLandCombatant::AdvanceColumnReinforcement` (`0x0059B0E0`) para que la artillería o infantería de la segunda línea intente ocupar la vacante.

4. **Despliegue de Reservas Generales:**
   - Tras completar el barrido de las 30 columnas, invoca a `CLandCombatant::DeployFromReserve` (`0x0059B190`), movilizando reservas de la fuerza general hacia los frentes activos.

5. **Compactación Centrípeta de Brechas (Gap Closing Loop):**
   - Itera sobre las columnas interiores $\text{col} \in [1, 28]$:
     - **Flanco Izquierdo ($1 \le \text{col} < 15$):**
       Si la casilla actual está vacía (`front_line[col] == NULL`) y su vecina exterior izquierda está ocupada (`front_line[col - 1] != NULL`), desplaza la unidad hacia la derecha (hacia el centro):
       $$\text{front\_line}[\text{col}] = \text{front\_line}[\text{col} - 1], \quad \text{front\_line}[\text{col} - 1] = \text{NULL}$$
     - **Flanco Derecho ($15 \le \text{col} < 29$):**
       Si la casilla actual está vacía (`front_line[col] == NULL`) y su vecina exterior derecha está ocupada (`front_line[col + 1] != NULL`), desplaza la unidad hacia la izquierda (hacia el centro):
       $$\text{front\_line}[\text{col}] = \text{front\_line}[\text{col} + 1], \quad \text{front\_line}[\text{col} + 1] = \text{NULL}$$
   - Este deslizamiento centrípeto elimina los huecos en la formación de batalla y garantiza que los regimientos permanezcan concentrados en torno a la columna central (columna 15-16).

## 3. Criterio de Evidencia y Verificación
- Catálogo de 157 afirmaciones Reverify cubriendo cada instrucción de `0x0059AEF0..0x0059B0D9`.
- Afirmación del punto de llamada en `0x0059ACD4`.
- Control negativo contrastado (`REFUTED`).
- Cascada de invalidación dependiente (`INVALIDATED`).
- Emulación dinámica con Unicorn en memoria sintética verificando el ciclo completo de detección de colapso, ascenso de refuerzos y deslizamiento centrípeto de huecos con 0 discrepancias frente a `combat_line_consolidation_model.py`.
