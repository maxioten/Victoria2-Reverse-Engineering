# Contrato: Avance de Refuerzos y Despliegue de Segunda Línea (`CLandCombatant::AdvanceReinforcementLine`)

## 1. Identificación y Alcance
- **Binario:** `base-game/v2game.exe` (SHA-256: `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`).
- **Direcciones de las rutinas:**
  - `0x0059B0E0..0x0059B14B` (108 bytes, 33 instrucciones): `CLandCombatant::AdvanceColumnReinforcement`.
  - `0x0059B150..0x0059B180` (49 bytes, 18 instrucciones): `CLandCombatant::AdvanceReinforcementLine`.
- **Puntos de llamada (xrefs):**
  - Invocado diariamente para ambos bandos en `CCombat::DailyUpdate` (`0x0059CAE5` para atacante, `0x0059CAEC` para defensor).
- **Convención de llamada:**
  - `0x0059B150`: `this` en `edi` (`CLandCombatant*`), epílogo `ret`.
  - `0x0059B0E0`: `this` en `eax` (`CLandCombatant*`), índice de columna en `ecx`, epílogo `ret`.

## 2. Descripción Funcional
Modela la dinámica táctica por la cual las unidades situadas en la segunda línea (`back_line[30]` en `[this + 0xEC]`) avanzan para cubrir bajas o huecos en la primera línea (`front_line[30]` en `[this + 0x6C]`):

1. **Secuencia de barrido desde el centro hacia los flancos (`0x0059B150`):**
   - Recorre las 30 columnas tácticas mediante la fórmula alternante:
     $$\text{col}_k = 16 + (-1)^k \cdot \left\lfloor \frac{k + 1}{2} \right\rfloor$$
   - Orden exacto de evaluación:
     $$16 \to 15 \to 17 \to 14 \to 18 \to 13 \to 19 \to 12 \to \dots \to 30 \to 1$$
   - Invoca `0x0059B0E0` para cada columna `col`.

2. **Avance condicional de columna (`0x0059B0E0`):**
   - Lee el regimiento en `back_line[col] = [this + col*4 + 0xEC]`. Si es nulo (`0`), retorna inmediatamente.
   - **Caso 1: Hueco frontal directo:**
     Si `front_line[col] == 0`:
     - El regimiento avanza directamente: `front_line[col] = regimiento`.
     - Se limpia la posición de retaguardia: `back_line[col] = 0`. Retorna.
   - **Caso 2: Frente ocupado — Discriminación por rol de Artillería/Soporte:**
     Si `front_line[col] != 0`:
     - Accede a la definición de tipo de regimiento en `[regimiento + 0x38]`.
     - Lee el atributo de soporte en `[type + 0x23C]`.
     - **Regla Victoria II:** Si $\text{support} > 0$ (Artillería / Ingenieros), **la unidad permanece en la segunda línea** disparando con bonificación y no avanza a posiciones de flanco.
   - **Caso 3: Frente ocupado — Maniobra de flanco para Infantería/Caballería ($\text{support} \le 0$):**
     - Evalúa primero el flanco derecho $\text{col} + 1$:
       Si $0 \le \text{col} + 1 < 30$ y `front_line[col + 1] == 0`:
       - Avanza al flanco derecho: `front_line[col + 1] = regimiento`, `back_line[col] = 0`. Retorna.
     - En caso contrario, evalúa el flanco izquierdo $\text{col} - 1$:
       Si $0 \le \text{col} - 1 \le 30$ y `front_line[col - 1] == 0`:
       - Avanza al flanco izquierdo: `front_line[col - 1] = regimiento`, `back_line[col] = 0`. Retorna.
     - Si ambos flancos adyacentes están ocupados, el regimiento permanece en `back_line[col]`.

## 3. Criterio de Evidencia y Verificación
- Catálogo de 51 afirmaciones Reverify cubriendo las dos rutinas contiguas `0x0059B0E0` y `0x0059B150`.
- Afirmaciones de los puntos de llamada diarios en `0x0059CAE5` y `0x0059CAEC`.
- Control negativo contrastado (`REFUTED`).
- Cascada de invalidación dependiente (`INVALIDATED`).
- Emulación dinámica con Unicorn en memoria sintética con 0 discrepancias frente a `combat_reinforcement_model.py`.
