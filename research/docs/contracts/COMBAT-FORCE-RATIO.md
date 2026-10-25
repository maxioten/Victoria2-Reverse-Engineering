# Contrato: Proporción Relativa de Fuerza de Combate (`CCombat::CalculateForceRatio`)

## 1. Identificación y Alcance
- **Binario:** `base-game/v2game.exe` (SHA-256: `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`).
- **Dirección de la función:** `0x0059C460..0x0059C51E` (190 bytes, 79 instrucciones).
- **Vtables asociadas:**
  - `CCombat`: slot 7 en `0x00E02160` (vtable base `0x00E02144`, offset `+0x1C`).
  - `CLandCombat`: slot 7 en `0x00E02370` (vtable base `0x00E02354`, offset `+0x1C`).
  - `CNavalCombat`: slot 7 en `0x00E023E0` (vtable base `0x00E023C4`, offset `+0x1C`).
- **Convención de llamada:** `__thiscall` con puntero `this` en `ecx` (`CCombat*`), argumento de salida `out_ratio` en `[esp + 4]`, retorno de puntero en `eax` (`out_ratio`), epílogo `ret 4`.

## 2. Descripción Funcional
Calcula la cuota proporcional en milésimas ($[0, 1000]$) que representa la fuerza o moral del bando atacante respecto a la suma total de fuerzas de la batalla:
1. **Piso mínimo de combatientes:**
   Evalúa la constante en `0x00F141C8` (float $1.5$) mediante `floor`, determinando un suelo inferior irreducible $\text{min\_floor} = 1$.
2. **Consulta polimórfica de fuerzas:**
   - Atacante (`[this + 0x10]`): invoca el método virtual `slot 10` (`vtable[10]` / `+0x28`) de `CCombatant`, obteniendo `attacker_strength`.
   - Defensor (`[this + 0x14]`): invoca el método virtual `slot 10` (`vtable[10]` / `+0x28`) de `CCombatant`, obteniendo `defender_strength`.
3. **Clamping inferior estricto:**
   Aplica `cmovl` para imponer que ningún bando tenga menos de 1 unidad de fuerza en el cómputo:
   $$A = \max(1, \text{attacker\_strength})$$
   $$D = \max(1, \text{defender\_strength})$$
   $$\text{total} = A + D$$
   Si $\text{total} == 0$, escribe `-1` (`0xFFFFFFFF`) en `*out_ratio` y retorna.
4. **Bifurcación algorítmica por umbral de desbordamiento de 32 bits:**
   Evalúa el desplazamiento no signado:
   $$\text{check} = (A + 1610611) \pmod{2^{32}}$$
   - **Camino rápido de 32 bits ($A \le 2,147,482$):**
     Como $A \times 1000 \le 2,147,482,000 < 2^{31} - 1$, la multiplicación cabe estrictamente en un entero signado de 32 bits.
     Calcula con la instrucción nativa `idiv`:
     $$\text{ratio} = \left\lfloor \frac{A \times 1000}{\text{total}} \right\rfloor$$
   - **Camino seguro extendido de 64 bits ($A > 2,147,482$):**
     Cuando la fuerza del atacante excede $2.147$ millones de unidades, el producto desbordaría `int32`.
     El motor conmuta automáticamente al camino extendido invocando `_allmul` (`0xAC9F20`) y `_alldiv` (`0xAC02A0`):
     $$\text{ratio} = \text{\_alldiv}(A \times 1000, \text{total})$$
5. Escribe el ratio resultante en `*out_ratio` y retorna el puntero.

## 3. Criterio de Evidencia y Verificación
- Catálogo de 79 afirmaciones Reverify cubriendo cada instrucción, saltos relativos, offsets de estructura y constante flotante en `0x00F141C8`.
- Punteros en vtables polimórficas de combate (`CCombat`, `CLandCombat`, `CNavalCombat`).
- Control negativo en target offset desfasado (`REFUTED`).
- Cascada de invalidación dependiente (`INVALIDATED`).
- Emulación dinámica con Unicorn en memoria sintética con 0 discrepancias frente a `combat_force_ratio_model.py`.
