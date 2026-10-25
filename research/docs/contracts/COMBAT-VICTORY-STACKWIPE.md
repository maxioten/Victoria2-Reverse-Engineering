# Contrato: Determinación de Victoria, Retirada y Aniquilación Total / Stackwipe (`CCombat::EvaluateVictoryAndStackwipe`)

## 1. Identificación y Alcance
- **Binario:** `base-game/v2game.exe` (SHA-256: `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`).
- **Dirección de la rutina:** `0x0059C630..0x0059C8A7` (632 bytes, 197 instrucciones).
- **Vtable Slot:** Slot 11 (`+0x2C`) en las tres tablas polimórficas de combate:
  - `CCombat`: `0x00E02174` (base `0x00E02148`).
  - `CLandCombat`: `0x00E02384` (base `0x00E02358`).
  - `CNavalCombat`: `0x00E02464` (base `0x00E02438`).
- **Puntos de llamada identificados (xrefs):**
  - `0x0059AF34` en `CLandCombatant::PruneAndConsolidateLine` (evaluación de conclusión de batalla).
  - `0x005954F0` y `0x005990E0` en rutinas de avance y resolución de turnos de combate.
- **Convención de llamada:**
  - Registro `ecx`: puntero al combate (`this` = `CCombat*`).
  - Pila:
    - `[esp + 4]`: umbral de ratio de aniquilación/arrollamiento (`ratio_threshold`, ej. 10 para 10:1).
    - `[esp + 8]`: bandera de verificación de retirada (`check_can_retreat_flag`, byte booleano).
  - Retorno en registro `al`: `1` si la batalla ha concluido (victoria/aniquilación), `0` si el combate prosigue.
  - Epílogo: `ret 8` (limpieza de 8 bytes de argumentos en pila).

## 2. Descripción Funcional y Flujo de Ejecución
La rutina modela el desenlace decisivo de cualquier batalla (terrestre o naval) en Victoria II:

1. **Agregación de Fuerzas:**
   - Invoca a `0x005DC0E0` para sumar la fuerza total operativa del bando atacante (`attacker_strength` en `[esp + 0x14]`).
   - Invoca a `0x005DC0E0` para sumar la fuerza total operativa del bando defensor (`defender_strength` en `[esp + 0x10]`).

2. **Evaluación de Quebranto Moral del Defensor:**
   - Consulta el estado de moral del defensor mediante llamada virtual `pDefender->HasOperationalUnits()` (`vtable[0x58]`).
   - Si el defensor no tiene unidades operativas o su moral colapsó (`al == 0`):
     - **Regla del Stackwipe 2:1:** Divide la fuerza del atacante entre 2 mediante división mágica (`0x10624DD3` con shift aritmético de 39 bits o llamada a `_alldiv` con divisor `0x7D0` = $2000$):
       $$\text{att\_half} = \left\lfloor \frac{\text{attacker\_strength}}{2} \right\rfloor$$
     - Si $\text{att\_half} > \text{defender\_strength}$ (es decir, el atacante supera al defensor en proporción superior a 2:1) **O** la provincia no ofrece vía de escape (`retreat_province_id == -1`, ejército cercado o en isla):
       $$\text{defender\_strength} = 0 \quad (\textbf{Aniquilación Total / Stackwipe})$$

3. **Evaluación Simétrica de Quebranto Moral del Atacante:**
   - Consulta la moral del atacante mediante `pAttacker->HasOperationalUnits()` (`vtable[0x58]`).
   - Si el atacante no tiene unidades operativas (`al == 0`):
     - Comprueba si $\lfloor \text{defender\_strength} / 2 \rfloor > \text{attacker\_strength}$ o si `retreat_province_id == -1`:
       $$\text{attacker\_strength} = 0 \quad (\textbf{Aniquilación Total / Stackwipe})$$

4. **Comprobación de Elegibilidad de Victoria:**
   - Si $\text{attacker\_strength} > 0$ y $\text{defender\_strength} == 0$, el atacante es elegible para la victoria (`attacker_eligible = 1`).
   - Si $\text{defender\_strength} > 0$ y $\text{attacker\_strength} == 0$, el defensor es elegible para la victoria (`defender_eligible = 1`).

5. **Compuerta de Victoria Decisiva y Arrollamiento:**
   - **Para el Atacante:**
     - Si `check_can_retreat` está activo, consulta si el defensor puede retirarse mediante `pDefender->CanRetreat()` (`vtable[0x54]`).
     - Calcula la cuota de arrollamiento:
       $$\text{quota} = \left\lfloor \frac{\text{attacker\_strength} \times 1000}{\text{ratio\_threshold} \times 1000} \right\rfloor = \left\lfloor \frac{\text{attacker\_strength}}{\text{ratio\_threshold}} \right\rfloor$$
     - Si $\text{quota} > \text{defender\_strength}$ y `attacker_eligible == 1`:
       - Aplica bajas de derrota final a defensores (`0x00595660`).
       - Concluye la batalla registrando la victoria del atacante (`0x005A0180` con `winner = 0`).
       - Finaliza listas de participantes (`0x00595760`) y retorna `al = 1`.
   - **Para el Defensor:**
     - Simétricamente, si $\lfloor \text{defender\_strength} / \text{ratio\_threshold} \rfloor > \text{attacker\_strength}$ y `defender_eligible == 1`:
       - Concluye la batalla registrando la victoria del defensor (`0x005A0180` con `winner = 1`) y retorna `al = 1`.

6. **Continuación del Combate:**
   - Si ningún bando cumple las condiciones de victoria o aniquilación, retorna `al = 0` y la batalla continúa al día siguiente.

## 3. Criterio de Evidencia y Verificación
- Catálogo de 197 afirmaciones Reverify cubriendo cada instrucción de `0x0059C630..0x0059C8A7`.
- Afirmaciones de los 3 slots de vtable (`0x00E02174`, `0x00E02384`, `0x00E02464`).
- Control negativo contrastado (`REFUTED`).
- Cascada de invalidación dependiente (`INVALIDATED`).
- Emulación dinámica con Unicorn en memoria sintética verificando batallas en curso, stackwipes 2:1, cercos sin retirada (`-1`), arrollamientos 10:1 y victorias de atacante/defensor con 0 discrepancias frente a `combat_victory_stackwipe_model.py`.
