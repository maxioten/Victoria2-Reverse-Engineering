# Contrato: Proporción Relativa de Fuerza del Atacante (`CCombat::CalculateAttackerStrengthRatio`)

## 1. Identificación y Alcance
- **Binario:** `base-game/v2game.exe` (SHA-256: `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`).
- **Dirección de la rutina:** `0x0059C460..0x0059C51B` (188 bytes, 79 instrucciones).
- **Vtable slot 6 (`+0x18`):**
  - `0x00E02160`: `CCombat` (`vtable + 0x18`).
  - `0x00E02370`: `CLandCombat` (`vtable + 0x18`).
  - `0x00E023E0`: `DerivedCombat` (`vtable + 0x18`).
- **Convención de llamada:** `__thiscall` con `ecx = pCombat`, argumento en pila `[esp + 4]` puntero a `int32` de salida (`int *out_ratio`). Retorno en `eax` con el puntero `out_ratio`, epílogo `ret 4`.

---

## 2. Descripción Funcional y Algorítmica

Calcula la proporción normalizada en milésimas ($[0, 1000]$) que representa el contingente militar atacante sobre la masa total de combate:

1. **Umbral de Estabilidad Numérica:**
   - Carga el valor flotante de configuración en `0x00F141C8` ($1.5$).
   - Aplica truncamiento inferior (`floor` en `0x00401000` y `_ftol2` en `0x00B31C00`) fijando el umbral mínimo en $\text{min\_threshold} = 1$.

2. **Extracción y Clamping de Fuerzas Individuales:**
   - Invoca el método virtual `GetTotalRawStrength` (slot 10, `+0x28`) sobre el atacante (`[pCombat + 0x10]`) obteniendo `raw_attacker_strength`.
   - Invoca el método virtual `GetTotalRawStrength` (slot 10, `+0x28`) sobre el defensor (`[pCombat + 0x14]`) obteniendo `raw_defender_strength`.
   - Aplica instrucción de movimiento condicional `cmovl` garantizando que ninguna fuerza sea evaluada por debajo de 1 hombre:
     $$\text{att} = \max(1, \text{raw\_attacker\_strength})$$
     $$\text{def} = \max(1, \text{raw\_defender\_strength})$$

3. **Cálculo de Proporción y Bifurcación Aritmética:**
   - Suma total: $\text{total} = \text{att} + \text{def}$.
   - Si $\text{total} == 0$: escribe `*out_ratio = -1` y retorna.
   - Si $\text{total} > 0$:
     - Evalúa el límite seguro de 32 bits: $\text{check} = (\text{att} + \text{0x189373}) \le \text{0x39580D}$ ($\text{att} \le 2,147,482$).
     - **Camino de 32 bits (`imul` / `idiv`):**
       $$\text{ratio} = \left\lfloor \frac{\text{att} \times 1000}{\text{total}} \right\rfloor$$
     - **Camino de 64 bits (`_allmul` / `_alldiv`):**
       $$\text{ratio} = \left\lfloor \frac{\text{att}_{64} \times 1000}{\text{total}_{64}} \right\rfloor$$
   - Escribe el resultado en `*out_ratio = ratio` y retorna el puntero `eax = out_ratio`.

---

## 3. Criterio de Evidencia y Verificación
- Verificación estática con Reverify sobre todas las 79 instrucciones en PE32 de `0x0059C460..0x0059C51B`.
- Verificación de slots de vtable (`bytes_at`) en `CCombat`, `CLandCombat` y `DerivedCombat`.
- Verificación de la constante flotante en `0x00F141C8`.
- Control negativo en target offset desfasado (`REFUTED`).
- Cascada de invalidación dependiente (`INVALIDATED`).
- Emulación dinámica con Unicorn en memoria sintética, cubriendo fuerzas pequeñas, paridad 50/50, asimetría extrema (999/1), y desbordamiento en el camino de 64 bits con 0 discrepancias frente a `combat_attacker_ratio_model.py`.
