# Contrato: Límite de Suministro Provincial de Ejércitos (`CArmy::CalculateSupplyLimit`)

## 1. Identificación y Alcance
- **Binario:** `base-game/v2game.exe` (SHA-256: `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`).
- **Dirección de la función:** `0x005D63E0..0x005D6574` (404 bytes, 125 instrucciones).
- **Vtable asociada:** `CArmy` slot 30 en `0x00DF8944` (vtable base `0x00DF88CC`, offset `+0x78`).
- **Convención de llamada:** `__thiscall` con puntero `this` en `ecx` (`CArmy*`), argumento de salida `out_limit` en `[esp + 4]`, retorno en `eax` (`out_limit`), epílogo `ret 4`.

## 2. Descripción Funcional
Calcula la capacidad de abastecimiento o límite máximo de suministro de un ejército en su provincia actual:
1. **Comprobación de movimiento/retirada forzada:**
   Si `[army + 0x164] != 0` (la unidad está en retirada forzada o movimiento táctico rápido),
   escribe `*out_limit = 0` inmediatamente y retorna.
2. **Determinación de base territorial amistosa vs hostil:**
   - Si la provincia está controlada por el mismo país propietario (`province->controller_id == army->country_id`),
     el ejército no está bajo asedio (`[army + 0x74] == 0`) y no está trabado en combate (`[army + 0x104] == 0`),
     invoca `0x005DC200` para obtener la base amistosa completa (`friendly_base`).
   - Si no se cumplen todas las condiciones anteriores (territorio hostil, ocupado, asediado o en combate),
     invoca `0x005DC2A0` para obtener la base hostil reducida (`hostile_base`).
3. **Bonificación de rasgo de líder:**
   Si la unidad tiene líder asignado (`army + 0xD8`) y su vtable valida el rasgo (`call [leader_vt + 0x20] != 0`),
   suma el bono de intendencia `[leader->modifier + 0x38]` a la base.
4. **Escalado tecnológico nacional:**
   Recupera el modificador tecnológico de suministro militar en `[country + 0xBCC]->offset + 0x20`.
   Aplica factor en milésimas:
   $$\text{scaled} = \left\lfloor \frac{\text{adjusted\_base} \times (\text{tech\_bonus} + 1000)}{1000} \right\rfloor$$
5. **Penalización por terreno y bonificación de infraestructura:**
   - Evalúa el modificador ambiental/terreno provincial mediante `0x004B3C40`, normalizado con el multiplicador $0x10624DD3$ y escala milésima (`terrain_penalty`).
   - Evalúa el bono de infraestructura provincial mediante `0x004B80B0` escalado a milésimas (`infra_bonus`).
   $$\text{raw\_supply} = \text{scaled} - \text{terrain\_penalty} + \text{infra\_bonus} + \text{base\_buffer}$$
6. **Doble acotación estricta (clamping):**
   - Techo provincial: recupera la capacidad portante máxima de la provincia en `[province + 0x9c]->offset + 0x18`, normalizada a milésimas.
     Aplica instrucción condicional `cmovg ecx, eax` para asegurar $\text{supply} \le \text{province\_cap}$.
   - Piso a cero: si el resultado acumulado es negativo, aplica `xor ecx, ecx` para imponer $\max(0, \text{supply})$.
7. **Bonificación de unidad estacionada:**
   Si la unidad se encuentra estacionada o fortificada (`[army + 0x70] != 0`),
   suma el modificador global de `defines` en `[0x012586DC]->0x20->0xDC`.
8. Persiste el valor final en `*out_limit` y retorna el puntero.

## 3. Criterio de Evidencia y Verificación
- Catálogo de 125 afirmaciones Reverify cubriendo cada instrucción, saltos relativos, offsets y singleton `0x012586DC`.
- Control negativo en target offset desfasado (`REFUTED`).
- Cascada de invalidación dependiente (`INVALIDATED`).
- Emulación dinámica con Unicorn en memoria sintética con 0 discrepancias frente a `army_supply_limit_model.py`.
