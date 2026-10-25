# Contrato: Agregación de Carga Logística Provincial y Presencia de Tropas (`CProvince::CalculateFriendlyTroopStrength` y `CProvince::CalculateTotalTroopStrength`)

## 1. Identificación y Alcance
- **Binario:** `base-game/v2game.exe` (SHA-256: `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`).
- **Direcciones de las rutinas:**
  - `CProvince::CalculateFriendlyTroopStrength`: `0x005DC200..0x005DC297` (149 bytes, 47 instrucciones).
  - `CProvince::CalculateTotalTroopStrength`: `0x005DC2A0..0x005DC322` (128 bytes, 39 instrucciones).
- **Llamadores confirmados:**
  - `0x005D6442` y `0x005D644F` en `CArmy::CalculateSupplyLimit` (`0x005D63E0`), alimentando la carga demográfica de entrada (`base_manpower`) para la intendencia y el límite de suministro territorial.
- **Convención de llamada:**
  - `0x005DC200`: `eax = location_or_country_ref` (con `target_country_id = [eax + 4]`), argumentos en pila `[ebp + 8] = ArmyNode** army_list_head_ptr`, `[ebp + 0xC] = int32* out_strength`. Epílogo `ret 8`. Retorna `eax = out_strength`.
  - `0x005DC2A0`: argumentos en pila `[ebp + 8] = ArmyNode** army_list_head_ptr`, `[ebp + 0xC] = int32* out_strength`. Epílogo `ret 8`. Retorna `eax = out_strength`.

---

## 2. Estructura de Memoria y Offsets

### Objeto `CArmy`
- `+0x00`: Puntero a vtable (`0x00DF88CC` / `0x00DF8944`)
  - `vtable + 0x38`: Método virtual `IsArmyActive()` (retorna 1 si el ejército está activo y operativo, 0 si no)
- `+0x38`: Puntero a la lista enlazada de subunidades (`SubUnitNode*`)
- `+0xC4`: `country_id` (código numérico de país propietario)

### Nodo de Subunidad (`SubUnitNode`)
- `+0x00`: Puntero a `CRegiment`
- `+0x08`: Puntero al siguiente `SubUnitNode*`

### Objeto `CRegiment`
- `+0x3C`: Efectivos humanos actuales (`regiment->strength`, int32)

---

## 3. Formulación Algorítmica y Matemática

### 1. Tropas Amistosas en Territorio Propio (`0x005DC200`)
1. **Inicialización flotante:**
   $$\text{init\_val} = \left\lfloor 0.0005 \times 1000.0 \right\rfloor = 0$$
   Persiste `*out_strength = 0`.
2. **Filtrado por soberanía nacional:**
   Lee `target_country = [eax + 4]`.
   Para cada ejército $A_k$ en la lista provincial:
   - Invoca virtualmente `A_k->IsArmyActive()` (`vtable[14]` / `+0x38`). Si retorna 0, omite el ejército.
   - Si `A_k->country_id != target_country`: omite el ejército (no compite ni satura el suministro territorial patrio).
   - Si coincide: suma los efectivos de todos sus regimientos $\sum_{r \in A_k} r\text{.strength}$ y los acumula en `*out_strength`.
3. Retorna `eax = out_strength`.

### 2. Tropas Totales en Territorio Hostil o Asediado (`0x005DC2A0`)
1. **Inicialización flotante:**
   `*out_strength = 0`.
2. **Saturación total sin distinción de soberanía:**
   Para cada ejército $A_k$ en la lista provincial:
   - Invoca virtualmente `A_k->IsArmyActive()`. Si retorna 0, omite el ejército.
   - Acumula los efectivos de todos sus regimientos $\sum_{r \in A_k} r\text{.strength}$ en `*out_strength` sin filtrar por nacionalidad.
   - En territorio ocupado, hostil o asediado, la totalidad de los contingentes presentes consumen los recursos logísticos de la provincia simultáneamente.
3. Retorna `eax = out_strength`.

---

## 4. Criterio de Evidencia y Verificación
- Verificación estática con Reverify sobre todas las instrucciones en PE32 de `0x005DC200..0x005DC297` (47 instrucciones) y `0x005DC2A0..0x005DC322` (39 instrucciones).
- Verificación de constantes flotantes compartidas en `0x00E45840` y `0x00E45660`.
- Control negativo en target offset desfasado (`REFUTED`).
- Cascada de invalidación dependiente (`INVALIDATED`).
- Emulación dinámica con Unicorn en memoria sintética, cubriendo listas vacías, ejércitos inactivos, mezclas multinacionales amigas y enemigas, regimientos múltiples y contingentes de gran escala con 0 discrepancias frente a `province_troop_strength_model.py`.
