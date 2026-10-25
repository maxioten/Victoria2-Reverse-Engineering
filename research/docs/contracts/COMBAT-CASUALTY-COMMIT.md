# Contrato: Aplicación Diaria de Bajas y Desglose de Pérdidas de Combate (`CCombatant::CommitCasualtiesAndMoraleLoss` y `CCombatant::CommitCasualtiesByUnitType`)

## 1. Identificación y Alcance
- **Binario:** `base-game/v2game.exe` (SHA-256: `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`).
- **Direcciones de las rutinas:**
  - `CCombatant::CommitCasualtiesAndMoraleLoss`: `0x005DC330..0x005DC3BD` (141 bytes, 46 instrucciones).
  - `CCombatant::CommitCasualtiesByUnitType`: `0x005DC3C0..0x005DC45B` (155 bytes, 49 instrucciones).
- **Llamadores confirmados:**
  - `0x00595E71` y `0x00595F12` en el ciclo de resolución diaria de batalla (`CCombat::ResolveDailyCasualtiesAndMoraleLoss`).
- **Convención de llamada:**
  - `0x005DC330`: argumentos en pila `[ebp + 8] = ArmyNode** pArmyListHead`, `[ebp + 0xC] = int32* out_total_loss`. Epílogo `ret 8`. Retorna `eax = out_total_loss`.
  - `0x005DC3C0`: argumentos en pila `[ebp + 8] = ArmyNode** pArmyListHead`, `[ebp + 0xC] = int32* out_type_loss`, `[ebp + 0x10] = UnitTypeFilter* pFilter` (con `category = [pFilter + 0x24]`). Epílogo `ret 0xC`. Retorna `eax = out_type_loss`.

---

## 2. Estructura de Memoria y Offsets

### Objeto `CRegiment`
- `+0x00`: Puntero a vtable
- `+0x38`: Puntero al tipo de regimiento (`CUnitType*`)
- `+0x3C`: Efectivos humanos actuales (`regiment->strength`, int32)
- `+0x40`: Organización / Moral actual (`regiment->morale`, int32 en milésimas)
- `+0x6C`: Acumulador de bajas pendientes del día (`pending_casualties`, int32)
- `+0x70`: Acumulador de pérdida moral pendiente del día (`pending_morale_loss`, int32)

### Objeto `CUnitType`
- `+0x24`: Identificador numérico de categoría de unidad (`unit_category_id`, int32: e.g. Infantería, Caballería, Artillería)

---

## 3. Formulación Algorítmica y Matemática

### 1. Aplicación General de Bajas (`0x005DC330`)
1. **Inicialización flotante:**
   `*out_total_loss = floor(0.0005 * 1000.0) = 0`.
2. **Iteración sobre ejércitos y subunidades:**
   Para cada ejército $A_k$ y para cada regimiento $R_{k,j} \in A_k$:
   - Invoca a `CRegiment::CommitCombatDamage` (`0x005C0160`):
     - Acota las bajas para evitar efectivos negativos:
       $$\text{eff\_cas} = \min(R\text{.strength}, R\text{.pending\_casualties})$$
       $$R\text{.strength} \leftarrow R\text{.strength} - \text{eff\_cas}$$
     - Acota y descuenta la pérdida moral:
       $$\text{eff\_mor} = \min(R\text{.morale}, R\text{.pending\_morale\_loss})$$
       $$R\text{.morale} \leftarrow R\text{.morale} - \text{eff\_mor}$$
     - Limpia los acumuladores diarios a cero:
       $$R\text{.pending\_casualties} = 0, \quad R\text{.pending\_morale\_loss} = 0$$
   - Acumula $\text{eff\_cas}$ en la suma provincial total:
     $$\text{*out\_total\_loss} \mathrel{+}= \text{eff\_cas}$$
3. Retorna `eax = out_total_loss`.

### 2. Desglose Filtrado por Tipo de Unidad (`0x005DC3C0`)
1. **Inicialización flotante:**
   `*out_type_loss = 0`.
2. **Filtrado por categoría:**
   Lee la categoría objetivo en `target_category = [pFilter + 0x24]`.
   Para cada regimiento $R_{k,j}$:
   - Comprueba su categoría: `reg_category = [R->type + 0x24]`.
   - Si $\text{reg\_category} == \text{target\_category}$:
     Aplica el daño vía `0x005C0160` y suma sus bajas al subtotal del tipo:
     $$\text{*out\_type\_loss} \mathrel{+}= \text{eff\_cas}$$
   - Si no coincide: el regimiento se omite intacto.
3. Retorna `eax = out_type_loss`.

---

## 4. Criterio de Evidencia y Verificación
- Verificación estática con Reverify sobre todas las instrucciones en PE32 de `0x005DC330..0x005DC3BD` (46 instrucciones) y `0x005DC3C0..0x005DC45B` (49 instrucciones).
- Puntos de llamada en `CCombat` (`0x00595E71` y `0x00595F12`).
- Constantes flotantes compartidas en `0x00E45840` y `0x00E45660`.
- Control negativo en target offset desfasado (`REFUTED`).
- Cascada de invalidación dependiente (`INVALIDATED`).
- Emulación dinámica con Unicorn en memoria sintética, cubriendo ejércitos vacíos, regimientos sin daño, saturación por encima de la fuerza actual (clamping), filtros por categoría coincidente y no coincidente con 0 discrepancias frente a `combat_casualty_commit_model.py`.
