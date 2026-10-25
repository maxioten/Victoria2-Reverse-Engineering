# Contrato: Censo y Clasificación de Subunidades de Formación Militar (`CCombatant::CountRegimentsByFilterObject` y `CCombatant::CountRegimentsByDirectId`)

## 1. Identificación y Alcance
- **Binario:** `base-game/v2game.exe` (SHA-256: `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`).
- **Direcciones de las rutinas:**
  - `CCombatant::CountRegimentsByFilterObject`: `0x005DC050..0x005DC093` (65 bytes, 29 instrucciones).
  - `CCombatant::CountRegimentsByDirectId`: `0x005DC0A0..0x005DC0DF` (63 bytes, 27 instrucciones).
- **Llamadores confirmados:**
  - `0x00786B65`, `0x00786BE3`, `0x00786C67` en `CCombatView::UpdateUnitTypeIcons` (`0x00786A00`), censando regimientos por armas de combate (Infantería, Caballería, Artillería) para los indicadores de batalla.
  - `0x0081FC0D`, `0x0081FC20`, `0x0081FC33`, `0x0081FC46` en `CMilitaryView::UpdateBranchTotals` (`0x0081FB00`), contabilizando divisiones por rama militar en el menú nacional de defensa.
  - `0x008208EC`, `0x008208FC`, `0x0082090C` en `CArmyView::UpdateComposition` (`0x00820800`).
- **Convención de llamada:**
  - `0x005DC050`: `ecx = ArmyNode** pArmyListHead`, argumento en pila `[ebp + 8] = UnitTypeFilter* pFilter` (donde `target_category = [pFilter + 0x24]`). Epílogo `ret 4`. Retorna `eax = matching_count`.
  - `0x005DC0A0`: `ecx = ArmyNode** pArmyListHead`, argumento en pila `[ebp + 8] = int32 target_id`. Epílogo `ret 4`. Retorna `eax = matching_count`.

---

## 2. Estructura de Memoria y Offsets

### Nodo de Ejército (`ArmyNode`)
- `+0x00`: Puntero a `CArmy`
- `+0x08`: Puntero al siguiente `ArmyNode*`

### Objeto `CArmy`
- `+0x38`: Puntero al primer nodo de subunidades (`SubUnitNode*`)

### Nodo de Subunidad (`SubUnitNode`)
- `+0x00`: Puntero a `CRegiment`
- `+0x08`: Puntero al siguiente `SubUnitNode*`

### Objeto `CRegiment`
- `+0x38`: Puntero a `CUnitType`

### Objeto `CUnitType`
- `+0x24`: Categoría de arma / rama militar (`category`, int32: e.g. Infantería=4, Caballería=5, Artillería=6)
- `+0x34`: Identificador numérico directo de tipo (`type_id`, int32)

---

## 3. Formulación Algorítmica y Matemática

### 1. Censo por Objeto Filtro (`0x005DC050`)
1. **Inicialización:**
   `eax = 0` (acumulador global de regimientos coincidentes).
2. **Doble bucle jerárquico:**
   - Itera por los ejércitos $A_k$ enlazados en `*pArmyListHead`.
   - Para cada ejército, itera por sus subunidades $R_{k,j} \in A_k$:
     - Lee la categoría del tipo de unidad: `cat = [R->type + 0x24]`.
     - Si $\text{cat} == \text{filter->category}$:
       $$\text{army\_count} \mathrel{+}= 1$$
   - Acumula en el total global:
     $$\text{total} \mathrel{+}= \text{army\_count}$$
3. Retorna `eax = total`.

### 2. Censo por Identificador Directo (`0x005DC0A0`)
1. **Inicialización:**
   `eax = 0`.
2. **Doble bucle jerárquico:**
   - Itera por los ejércitos $A_k$.
   - Para cada ejército, itera por sus subunidades $R_{k,j}$:
     - Lee el identificador directo: `id = [R->type + 0x34]`.
     - Si $\text{id} == \text{target\_id}$:
       $$\text{army\_count} \mathrel{+}= 1$$
   - Acumula en el total global:
     $$\text{total} \mathrel{+}= \text{army\_count}$$
3. Retorna `eax = total`.

---

## 4. Criterio de Evidencia y Verificación
- Verificación estática con Reverify sobre todas las instrucciones en PE32 de `0x005DC050..0x005DC093` (29 instrucciones) y `0x005DC0A0..0x005DC0DF` (27 instrucciones).
- Verificación de puntos de llamada en `CCombatView` (`0x00786B65`, `0x00786BE3`, `0x00786C67`).
- Control negativo en target offset desfasado (`REFUTED`).
- Cascada de invalidación dependiente (`INVALIDATED`).
- Emulación dinámica con Unicorn en memoria sintética, cubriendo listas vacías, ejércitos sin subunidades, mezclas de infantería, caballería, artillería, filtros sin coincidencias y formaciones masivas con 0 discrepancias frente a `subunit_census_model.py`.
