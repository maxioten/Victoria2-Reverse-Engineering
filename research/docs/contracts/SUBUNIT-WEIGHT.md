# Contrato: Recuento de Subunidades y Cómputo de Peso de Suministro Militar (`CCombatant::CountTotalRegiments`, `CCombatant::CalculateSupplyWeight` y `CArmy::CalculateSupplyWeight`)

## 1. Identificación y Alcance
- **Binario:** `base-game/v2game.exe` (SHA-256: `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`).
- **Direcciones de las rutinas:**
  - `CCombatant::CountTotalRegiments`: `0x005DC560..0x005DC58F` (48 bytes, 18 instrucciones).
  - `CArmy::CalculateSupplyWeight`: `0x005DC590..0x005DC5CB` (60 bytes, 17 instrucciones).
  - `CCombatant::CalculateSupplyWeight`: `0x005DC5D0..0x005DC621` (82 bytes, 29 instrucciones).
- **Llamadores confirmados:**
  - `CountTotalRegiments` (`0x005DC560`):
    - `0x0078F55F` en `CBattleReport::UpdateRegimentCounts` (`0x0078F500`).
    - `0x00791601` en `CCombatView::UpdateSubUnitRoster` (`0x00791500`).
    - `0x005D77E8` en `CArmy::UpdateTotalRegimentCount` (`0x005D7700`).
    - `0x005E428A` en `CCombatant::ValidateOperationalLimits` (`0x005E4200`).
  - `CalculateSupplyWeight` (ejército individual, `0x005DC590`):
    - `0x0084E97B` en `CShipView::CanEmbark` (`0x0084E900`), contrastando la carga de transporte requerida del ejército frente a la capacidad de bodegas navales (`add esi, [ship + 0x98]`).
  - `CalculateSupplyWeight` (combatiente/selección múltiple, `0x005DC5D0`):
    - `0x00828AED` en `CArmyView::UpdateSelectedWeight` (`0x00828A00`).
    - `0x008296ED` en `CArmyView::UpdateTransportFit` (`0x00829600`).
    - `0x00829984` en `CArmyView::ValidateEmbarkSelection` (`0x00829900`).
- **Convención de llamada:**
  - `0x005DC560`: `ecx = ArmyNode** pArmyListHead`, retorna `eax = total_count`. Epílogo `ret`.
  - `0x005DC590`: `eax = SubUnitNode** pSubUnitListHead`, retorna `eax = total_weight`. Epílogo `ret`.
  - `0x005DC5D0`: `eax = ArmyNode** pArmyListHead`, retorna `eax = total_weight`. Epílogo `ret`.

---

## 2. Estructura de Memoria y Offsets

### Nodo de Ejército (`ArmyNode`)
- `+0x00`: Puntero a la formación militar `CArmy`
- `+0x08`: Puntero al siguiente `ArmyNode*`

### Formación Militar (`CArmy`)
- `+0x38`: Puntero a la lista de subunidades del ejército (`SubUnitNode*`)
- `+0x90`: Puntero a la lista de subunidades seleccionadas (`SubUnitNode*`)

### Nodo de Subunidad (`SubUnitNode`)
- `+0x00`: Puntero al regimiento `CSubUnit`
- `+0x08`: Puntero al siguiente `SubUnitNode*`

### Objeto Regimiento / Subunidad (`CSubUnit`)
- `+0x38`: Puntero al descriptor de tipo `CUnitType*` (en contexto de formación general `+0x90`)
- `+0xA4`: Puntero al descriptor de tipo `CUnitType*` (en contexto de subunidad individual de transporte)

### Descriptor de Tipo de Unidad (`CUnitType`)
- `+0x258`: Consumo de suministros / peso de transporte en milésimas (`supply_consumption`, `int32`)

---

## 3. Formulación Algorítmica y Matemática

### 1. Recuento Total de Subunidades (`0x005DC560`)
Itera sobre la lista de formaciones $A_k \in \mathcal{L}_{\text{armies}}$:
$$\text{total} = \sum_{k} |A_k.\text{subunits}|$$
Retorna el número entero de subunidades en `eax`.

### 2. Peso Logístico de Formación Individual (`0x005DC590`)
Itera sobre la lista de subunidades $U_i$:
Para cada una, lee $C_i = U_i.\text{type}.\text{supply\_consumption}$ (`[type + 0x258]`).
Divide por 1000 usando la constante de optimización entera de MSVC:
$$M = \texttt{0x10624DD3} = 274,877,907$$
$$q = \lfloor (C_i \times M) / 2^{32} \rfloor$$
$$\text{weight}_i = \lfloor q / 2^6 \rfloor = \lfloor C_i / 1000 \rfloor$$
Suma acumulada:
$$\text{ArmyWeight} = \sum_{i} \left\lfloor \frac{C_i}{1000} \right\rfloor$$
Retorna `eax = ArmyWeight`.

### 3. Peso Logístico Global del Combatiente (`0x005DC5D0`)
Itera jerárquicamente sobre las formaciones $A_k$ y sus subunidades seleccionadas en `[A_k + 0x90]`:
$$\text{TotalWeight} = \sum_{k} \sum_{U_{k,j} \in A_k} \left\lfloor \frac{U_{k,j}.\text{type}.\text{supply\_consumption}}{1000} \right\rfloor$$
Retorna `eax = TotalWeight`.

---

## 4. Criterio de Evidencia y Verificación
- Verificación estática con Reverify sobre las 64 instrucciones en PE32 de las tres rutinas (`0x005DC560`, `0x005DC590`, `0x005DC5D0`).
- Comprobación de la constante mágica de división por 1000 (`0x10624DD3`).
- Verificación de los 5 call sites en `CBattleReport`, `CCombatView`, `CShipView` y `CArmyView`.
- Control negativo `REFUTED` y control dependiente `INVALIDATED`.
- Emulación dinámica con Unicorn Engine en configuraciones heterogéneas de ejércitos, flotas y subunidades sin discrepancias frente al modelo analítico Python.
