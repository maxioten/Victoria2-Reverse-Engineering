# Contrato: Cómputo de Fuerza Efectiva y Fuerza Actual de Combatiente Militar (`CCombatant::CalculateEffectiveStrength` y `CCombatant::CalculateTotalCurrentStrength`)

## 1. Identificación y Alcance
- **Binario:** `base-game/v2game.exe` (SHA-256: `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`).
- **Direcciones de las rutinas:**
  - `CCombatant::CalculateEffectiveStrength`: `0x005DC0E0..0x005DC17C` (159 bytes, 60 instrucciones).
  - `CCombatant::CalculateTotalCurrentStrength`: `0x005DC180..0x005DC1F3` (118 bytes, 45 instrucciones).
- **Llamadores confirmados:**
  - `CalculateEffectiveStrength` (`0x005DC0E0`):
    - `0x0059C65C`, `0x0059C66D` en `CCombat::CalculateAttackerStrengthRatio` (`0x0059C630`), evaluando la masa efectiva de atacante y defensor incluyendo transporte/buques de guerra.
    - `0x005A9D66`, `0x005A9D77` en `CCombat::EvaluateEngagementPotential` (`0x005A9D00`).
  - `CalculateTotalCurrentStrength` (`0x005DC180`):
    - `0x005954DC` en `CCombat::CheckMinimumStrengthThreshold` (`0x005954C0`), contrastando la masa de efectivos contra el umbral de batalla `[0x0125F594]`.
    - `0x00785DA0`, `0x00785EB0` en `CCombatView::UpdateStrengthIndicators` (`0x00785D00`), normalizando la fuerza con `/ 1000.0` para visualización en la interfaz.
    - `0x006C352C`, `0x006C355F` en `CProvinceView::UpdateGarrisonStrength` (`0x006C3500`).
    - `0x0085587D` en `CUnitView::UpdateFormationTotal` (`0x00855800`).
- **Convención de llamada:**
  - `0x005DC0E0`: `__stdcall` con 2 argumentos: `arg0 = ArmyNode** pArmyListHead`, `arg1 = int* out_val`. Epílogo `ret 8`.
  - `0x005DC180`: `__stdcall` con 2 argumentos: `arg0 = ArmyNode** pArmyListHead`, `arg1 = int* out_val`. Epílogo `ret 8`. Retorna `eax = out_val`.

---

## 2. Estructura de Memoria y Offsets

### Nodo de Ejército (`ArmyNode`)
- `+0x00`: Puntero a `CArmy` (o `CNavy`)
- `+0x08`: Puntero al siguiente nodo `ArmyNode*`

### Formación Militar (`CArmy`)
- `+0x38`: Puntero a la cabeza de la lista enlazada de subunidades (`SubUnitNode*`)

### Nodo de Subunidad (`SubUnitNode`)
- `+0x00`: Puntero a `CSubUnit` (`CRegiment*` o `CShip*`)
- `+0x08`: Puntero al siguiente `SubUnitNode*`

### Subunidad (`CSubUnit`)
- `+0x00`: Puntero a la tabla virtual (`vtable`)
  - Slot 9 (`+0x24`): `virtual bool IsLand() const`
    - `CRegiment` (`vtable = 0x00DF8884`): `0x00A31490` (`mov al, 1; ret`)
    - `CShip` (`vtable = 0x00E02A64`): `0x0058CFD0` (`xor al, al; ret`)
- `+0x38`: Puntero al descriptor de tipo (`CUnitType*`)
- `+0x3C`: Efectivos actuales / fuerza del regimiento (`current_strength`, `int32`)

### Descriptor de Tipo de Unidad (`CUnitType`)
- `+0x244`: Capacidad / fuerza intrínseca o dotación del buque (`max_strength` / `hull_complement`, `int32`)

---

## 3. Formulación Algorítmica y Matemática

### 1. Inicialización en Punto Flotante
Ambas rutinas inician inicializando el acumulador a cero mediante la multiplicación de constantes de precisión IEEE 754:
$$c_1 = 0.0005 \quad (\text{en } \texttt{0x00E45840})$$
$$c_2 = 1000.0 \quad (\text{en } \texttt{0x00E45660})$$
$$\text{init} = \lfloor c_1 \times c_2 \rfloor = \lfloor 0.5 \rfloor = 0$$
Se escribe `*out_val = 0`. Si `*pArmyListHead == NULL`, la función concluye de forma inmediata.

### 2. Fuerza Efectiva (`CCombatant::CalculateEffectiveStrength`, `0x005DC0E0`)
Itera jerárquicamente sobre la lista de ejércitos $A_k \in \mathcal{L}_{\text{armies}}$ y sus subunidades $U_{k,j} \in A_k$:
$$\text{eff}(U_{k,j}) = \begin{cases} U_{k,j}.\text{strength} & \text{si } U_{k,j}.\text{IsLand}() = \text{true} \\ U_{k,j}.\text{type}.\text{max\_strength} & \text{si } U_{k,j}.\text{IsLand}() = \text{false} \end{cases}$$

$$\text{ArmyStrength}(A_k) = \sum_{j} \text{eff}(U_{k,j})$$
$$\text{TotalEffectiveStrength} = \sum_{k} \text{ArmyStrength}(A_k)$$
Escribe $\text{TotalEffectiveStrength}$ en `*out_val`.

### 3. Fuerza Actual Total (`CCombatant::CalculateTotalCurrentStrength`, `0x005DC180`)
Itera directamente sobre la lista de ejércitos y subunidades sumando sin discriminación polimórfica la fuerza viva actual:
$$\text{TotalCurrentStrength} = \sum_{k} \sum_{j} U_{k,j}.\text{strength}$$
Escribe `*out_val = TotalCurrentStrength` y retorna `eax = out_val`.

---

## 4. Criterio de Evidencia y Verificación
- Verificación estática Reverify de las 105 instrucciones PE32 de ambas rutinas.
- Comprobación de constantes de punto flotante en `0x00E45840` y `0x00E45660`.
- Verificación formal de los métodos virtuales `IsLand()` en `CRegiment` (`0x00A31490`) y `CShip` (`0x0058CFD0`).
- Comprobación de call sites en `CCombat` (`0x0059C65C`, `0x0059C66D`, `0x005954DC`) y `CCombatView` (`0x00785DA0`).
- Control negativo `REFUTED` y control dependiente `INVALIDATED`.
- Emulación dinámica con Unicorn Engine en un espectro exhaustivo de topologías de ejército (listas vacías, regimientos terrestres puros, formaciones navales puras, agrupaciones combinadas y valores límite).
