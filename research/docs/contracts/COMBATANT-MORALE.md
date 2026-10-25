# Contrato: Ponderación de Moral Media y Organización Máxima de Combatiente (`CCombatant::CalculateAverageMorale` y `CCombatant::CalculateAverageMaxMorale`)

## 1. Identificación y Alcance
- **Binario:** `base-game/v2game.exe` (SHA-256: `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`).
- **Direcciones de las rutinas:**
  - `CCombatant::CalculateAverageMorale`: `0x005DC630..0x005DC6FD` (206 bytes, 70 instrucciones).
  - `CCombatant::CalculateAverageMaxMorale`: `0x005DC710..0x005DC7B2` (163 bytes, 59 instrucciones).
- **Llamadores confirmados:**
  - `0x00785B1B` en `CCombatView::UpdateMoraleProgress` (`0x00785B00`), invocando `CalculateAverageMorale` para obtener la moral viva del combatiente.
  - `0x00785B2E` en `CCombatView::UpdateMoraleProgress` (`0x00785B00`), invocando `CalculateAverageMaxMorale` para obtener la moral máxima teórica y calcular la ratio porcentual para la barra visual de combate.
- **Convención de llamada:**
  - `0x005DC630`: `__stdcall` con 2 argumentos: `arg0 = ArmyNode** pArmyList`, `arg1 = int* out_val`. Epílogo `ret 8`. Retorna `eax = out_val`.
  - `0x005DC710`: `__cdecl` con registro `eax = ArmyNode** pArmyList`, y argumento en pila `[esp + 4] = int* out_val`. Epílogo `ret 4`. Retorna `eax = out_val`.

---

## 2. Estructura de Memoria y Offsets

### Nodo de Ejército (`ArmyNode`)
- `+0x00`: Puntero a la formación militar `CArmy` (o `CNavy`)
- `+0x08`: Puntero al siguiente nodo `ArmyNode*`

### Formación Militar (`CArmy` / `CNavy` derivado de `CUnit`)
- `+0x00`: Puntero a la tabla virtual (`vtable`, `0x00DF88CC` para `CArmy`, `0x00E02FCC` para `CNavy`)
  - Slot 37 (`+0x94`): `virtual int* CalculateAverageMorale(int* out_morale)` (`0x005C8DC0`)
  - Slot 17 (`+0x44`): `virtual int* CalculateMaxMorale(int* out_max_morale)` (`0x005CFA90`)
- `+0x40`: Número de subunidades / buques en la formación (`subunit_count`, `int32`)

---

## 3. Formulación Algorítmica y Matemática

### 1. Inicialización en Punto Flotante
`CCombatant::CalculateAverageMorale` inicializa `*out_val = 0` mediante constante de punto flotante IEEE 754:
$$c_1 = 0.0005 \quad (\text{en } \texttt{0x00E45840})$$
$$c_2 = 1000.0 \quad (\text{en } \texttt{0x00E45660})$$
$$\text{init} = \lfloor c_1 \times c_2 \rfloor = 0$$
`CCombatant::CalculateAverageMaxMorale` inicializa directamente `*out_val = 0` mediante instrucción entera (`mov dword ptr [ebx], 0`).
Si `*pArmyList == NULL`, ambas rutinas retornan `0` inmediatamente.

### 2. Acumulación Ponderada de Moral Viva (`0x005DC630`)
Para cada formación $A_k \in \mathcal{L}_{\text{armies}}$:
1. Lee el recuento de subunidades: $N_k = A_k.\text{subunit\_count}$ (`[A_k + 0x40]`).
2. Invoca el método virtual slot 37 (`+0x94`): $M_k = A_k.\text{CalculateAverageMorale}()$.
3. Multiplica en 64 bits con escalado a milésimas y división segura mediante `_alldiv` (`0x00AC02A0`):
   $$W_k = \left\lfloor \frac{(N_k \times 1000) \times M_k}{1000} \right\rfloor = N_k \times M_k$$
4. Acumula:
   $$\text{SumWeighted} \mathrel{+}= W_k$$
   $$\text{TotalSubunits} \mathrel{+}= N_k$$

### 3. Acumulación Ponderada de Moral Máxima (`0x005DC710`)
De forma análoga, para cada formación $A_k$:
1. $N_k = A_k.\text{subunit\_count}$.
2. Invoca el método virtual slot 17 (`+0x44`): $M^{\max}_k = A_k.\text{CalculateMaxMorale}()$.
3. Multiplica y normaliza con `_alldiv`:
   $$W^{\max}_k = N_k \times M^{\max}_k$$
4. Acumula en $\text{SumWeightedMax}$ y $\text{TotalSubunits}$.

### 4. Normalización Global del Combatiente
Al concluir la iteración sobre todas las formaciones aliadas:
Si $\text{TotalSubunits} == 0$: escribe `*out_val = 0`.
Si $\text{TotalSubunits} > 0$:
Aplica multiplicación de 64 bits (`_allmul` en `0x00AC9F20`) y división entera truncada (`_alldiv` en `0x00AC02A0`):
$$\text{FinalAverageMorale} = \left\lfloor \frac{\text{SumWeighted} \times 1000}{\text{TotalSubunits} \times 1000} \right\rfloor = \left\lfloor \frac{\sum_k (N_k \times M_k)}{\sum_k N_k} \right\rfloor$$

$$\text{FinalAverageMaxMorale} = \left\lfloor \frac{\text{SumWeightedMax} \times 1000}{\text{TotalSubunits} \times 1000} \right\rfloor = \left\lfloor \frac{\sum_k (N_k \times M^{\max}_k)}{\sum_k N_k} \right\rfloor$$

Ambas rutinas escriben el entero resultante en `*out_val` y retornan el puntero `eax = out_val`.

---

## 4. Criterio de Evidencia y Verificación
- Verificación estática con Reverify sobre todas las instrucciones en PE32 de ambas rutinas:
  - `0x005DC630..0x005DC6FD` (70 instrucciones).
  - `0x005DC710..0x005DC7B2` (59 instrucciones).
- Verificación de slots de vtable:
  - Slot 37 (`+0x94`) en `CArmy` (`0x00DF88CC`) y `CNavy` (`0x00E02FCC`): `0x005C8DC0`.
  - Slot 17 (`+0x44`) en `CArmy` (`0x00DF88CC`) y `CNavy` (`0x00E02FCC`): `0x005CFA90`.
- Verificación de call sites en `CCombatView`:
  - `0x00785B1B` -> `0x005DC630`.
  - `0x00785B2E` -> `0x005DC710`.
- Control negativo `REFUTED` y control dependiente `INVALIDATED`.
- Emulación dinámica con Unicorn Engine en un espectro exhaustivo de contingentes:
  - Formaciones vacías.
  - Ejército único con moral variada.
  - Múltiples ejércitos homogéneos y heterogéneos con pesos asimétricos.
  - Ejércitos sin subunidades (`count = 0`).
  - Contingentes masivos con decenas de miles de hombres sin discrepancias frente al modelo analítico Python.
