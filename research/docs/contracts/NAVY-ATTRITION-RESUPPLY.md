# Contrato: Mantenimiento Operativo y Evaluación de Atrición Naval (`CNavy::CalculateSeaAttrition` y `CNavy::EvaluateResupplyNecessity`)

## 1. Identificación y Alcance
- **Binario:** `base-game/v2game.exe` (SHA-256: `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`).
- **Direcciones de las rutinas:**
  - `CNavy::CalculateSeaAttrition`: `0x005D7EC0..0x005D7F6E` (175 bytes, 58 instrucciones).
  - `CNavy::EvaluateResupplyNecessity`: `0x005D8120..0x005D8199` (122 bytes, 36 instrucciones).
- **Vtables asociadas:**
  - `CNavy` slot 31 (`+0x7C`) en `0x00E03048` -> `0x005D7EC0` (`CalculateSeaAttrition`).
  - `CUnit` (`CArmy` y `CNavy`) slot 21 (`+0x54`) en `0x00DF8920` y `0x00E03020` -> `0x005CFE90` (`CalculateAverageSubunitHealthRatio`).
- **Convenciones de llamada:**
  - `CalculateSeaAttrition`: `__thiscall` con puntero `this` en `ecx` (`CNavy*`), argumento de salida `out_attrition` en `[esp + 4]`, retorno en `eax` (`out_attrition`), epílogo `ret 4`.
  - `EvaluateResupplyNecessity`: `__fastcall` con puntero `this` en `eax` (`CNavy*`), 0 argumentos en pila, retorno booleano en `al` (1 = necesita reabastecimiento/reparación, 0 = operativo), epílogo `ret`.

---

## 2. Estructura de Memoria y Offsets

### Formación Naval (`CNavy`)
- `+0x00`: Puntero a vtable (`0x00E02FCC`).
- `+0x40`: Conteo de buques en la flota (`ship_count`, `int32`).
- `+0xB0`: Distancia efectiva a base naval amiga (`supply_distance`, `int32`).
- `+0xDC`: Puntero a la provincia de estacionamiento (`CProvince*`).
- `+0x1BC`: Tiempo transcurrido en alta mar (`time_at_sea`, `int32`).

### Estructura de Parámetros Globales (`CDefines` en `0x012586DC`)
- `+0x20`: Puntero a grupo de defines militares (`MilitaryDefines*`).
- `[defines + 0xF0]`: Periodo de gracia en mar antes de atrición (`naval_grace_period`, `int32` en milésimas).
- `[defines + 0xE4]`: Divisor de alcance base de suministro (`naval_range_divisor`, `int32`).
- `[defines + 0xEC]`: Tasa máxima de atrición naval (`max_naval_attrition`, `int32` en milésimas).

### Objeto Provincia (`CProvince`)
- `+0x118`: Array de punteros a tablas portuarias / de atraque (`PortInfo**`).
- `0x01258720`: Índice de tick temporal / mes actual (`current_tick_idx`, `int32`).
- `[port + 0x20]`: Capacidad / nivel portuario (`int32`).

---

## 3. Formulación Algorítmica y Matemática

### A. Cálculo de Atrición en Alta Mar (`CalculateSeaAttrition`, `0x005D7EC0`)
1. **Verificación de Periodo de Gracia:**
   Recupera el umbral de días en alta mar desde defines:
   $$\text{threshold} = \left\lfloor \frac{\text{naval\_grace\_period}}{1000} \right\rfloor$$
   optimizado con la constante mágica $\texttt{0x10624DD3}$.
   Si $\text{time\_at\_sea} < \text{threshold}$:
   La flota navega sin desgaste logístico; escribe `*out_attrition = 0` y concluye.
2. **Determinación del Factor de Distancia:**
   Si $\text{time\_at\_sea} \ge \text{threshold}$:
   Lee el divisor de alcance $D = [defines + 0xE4]$. Si $D == 0$, asigna ratio de $-1$.
   De lo contrario, evalúa la distancia $R = [navy + 0xB0]$:
   - Si $-1,610,612 \le R \le 2,147,483$: cómputo entero de 32 bits $(R \times 1000) / D$.
   - En caso de posible desbordamiento: producto y división de 64 bits mediante `_allmul` (`0x00AC9F20`) y `_alldiv` (`0x00AC02A0`).
   $$\text{ratio} = \left\lfloor \frac{R \times 1000}{D} \right\rfloor$$
3. **Escalado de Atrición por Tasa Máxima:**
   Calcula el factor de estrés logístico: $\Delta = 1000 - \text{ratio}$.
   Multiplica en 64 bits por la atrición máxima $\text{max\_attr} = [defines + 0xEC]$ y normaliza entre 1000:
   $$\text{attrition} = \left\lfloor \frac{(1000 - \text{ratio}) \times \text{max\_attr}}{1000} \right\rfloor$$
   Escribe en `*out_attrition` y retorna `eax = out_attrition`.

### B. Evaluación de Necesidad de Reabastecimiento (`EvaluateResupplyNecessity`, `0x005D8120`)
1. **Comprobación de Atrición Activa:**
   Invoca virtualmente `this->CalculateSeaAttrition(&attr)` (slot 31, `+0x7C`).
   Si $\text{attr} > 0$, la flota sufre desgaste activo y retorna inmediatamente `true` (`al = 1`).
2. **Comprobación de Entorno Portuario y Fuerza Flotante:**
   Si $\text{attr} \le 0$:
   - Comprueba si la provincia dispone de muelle operativo activo en el tick actual: $[port + 0x20] > 0$.
   - Comprueba si la flota posee al menos un buque: $\text{ship\_count} > 0$.
   - Si no se cumplen ambas condiciones, retorna `false` (`al = 0`).
3. **Comprobación de Daño en Cascos e Integridad:**
   Invoca virtualmente `this->CalculateAverageSubunitHealthRatio(&health)` (slot 21, `+0x54`).
   Recupera la constante de umbral flotante en `0x00E45ADC`: $850.5$.
   Aplica `floor(850.5) = 850` milésimas ($85.0\%$).
   Si $\text{health} < 850$:
   La flota presenta daños estructurales significativos en sus buques y requiere carenado / reparación portuaria; retorna `true` (`al = 1`).
   De lo contrario, retorna `false` (`al = 0`).

---

## 4. Criterio de Evidencia y Verificación
- Verificación estática Reverify:
  - 58 instrucciones de `0x005D7EC0..0x005D7F6E`.
  - 36 instrucciones de `0x005D8120..0x005D8199`.
  - Vtable slot 31 (`+0x7C`) en `CNavy` (`0x00E03048` -> `0x005D7EC0`).
  - Vtable slot 21 (`+0x54`) en `CNavy` y `CArmy` (`0x00E03020` y `0x00DF8920` -> `0x005CFE90`).
  - Constante de división entera `0x10624DD3`.
  - Constante flotante `0x00E45ADC` ($850.5$).
  - Singleton `0x012586DC` (`CDefines`) y global `0x01258720`.
  - Control negativo `REFUTED` e invalidación dependiente `INVALIDATED`.
- Emulación dinámica Unicorn Engine:
  - Flotas dentro y fuera del periodo de gracia de navegación.
  - Distancias cortas, moderadas y lejanas respecto a bases navales.
  - Desbordamientos de rango en 32 bits frente a caminos de 64 bits.
  - Flotas con salud íntegra ($\ge 85\%$) vs flotas averiadas ($< 85\%$) en fondeadero sin discrepancias frente a `navy_attrition_resupply_model.py`.
