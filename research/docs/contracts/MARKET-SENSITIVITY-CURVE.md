# Contrato Semántico: Curva de Elasticidad y Sensibilidad de Precios de Mercado

## 1. Identificación y Alcance
- **Binario:** `base-game/v2game.exe`
- **Hash SHA-256:** `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`
- **Rutinas objeto:**
  - `0x00482610..0x0048292B` (`CMarket::CalculateSensitivityMultiplier`): función principal de 795 bytes que toma el ratio oferta/demanda y retorna el factor multiplicador en punto fijo.
  - `0x0048C080..0x0048C0C8` (`CMarket::SensitivitySqrtFallback`): cálculo continuo sub-lineal por raíz cuadrada cuando el ratio excede el umbral máximo de la tabla.
- **Llamador verificado:** `0x00482B65` en el bucle diario de actualización de precios de bienes de mercado mundial.
- **Subsistema:** Formación de Precios / Mercado Mundial (`CMarket::DailyUpdate`).

---

## 2. Convención de Llamada y Estructuras
- **Firma:** `CFixedPoint* __cdecl CMarket::CalculateSensitivityMultiplier(CFixedPoint* out_multiplier, int64_t ratio)`
- **Registros y Pila:**
  - `[ebp + 0x08]`: parte baja del ratio (32 bits, `ratio_low`).
  - `[ebp + 0x0C]`: parte alta del ratio (32 bits con signo, `ratio_high`).
  - `EDI`: puntero al struct de retorno de 8 bytes `CFixedPoint` (`[ebp - 0x70]` en el llamador).
  - Retorno: `EAX = EDI`.
- **Formato numérico:** `CFixedPoint` (escalado a 15 bits fraccionarios, $1.0 = 32768$).

---

## 3. Comportamiento Matemático y Algoritmo

### 3.1. Relación de Entrada (Ratio Oferta/Demanda)
En `0x00482B58`:
$$\text{ratio} = \left\lfloor \frac{\text{supply} \times 32768}{\text{demand}} \right\rfloor$$
Si $\text{demand} \le 0$, el motor salta el cálculo de ajuste de precios para ese bien.

### 3.2. Tabla Escalonada Discreta (Tramos 1 al 13)
Cuando la oferta es baja en relación a la demanda ($\text{ratio} < 21823 \approx 0.666$), el motor aplica factores de elasticidad discretos escalonados para moderar el incremento de precios:

| Tramo | Condición de Ratio | Factor Multiplicador | Factor Flotante Aprox. |
| :---: | :--- | :---: | :---: |
| 1 | $\text{ratio} < 1638$ ($< 0.050$) | $7307$ | $0.2230$ |
| 2 | $\text{ratio} < 2163$ ($< 0.066$) | $8454$ | $0.2580$ |
| 3 | $\text{ratio} < 2720$ ($< 0.083$) | $9437$ | $0.2880$ |
| 4 | $\text{ratio} < 3277$ ($< 0.100$) | $10355$ | $0.3160$ |
| 5 | $\text{ratio} < 3637$ ($< 0.111$) | $10912$ | $0.3330$ |
| 6 | $\text{ratio} < 4096$ ($< 0.125$) | $11567$ | $0.3530$ |
| 7 | $\text{ratio} < 4653$ ($< 0.142$) | $12354$ | $0.3770$ |
| 8 | $\text{ratio} < 5439$ ($< 0.166$) | $13369$ | $0.4080$ |
| 9 | $\text{ratio} < 6554$ ($< 0.200$) | $14647$ | $0.4470$ |
| 10 | $\text{ratio} < 8192$ ($< 0.250$) | $16384$ | $0.5000$ |
| 11 | $\text{ratio} < 10912$ ($< 0.333$) | $18907$ | $0.5770$ |
| 12 | $\text{ratio} < 16384$ ($< 0.500$) | $22938$ | $0.7000$ |
| 13 | $\text{ratio} < 21823$ ($< 0.666$) | $26739$ | $0.8160$ |

### 3.3. Fallback Continuo por Raíz Cuadrada (Tramo 14)
Cuando $\text{ratio} \ge 21823$ ($0.666$), el motor invoca `0x0048C080`:
$$\text{multiplier} = \left\lfloor \sqrt{\frac{\text{ratio}}{32768.0}} \times 32768.0 + 0.5 \right\rfloor$$
- Para equilibrio exacto ($\text{supply} = \text{demand}$, $\text{ratio} = 32768$):
  $$\sqrt{1.0} \times 32768.0 = 32768 \implies \text{multiplier} = 1.0$$
- Para sobreoferta doble ($\text{supply} = 2 \times \text{demand}$, $\text{ratio} = 65536$):
  $$\sqrt{2.0} \times 32768.0 \approx 46341$$

### 3.4. Multiplicación con Precio Base
Posteriormente, en `0x00482B7F`, el factor resultante se multiplica por el precio base del bien (`base_price`):
$$\text{target\_price} = \text{FixedPoint\_Multiply}(\text{multiplier}, \text{base\_price})$$
Este $\text{target\_price}$ es el que luego alimenta la acotación de 1% diario y el clamp de min/max formalizado en `MARKET-PRICE-DELTA.md` y `PRICE-CLAMP.md`.

---

## 4. Requisitos de Entorno de Ejecución (FPU)
- El runtime MSVC de 32 bits opera con el registro de control de FPU (`FPU CW`) en `0x027F` (precisión de 53 bits / double precision, excepciones enmascaradas).
- La conversión en `_ftol2` (`0x00B31C36`) utiliza `fistp` con redondeo por defecto y posterior corrección por signo y acarreo de la mantisa para emular truncamiento hacia cero sin recarga costosa de `fldcw`.
