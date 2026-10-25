# Contrato Formal: Cálculo de Financiación y Gasto por Categoría (CCountry::CalculateCategorySpending)

- **Binario objetivo:** `base-game/v2game.exe`
- **SHA-256:** `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`
- **Rutina objeto:** `0x00539760..0x00539874` (`CCountry::CalculateCategorySpending`, 181 bytes)
- **Llamadores confirmados:**
  - `0x00539910` (bucle de presupuesto y deducción de tesorería nacional en `CCountry`)
  - `0x00663027` (evaluación de balance de gasto gubernamental)
  - `0x0071DCFE` (simulador presupuestario diario)
  - `0x007205A1` (interfaz y balance fiscal del gabinete)

---

## 1. Convención de Llamada y Estructura en Memoria

- **Convención:** Mixta x86 fastcall/stdcall modificada:
  - `EAX`: puntero a la instancia nacional (`CCountry* this`).
  - `ESI`: puntero al buffer receptor del valor resultante (`int64* out_spending`).
  - `[ebp + 8]`: índice de la categoría de gasto (`uint32 category_index`).
- **Retorno:** `EAX = ESI` (`out_spending`), con limpieza de argumento en el retorno (`ret 4`).
- **Callee-saved:** Preserva fielmente `EBX` y `EDI`.

---

## 2. Parámetros de Entrada y Mapeo de Tablas de 64 bits

| Parámetro | Offset en `CCountry` | Tipo | Descripción |
|---|---|---|---|
| `slider_1` | `[country + 0x1448]` | `int64` | Nivel configurado del slider 1 de gasto |
| `slider_2` | `[country + 0x1450]` | `int64` | Nivel configurado del slider 2 de gasto |
| `slider_3` | `[country + 0x1458]` | `int64` | Nivel configurado del slider 3 de gasto |
| `idx_1` | `[country + category + 0xECC]` | `uint8` | Selector de índice para la tabla base 1 |
| `table_1` | `[country + 0xF0C]` | `int64*` | Array de valores base de gasto primario |
| `idx_2` | `[country + category + 0xF24]` | `uint8` | Selector de índice para la tabla base 2 |
| `table_2` | `[country + 0xF64]` | `int64*` | Array de valores base de gasto secundario |
| `idx_3` | `[country + category + 0xF7C]` | `uint8` | Selector de índice para el subsidio aditivo |
| `table_3` | `[country + 0xFBC]` | `int64*` | Array de subsidios fijos o suplementos base |
| `idx_4` | `[country + category + 0xFD4]` | `uint8` | Selector de índice para la tabla base 4 |
| `table_4` | `[country + 0x1014]` | `int64*` | Array de valores base de mantenimiento de infraestructura |

---

## 3. Lógica Algorítmica y Acotación a Cero

1. **Término Ponderado 1:**
   Multiplica `table_1[idx_1]` por `slider_1` mediante llamada a la CRT de 64 bits `0x00AC9F20` (`__allmul`)
   y escala el punto fijo dividiendo entre $32,768$ ($2^{15}$) mediante desplazamiento aritmético:
   $$\text{term}_1 = \left\lfloor \frac{\text{table}_1[\text{idx}_1] \times \text{slider}_1}{32,768} \right\rfloor$$
2. **Término Ponderado 2:**
   Multiplica `table_2[idx_2]` por `slider_2` y escala entre $32,768$:
   $$\text{term}_2 = \left\lfloor \frac{\text{table}_2[\text{idx}_2] \times \text{slider}_2}{32,768} \right\rfloor$$
3. **Término Aditivo Fijo:**
   Suma directamente el valor base sin aplicar slider:
   $$\text{term}_3 = \text{table}_3[\text{idx}_3]$$
4. **Término Ponderado 3:**
   Multiplica `table_4[idx_4]` por `slider_3` y escala entre $32,768$:
   $$\text{term}_4 = \left\lfloor \frac{\text{table}_4[\text{idx}_4] \times \text{slider}_3}{32,768} \right\rfloor$$
5. **Agregación y Clamping Rígido Inferior a Cero:**
   $$\text{raw\_total} = \text{term}_1 + \text{term}_2 + \text{term}_3 + \text{term}_4$$
   $$\text{final\_spending} = \begin{cases}
   0 & \text{si } \text{raw\_total} \le 0 \\
   \text{raw\_total} & \text{si } \text{raw\_total} > 0
   \end{cases}$$
   *Evidencia:* `0x0053983D test eax, eax; jl 0x53985e; jg 0x539847; test ecx, ecx; je 0x53985e`. Si el total acumulado de 64 bits es menor o igual a cero, salta a `0x0053985E`, donde copia el valor cero inicializado con `xorpd xmm0, xmm0` en `[ebp - 0x14]`, impidiendo que un país genere gastos negativos (ingresos artificiales por déficit de financiación).

---

## 4. Criterio de Verificación

1. **Reverify Estático:**
   - 77 aserciones de instrucciones de código binario contra `base-game/v2game.exe`.
   - Control negativo contra objetivo erróneo con veredicto `REFUTED`.
   - Control dependiente con invalidación formal `INVALIDATED`.
2. **Emulación Dinámica en Unicorn:**
   - Contrastación del modelo exacto en Python `country_category_spending_model.py` contra la ejecución nativa de los 181 bytes en Unicorn.
   - Fixtures exhaustivos que cubren valores positivos, términos negativos que fuerzan total $\le 0$, cero exacto, combinación de sliders extremos y tablas de 64 bits.
