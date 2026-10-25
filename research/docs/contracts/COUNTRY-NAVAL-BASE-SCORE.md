# Contrato Formal: Puntuación de Base Naval y Eficiencia Costera (COUNTRY-NAVAL-BASE-SCORE)

- **Binario objetivo:** `base-game/v2game.exe`
- **SHA-256:** `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`
- **Rutina objeto:** `0x0052FCD0..0x00530020` en `CCountry::CalculateNavalBaseScore` (bloque de cálculo `0x0052FF12..0x0052FFB9`)
- **Llamador principal:** `0x0053805D` en el despachador diario de subsistemas nacionales (`0x00538040`)
- **Constante canónica de piso (5%):** `0x00E45820` = `1638.9000244140625` ($0.05 \times 32,768 + 0.5$)
- **Constante canónica de techo (100%):** `0x8000 = 32,768` ($1.0 \times 32,768$)

---

## 1. Mapeo de Registros y Acumulador

| Parámetro / Variable | Registro / Offset | Descripción |
|---|---|---|
| `this` (`CCountry`) | `[EBP + 8]` | Puntero a la instancia nacional |
| `naval_score_accumulator` | `[country + 0x198 : 0x19C]` | Puntuación nacional naval de 64 bits |
| `current_supply` | `[ESP + 0x14]` | Suministro/unidades navales costeras |
| `demand_points` | `[ESP + 0x28]` | Demanda de capacidad/bases requeridas |
| `base_weight` | `[ESP + 0x20 : 0x24]` | Ponderación base de la categoría (64 bits) |
| `floor_constant` | `[0x00E45820]` | Doble precisión: 1638.9000244140625 (5% eficiencia) |
| `ceil_constant` | Inmediato `0x8000` | 32,768 (100% eficiencia en punto fijo 15 bits) |

---

## 2. Lógica Algorítmica y Normalización

1. **Reinicio de acumulador:**
   Si el parámetro `mode` (`[ebp + 0xc]`) es 0, `[country + 0x198 : 0x19C]` se inicializa a 0.
2. **División de centenas mediante multiplicación inversa:**
   Ambos parámetros se dividen por 100 con redondeo hacia cero usando la constante mágica `0x51eb851f`:
   $$c_{14} = \text{trunc}(val_{14} / 100)$$
   $$c_{28} = \text{trunc}(val_{28} / 100)$$
3. **Cálculo de razón en punto fijo de 15 bits:**
   $$\text{num} = c_{14} \ll 30, \quad \text{den} = c_{28} \ll 15$$
   $$\text{ratio} = \left\lfloor \frac{\text{num}}{\text{den}} \right\rfloor \quad (\text{vía } 0\text{x}00\text{AC}02\text{A}0)$$
4. **Doble Acotación [Piso 5%, Techo 100%]:**
   $$\text{ratio}_{\text{clamped}} = \begin{cases}
   1638 & \text{si } \text{ratio} < 1638 \\
   32768 & \text{si } \text{ratio} > 32768 \\
   \text{ratio} & \text{en otro caso}
   \end{cases}$$
5. **Ponderación y Acumulación en 64 bits:**
   $$\text{contrib} = \frac{\text{ratio}_{\text{clamped}} \times \text{base\_weight}}{32,768} \quad (\text{vía } 0\text{x}00\text{AC}9\text{F}20)$$
   $$[country + 0\text{x}198 : 0\text{x}19\text{C}] += \text{contrib}$$

---

## 3. Criterio de Verificación

1. **Reverify Estático:**
   - 72 aserciones de instrucciones binarias y 1 asercion de bytes de la constante `0x00E45820`.
   - Control negativo contra objetivo erróneo con veredicto `REFUTED`.
   - Control dependiente con invalidación formal `INVALIDATED`.
2. **Emulación Dinámica en Unicorn:**
   - Contrastación del modelo formal en Python `country_naval_base_model.py` contra la ejecución nativa en Unicorn.
   - Fixtures exhaustivos cubriendo saturación superior (> 100%), saturación inferior (< 5%), valores intermedios, pesos altos y estados previos del acumulador.
