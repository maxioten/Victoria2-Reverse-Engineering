# Contrato Semántico: Recaudación Impositiva e Ingresos Nacionales (`CCountry::CalculateTotalTaxRevenue`)

## 1. Identificación y Alcance
- **Binario:** `base-game/v2game.exe`
- **Hash SHA-256:** `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`
- **Rutina objeto:** `0x0052B780..0x0052B859` (`CCountry::CalculateTotalTaxRevenue`, 122 bytes)
- **Llamador verificado:** `0x008383CF` en el cálculo de presupuesto e ingresos nacionales.
- **Subsistema:** Economía Nacional / Finanzas y Recaudación Fiscal por Estratos Sociales.

---

## 2. Convención de Llamada y Estructuras de Datos
- **Firma:** `int64_t* __stdcall CCountry::CalculateTotalTaxRevenue(CCountry* country)`
- **Pila y Registros:**
  - `[ebp + 8]`: puntero al país (`CCountry*`).
  - `ESI`: puntero implícito struct-return a `int64_t* out_tax_total` (8 bytes).
  - Retorno: `EAX = ESI`.
- **Estructura `CCountry`:**
  - `[country + 0xA0]`: `std::vector<CTaxSetting*>`: vector de punteros a configuraciones impositivas:
    - Índice 0: Clase baja / Pobres (`BUDGET_TAX_POOR`, token `0x874`).
    - Índice 1: Clase media (`BUDGET_TAX_MIDDLE`, token `0x875`).
    - Índice 2: Clase alta / Ricos (`BUDGET_TAX_RICH`, token `0x876`).
  - Cada `CTaxSetting` (120 bytes, vtable `0x00DF8114`):
    - `[tax_setting + 0x60]`: tasa impositiva fijada en slider (`rate_lo`: uint32).
    - `[tax_setting + 0x64]`: tasa impositiva fijada en slider (`rate_hi`: int32).
    - `[tax_setting + 0x48 + edi*8]` con `edi = 1` (global `0x00F0973C`): base imponible de la clase social (`base_lo`: uint32, offset `+0x50`).
    - `[tax_setting + 0x4C + edi*8]` (`base_hi`: int32, offset `+0x54`).
  - `[country + 0x0E0]`: `std::vector<int64_t>` buckets de ingresos del país:
    - Calculado dinámicamente como `((1 + 13) << 4) = 224 = 0x0E0` usando global `0x00F096C8` (= 1).
    - `[country + 0x0E0]`: `buckets.begin`.
    - `[country + 0x0E4]`: `buckets.end`.
    - `count = (end - begin) / 8` (`sar edx, 3`).

---

## 3. Comportamiento Matemático y Algoritmo

### 3.1. Inicialización y Comprobación de Tamaño
El acumulador de salida se pone a cero:
$$\text{out\_tax\_total} = 0$$
Si el vector de buckets está vacío (`count \le 0`), la rutina finaliza inmediatamente retornando 0.

### 3.2. Bucle de Acumulación por Clase Social e Ingresos Fijos
Para cada índice $i$ desde $0$ hasta $\text{count} - 1$:

#### A. Clases Impositivas ($i \in \{0, 1, 2\}$):
1. **Multiplicación de Enteros de 64 bits (`__allmul`):**
   Multiplica la base imponible de la clase por la tasa fijada en el slider mediante `0x00AC9F20` (`__allmul` de MSVC CRT):
   $$\text{product} = \text{base}_i \times \text{rate}_i$$
2. **Alineación de Punto Fijo:**
   Limpia los 15 bits fraccionarios inferiores de la parte baja:
   $$\text{masked\_lo} = \text{product.lo} \ \& \ \text{0xFFFF8000}$$
   $$\text{masked\_product} = (\text{product.hi} \ll 32) \mid \text{masked\_lo}$$
3. **Normalización por Divisor Escalar Nacional (`__alldiv`):**
   Divide con signo mediante `0x00AC02A0` (`__alldiv`) por la constante de 64 bits en `0x00F0AAC8` ($32,768,000 = 1000 \times 32768$):
   $$\text{class\_tax}_i = \left\lfloor \frac{\text{masked\_product}}{32,768,000} \right\rfloor$$
4. **Acumulación:**
   $$\text{out\_tax\_total} = \text{out\_tax\_total} + \text{class\_tax}_i$$

#### B. Ingresos Fijos / Otros Buckets ($i \ge 3$):
Para los índices superiores a las 3 clases impositivas (otros ingresos fiscales fijos, subsidios o rentas provinciales acumuladas en el vector):
$$\text{out\_tax\_total} = \text{out\_tax\_total} + \text{bucket}[i]$$

---

## 4. Evidencia y Reproducción
- **Suite de verificación:** `research/scripts/verify_country_tax_revenue.py`
- **Modelo de referencia:** `research/scripts/country_tax_revenue_model.py`
- **Artefactos generados:** `research/evidence/generated/country-tax-revenue/`
  - `claims.json`: 44 afirmaciones formales de instrucciones y llamadas.
  - `reverify.json`: veredicto `VERIFIED` en las 44 afirmaciones.
  - `negative-controls.json`: control erróneo `REFUTED` y cascada `INVALIDATED`.
  - `emulation.json`: 141 fixtures ejecutados en Unicorn con 0 discrepancias.
- **Reproducción:**
  ```bash
  source research/env.sh
  python research/scripts/verify_country_tax_revenue.py
  ```
