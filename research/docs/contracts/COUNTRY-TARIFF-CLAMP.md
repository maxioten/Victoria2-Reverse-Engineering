# Contrato Semántico: Doble Acotación y Fijación de Aranceles Nacionales (`CCountry::SetTariffRateAndClamp`)

## 1. Identificación y Alcance
- **Binario:** `base-game/v2game.exe`
- **Hash SHA-256:** `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`
- **Rutina objeto:** `0x00538070..0x00538147` (`CCountry::SetTariffRateAndClamp`, 216 bytes)
- **Llamadores verificados:** `0x00582500` en `CChangeTariffs::Execute` y `0x00524A7B` en `CCountry::DailyUpdate`.
- **Subsistema:** Comercio Exterior / Política Arancelaria y Restricciones de Comercio.

---

## 2. Convención de Llamada y Estructuras de Datos
- **Firma:** `void __thiscall CCountry::SetTariffRateAndClamp(int64_t new_rate)`
- **Registros y Pila:**
  - `ECX`: puntero a la instancia `CCountry` (`this`, preservado en `ESI`).
    - `[country + 0x1440]`: tasa arancelaria efectiva (`tariff_rate_lo`: uint32).
    - `[country + 0x1444]`: tasa arancelaria efectiva (`tariff_rate_hi`: int32).
    - `[country + 0x0A60]`: puntero a la política económica activa (`economic_policy*`).
      - `[economic_policy + 0xE8]`: límite mínimo de aranceles de la política (`min_limit_raw`: int32).
      - `[economic_policy + 0xF0]`: límite máximo de aranceles de la política (`max_limit_raw`: int32).
  - `[ebp + 8]`: parte baja del nuevo arancel solicitado (`new_rate.lo`: uint32).
  - `[ebp + 0xC]`: parte alta del nuevo arancel solicitado (`new_rate.hi`: int32).
  - Retorno: `void` (`ret 8`).

---

## 3. Comportamiento Matemático y Algoritmo

### 3.1. Asignación Preliminar
El motor asigna inmediatamente el valor recibido a los campos de arancel del país:
$$\text{tariff\_rate} = \text{new\_rate}$$

### 3.2. Clamping por Límite Inferior (Piso Arancelario)
1. Lee el límite inferior de la política económica en `[economic_policy + 0xE8]`.
2. Escala el valor a punto fijo mediante desplazamiento aritmético de 30 bits y división con signo entre $32,768,000$ (`0x01F40000 = 1000 \times 32768`) vía `0x00AC02A0` (`__alldiv`):
   $$\text{min\_scaled} = \left\lfloor \frac{\text{min\_limit\_raw} \ll 30}{32,768,000} \right\rfloor$$
3. Realiza una comparación con signo de 64 bits (`cmp edx, ecx; jg; jl; cmp eax, edi; jae`):
   - Si $\text{min\_scaled} \ge \text{tariff\_rate}$:
     $$\text{tariff\_rate} = \text{min\_scaled}$$

### 3.3. Clamping por Límite Superior (Techo Arancelario)
1. Lee el límite superior de la política económica en `[economic_policy + 0xF0]`.
2. Escala el valor a punto fijo con la misma fórmula:
   $$\text{max\_scaled} = \left\lfloor \frac{\text{max\_limit\_raw} \ll 30}{32,768,000} \right\rfloor$$
3. Realiza la comparación con signo de 64 bits:
   - Si $\text{tariff\_rate} \ge \text{max\_scaled}$:
     $$\text{tariff\_rate} = \text{max\_scaled}$$

El valor final acotado queda definitivamente fijado en `[country + 0x1440]` y `[country + 0x1444]`.

---

## 4. Evidencia y Reproducción
- **Suite de verificación:** `research/scripts/verify_country_tariff_clamp.py`
- **Modelo de referencia:** `research/scripts/country_tariff_clamp_model.py`
- **Artefactos generados:** `research/evidence/generated/country-tariff-clamp/`
  - `claims.json`: 45 afirmaciones formales de instrucciones, llamadas y saltos condicionales.
  - `reverify.json`: veredicto `VERIFIED` en las 45 afirmaciones.
  - `negative-controls.json`: control erróneo `REFUTED` y cascada `INVALIDATED`.
  - `emulation.json`: 350 fixtures ejecutados en Unicorn con 0 discrepancias.
- **Reproducción:**
  ```bash
  source research/env.sh
  python research/scripts/verify_country_tariff_clamp.py
  ```
