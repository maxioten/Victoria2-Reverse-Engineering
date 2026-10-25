# Contrato Semántico: Modificador Administrativo del Gasto Nacional (`CCountry::CalculateAdministrativeSpendingModifier`)

## 1. Identificación y Alcance
- **Binario:** `base-game/v2game.exe`
- **Hash SHA-256:** `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`
- **Rutina objeto:** `0x00538150..0x005381F2` (`CCountry::CalculateAdministrativeSpendingModifier`, 163 bytes)
- **Llamadores verificados:** `0x00509F62` y `0x005077C2` en `CCountry::DailyUpdate`.
- **Subsistema:** Administración del Estado / Eficiencia de Gasto Público y Políticas de Gobierno.

---

## 2. Convención de Llamada y Estructuras de Datos
- **Firma:** `int32_t* __thiscall CCountry::CalculateAdministrativeSpendingModifier(int32_t* out_modifier)`
- **Registros:**
  - `ECX`: puntero a la instancia `CCountry` (`this`).
    - `[country + 0xBCC]`: puntero al árbol/contenedor de tecnologías del país.
      - `[tech_container + 0x7C]`: nivel entero de tecnología administrativa/comercial (`tech_val`: int32).
    - `[country + 0x4CC]`: bandera de política/partido gobernante (`ruling_party_flag`: int32).
    - `[country + 0xA48]`: estructura de políticas gubernamentales activas.
    - `[country + 0x12E8]`: contexto extendido del estado.
  - `EDI`: puntero al struct de retorno `int32_t* out_modifier`.
  - Retorno: `EAX = EDI`.

---

## 3. Comportamiento Matemático y Algoritmo

### 3.1. Escalado Tecnológico a Punto Fijo
El valor de tecnología administrativa `[tech_container + 0x7C]` se promueve a 64 bits con desplazamiento de 30 bits a la izquierda:
$$\text{tech\_shifted} = \text{tech\_val} \ll 30$$
Luego se divide con signo mediante `0x00AC02A0` (`__alldiv`) por el divisor escalar estándar de Victoria 2:
$$\text{tech\_fp} = \left\lfloor \frac{\text{tech\_shifted}}{32,768,000} \right\rfloor$$
El resultado de 64 bits se almacena en el frame de stack temporal (`[ebx] = eax`, `[ebx + 4] = edx`).

### 3.2. Selección de Modificador según Política de Gobierno
El motor evalúa la bandera del partido en el poder `[country + 0x4CC]`:
- Si `[country + 0x4CC] > 0`: selecciona el buffer de política A en `[esp + 0x14]`.
- Si `[country + 0x4CC] \le 0`: selecciona el buffer de política B en `[esp + 0x1C]`.
Invoca `0x0096A2C0` (`CCountry::GetPolicyModifier`) pasando el contexto de políticas y el buffer seleccionado, obteniendo el modificador de política de 64 bits `policy_mod`.

### 3.3. Multiplicación Escalar y Desplazamiento
Multiplica el modificador de política por $32,768,000$ (`0x01F40000`) mediante `0x00AC9F20` (`__allmul`):
$$\text{product} = \text{policy\_mod} \times 32,768,000$$
Posteriormente, normaliza el producto desplazando 30 bits aritméticamente a la derecha:
$$\text{final\_modifier} = \text{product} \gg 30$$
El valor resultante se almacena en `[edi]` (`*out_modifier = final_modifier`) y la rutina retorna `EAX = EDI`.

---

## 4. Evidencia y Reproducción
- **Suite de verificación:** `research/scripts/verify_country_admin_modifier.py`
- **Modelo de referencia:** `research/scripts/country_admin_modifier_model.py`
- **Artefactos generados:** `research/evidence/generated/country-admin-modifier/`
  - `claims.json`: 35 afirmaciones formales de instrucciones, llamadas y offsets.
  - `reverify.json`: veredicto `VERIFIED` en las 35 afirmaciones.
  - `negative-controls.json`: control erróneo `REFUTED` y cascada `INVALIDATED`.
  - `emulation.json`: 272 fixtures ejecutados en Unicorn con 0 discrepancias.
- **Reproducción:**
  ```bash
  source research/env.sh
  python research/scripts/verify_country_admin_modifier.py
  ```
