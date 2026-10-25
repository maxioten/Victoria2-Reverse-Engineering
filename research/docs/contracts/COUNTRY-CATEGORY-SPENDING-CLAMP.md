# Contrato Formal: Doble Acotación Política del Slider de Gasto Nacional (COUNTRY-CATEGORY-SPENDING-CLAMP)

- **Binario objetivo:** `base-game/v2game.exe`
- **SHA-256:** `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`
- **Rutina objeto:** `0x00538070..0x00538147` en `CCountry::SetCategorySpendingSlider` (216 bytes)
- **Llamadores confirmados:**
  - `0x00524A7B` en evaluación presupuestaria de IA/Diaria
  - `0x00582500` en ejecución del comando de UI/Jugador (`CSetSpendingSliderCommand::Execute`)

---

## 1. Mapeo de Registros y Estructuras

| Parámetro / Campo | Registro / Offset | Descripción |
|---|---|---|
| `this` (`CCountry`) | `ESI` | Puntero a la instancia nacional |
| `proposed_slider` | `[EBP + 8 : EBP + 0xC]` | Valor entero de 64 bits con el slider propuesto |
| `ruling_party_policy` | `[ESI + 0xA60]` | Puntero a la política económica del gobierno actual |
| `policy_min_raw` | `[party + 0xE8]` | Límite inferior entero de política de gasto |
| `policy_max_raw` | `[party + 0xF0]` | Límite superior entero de política de gasto |
| `primary_slider` | `[ESI + 0x1440 : ESI + 0x1444]` | Slider nacional de gasto fijado tras clamping (64 bits) |

---

## 2. Lógica Algorítmica y Normalización

1. **Normalización de cotas políticas (30 bits con división de 64 bits):**
   Las cotas políticas se leen como enteros con signo de 32 bits y se escalan mediante división truncada entera `__alldiv` (`0x00AC02A0`):
   $$\text{min\_bound} = \left\lfloor \frac{\text{policy\_min\_raw} \ll 30}{32,768,000} \right\rfloor$$
   $$\text{max\_bound} = \left\lfloor \frac{\text{policy\_max\_raw} \ll 30}{32,768,000} \right\rfloor$$
   Donde $32,768,000 = 32,768 \times 1,000$, normalizando los milésimos porcentuales al espacio de punto fijo de 15 bits del motor.

2. **Acotación inferior (Clamping mínimo):**
   $$\text{step}_1 = \max(\text{proposed\_slider}, \text{min\_bound})$$
   Implementado con comparación completa de 64 bits (`cmp edx, ecx; jg; jl; cmp eax, edi; jae`).

3. **Acotación superior (Clamping máximo):**
   $$\text{final\_slider} = \min(\text{step}_1, \text{max\_bound})$$
   Implementado con comparación de 64 bits y almacenamiento en `[esi + 0x1440 : 0x1444]`.

---

## 3. Criterio de Verificación

1. **Reverify Estático:**
   - 68 aserciones de instrucciones de la rutina `0x00538070` y 2 llamadores clave (`0x00524A7B`, `0x00582500`).
   - Control negativo contra objetivo erróneo con veredicto `REFUTED`.
   - Control dependiente con invalidación formal `INVALIDATED`.
2. **Emulación Dinámica en Unicorn:**
   - Contrastación del modelo formal en Python `country_spending_clamp_model.py` contra la ejecución nativa PE32.
   - Fixtures exhaustivos cubriendo:
     - Valores propuestos dentro del rango permitido (`min <= prop <= max`).
     - Violación de límite inferior (`prop < min`) forzando acotación hacia arriba.
     - Violación de límite superior (`prop > max`) forzando acotación hacia abajo.
     - Sliders propuestos negativos y valores nulos.
     - Casos aleatorios con diversos rangos de políticas de partidos.
