# Contrato Formal: Asignación y Distribución Diaria de Cuotas por Estrato (PROVINCE-PROMOTION-TARGET-ALLOCATION)

- **Binario objetivo:** `base-game/v2game.exe`
- **SHA-256:** `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`
- **Rutina objeto:** `0x004EE150..0x004EE2FB` en `CProvincePromotionBuffer::AllocateTargetQuota` (428 bytes)
- **Llamadores confirmados:**
  - `0x004C1412` en actualización demográfica de estado
  - `0x004D1638` en despacho de cuotas por estrato
  - `0x004EF185` en balance mensual de capacidad
  - `0x005221B0` en el subsistema de producción industrial y asignación de mano de obra
- **Consumidores invocados:**
  - `0x004EE650`: Consumidor de democión por candidato objetivo (`ebx < 0`)
  - `0x004EE780`: Consumidor de promoción por candidato objetivo (`ebx >= 0`)

---

## 1. Mapeo de Parámetros y Registros

| Parámetro | Registro / Offset | Descripción |
|---|---|---|
| `buffer` | `[EBP + 0x08]` | Instancia de `CProvincePromotionBuffer` |
| `pop_type` | `[EBP + 0x0C]` | Objeto de tipo de POP con lista de destinos `[pop_type + 0x118 : 0x11C]` |
| `desired_capacity` | `[EBP + 0x10]` | Capacidad deseada del estrato objetivo (32 bits) |
| `rate_weight` | `[EBP + 0x14 : 0x18]` | Ponderación de tasa de transición demográfica (64 bits) |
| `current_capacity` | `[buffer + 0x48]` | Capacidad actual registrada en el buffer provincial |
| `defines_promo` | `[defines + 0x64]` | Define de promoción base (`1000 = 100%`) |
| `defines_demote` | `[defines + 0x68]` | Define de degradación base (`1000 = 100%`) |

---

## 2. Lógica Algorítmica y Reglas de Clamping

1. **Cálculo de Delta y Salida Temprana:**
   $$\Delta = \text{desired\_capacity} - \text{current\_capacity}$$
   Si $\Delta == 0$ o $\text{rate\_weight} == 0$, retorna sin distribuir cuotas.

2. **Paso Diario de Promoción ($\Delta \ge 0$):**
   - Razón preliminar en punto fijo:
     $$\text{raw\_step} = \frac{(\Delta \ll 15) \times \text{rate\_weight}}{2^{30}}$$
   - Normalización del factor por define provincial:
     $$\text{norm\_def} = \left\lfloor \frac{\text{defines\_promo} \ll 30}{32,768,000} \right\rfloor$$
     $$\text{scaled\_step} = \frac{(\text{current\_capacity} \ll 15) \times \text{norm\_def}}{2^{30}}$$
   - **Clamping de Paso Mínimo:** La cuota diaria es de al menos 50 POPs (`max(50, scaled_step)`).
   - **Clamping de Techo Delta:**
     $$\text{total\_quota} = \min(\Delta, \max(\text{raw\_step}, \max(50, \text{scaled\_step})))$$

3. **Paso Diario de Democión ($\Delta < 0$):**
   - Amortiguación por factor 4 y normalización con `defines_demote` (`+0x68`).
   - Clamping de cota inferior a un mínimo de $-50$ POPs y acotación superior a $\Delta$.

4. **Distribución Secuencial a Objetivos Candidatos:**
   Para cada objetivo $i$ en `pop_type->candidates`:
   - Capacidad disponible del objetivo: $C_i = \text{buffer}->\text{available}[ \text{target}_i.\text{slot} ]$.
   - Asignación efectiva: $A_i = \min(\text{remaining\_quota}, C_i)$.
   - Descuenta $A_i$ de $\text{remaining\_quota}$ e invoca al consumidor correspondiente (`0x004EE780` para promoción, `0x004EE650` para democión).
   - Termina inmediatamente si $\text{remaining\_quota} == 0$.

---

## 3. Criterio de Verificación

1. **Reverify Estático:**
   - 170 aserciones de instrucciones cubriendo la rutina completa de 428 bytes y los 4 llamadores confirmados.
   - Control negativo contra objetivo erróneo con veredicto `REFUTED`.
   - Control dependiente con invalidación formal `INVALIDATED`.
2. **Emulación Dinámica en Unicorn:**
   - Contrastación del modelo formal en Python `province_target_quota_model.py` contra la ejecución nativa en Unicorn.
   - Fixtures exhaustivos cubriendo deltas positivos, negativos, nulos, clamping de 50 POPs, tasas parciales y distribución multi-objetivo con saturación intermedia.
