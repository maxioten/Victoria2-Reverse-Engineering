# Contrato: Evaluación de Potencia de Combate Efectiva y Calificación Táctica de Subunidades (`CUnitType::CalculateCombatRating` y `CUnit::CalculateEffectiveCombatPower`)

## 1. Identificación y Alcance
- **Binario:** `base-game/v2game.exe` (SHA-256: `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`).
- **Direcciones de las rutinas:**
  - `CUnitType::CalculateCombatRating`: `0x005BDC80..0x005BDD45` (197 bytes, 58 instrucciones).
  - `CUnit::CalculateEffectiveCombatPower`: `0x005D0500..0x005D05E2` (226 bytes, 83 instrucciones).
- **Vtables:**
  - `CArmy` (vtable base `0x00DF88CC`, RTTI COL en `0x00E4B2BC`):
    - Slot 25 (`+0x64` en `0x00DF8930`): `0x005D0500` (`CalculateEffectiveCombatPower`).
  - `CNavy` (vtable base `0x00E02FCC`, RTTI COL en `0x00E5085C`):
    - Slot 25 (`+0x64` en `0x00E03030`): `0x005D0500` (`CalculateEffectiveCombatPower`).
  - `CRegiment` (vtable base `0x00DF8884`):
    - Slot 12 (`+0x30` en `0x00DF88B4`): `0x005BFF80` (`CSubUnit::GetMaxStrength`).
  - `CShip` (vtable base `0x00E02A64`):
    - Slot 12 (`+0x30` en `0x00E02A94`): `0x005BFF80` (`CSubUnit::GetMaxStrength`).
- **Llamadores confirmados:**
  - `CUnitType::CalculateCombatRating` (`0x005BDC80`):
    - `0x005D055B`: `CUnit::CalculateEffectiveCombatPower` (potencia total de formación).
    - `0x005D0346`: `CUnit::CalculateSelectedEffectiveCombatPower` (potencia de subunidades seleccionadas en UI).
    - `0x005D0133`: `CUnit::EvaluateCompositionBalance` (ponderación de eficacia táctica).
  - `CUnit::CalculateEffectiveCombatPower` (`0x005D0500`): invocado a través del slot 25 (`+0x64`) en evaluación de balance estratégico de ejércitos y armadas, estimación de poder militar diplomático e interfaz de órdenes operacionales.
- **Convención de llamada:**
  - `0x005BDC80`: convención por registros: `eax = this` (`CUnitType*`), `edi = out_rating` (`CFixedPoint*`). Retorna `eax = edi`. Epílogo `ret`.
  - `0x005D0500`: `__thiscall` con retorno por puntero oculto: `ecx = this` (`CUnit*`), `[esp + 4]` / `[ebp + 8]` = `out_total` (`CFixedPoint*`). Retorna `eax = out_total`. Epílogo `ret 4`.

---

## 2. Estructura de Memoria y Offsets

### Descriptor de Tipo de Unidad (`CUnitType`)
- `+0x38`: Bandera de tipo auxiliar / desarmado (`uint8 m_bAuxiliary`).
- `+0x39`: Bandera de tipo terrestre (`uint8 m_bIsLand`).
- **Atributos de Unidades Terrestres (`m_bIsLand != 0`):**
  - `+0x228`: Reconocimiento (`int32 m_nReconnaissance`).
  - `+0x22C`: Ataque (`int32 m_nAttack`).
  - `+0x230`: Defensa (`int32 m_nDefense`).
  - `+0x234`: Apoyo (`int32 m_nSupport`).
  - `+0x238`: Disciplina / multiplicador táctico (`int32 m_nDiscipline`).
  - `+0x23C`: Maniobra (`int32 m_nManeuver`).
  - `+0x240`: Asedio (`int32 m_nSiege`).
- **Atributos de Unidades Navales (`m_bIsLand == 0`, `m_bAuxiliary == 0`):**
  - `+0x244`: Potencia de fuego / cañones (`int32 m_nGunPower`).
  - `+0x248`: Resistencia de casco (`int32 m_nHull`).
  - `+0x24C`: Evasión naval (`int32 m_nEvasion`).
  - `+0x250`: Torpedos / alcance de tiro (`int32 m_nTorpedoFire`).
  - `+0x25C`: Blindaje / coraza (`int32 m_nArmor`).

### Formación Militar (`CUnit`, base de `CArmy` y `CNavy`)
- `+0x00`: Vtable (`CArmy` en `0x00DF88CC`, `CNavy` en `0x00E02FCC`).
- `+0x38`: Puntero al primer nodo de subunidades (`SubUnitNode* m_subunits_head`).

### Nodo de Subunidad (`SubUnitNode`)
- `+0x00`: Puntero al regimiento / buque `CSubUnit* subunit`.
- `+0x08`: Siguiente nodo `SubUnitNode* next`.

### Objeto de Subunidad (`CSubUnit`)
- `+0x00`: Vtable (`slot 12` -> `GetMaxStrength`).
- `+0x38`: Puntero a `CUnitType* m_type`.
- `+0x3C`: Fuerza actual en milésimas (`int32 m_nStrength`).

---

## 3. Formulación Algorítmica y Matemática

### 1. Calificación de Combate de Tipo (`CUnitType::CalculateCombatRating`, `0x005BDC80`)
1. **Comprobación de Categoría:**
   - Si `type->m_bIsLand != 0`:
     Totaliza la suma de atributos terrestres:
     $$\text{Sum}_{\text{land}} = \text{recon} + \text{attack} + \text{defense} + \text{support} + \text{maneuver} + \text{siege}$$
     Multiplica por el factor de disciplina y normaliza en 1,000 milésimas:
     $$\text{rating} = \left\lfloor \frac{\text{Sum}_{\text{land}} \times \text{discipline}}{1000} \right\rfloor$$
   - Si `type->m_bIsLand == 0`:
     - Si `type->m_bAuxiliary != 0` (transporte o auxiliar civil):
       $$\text{rating} = 0$$
     - Si `type->m_bAuxiliary == 0` (buque de guerra):
       Calcula el factor de casco y pegada:
       $$\text{BaseFactor} = \text{gun\_power} + \text{hull} + \text{armor}$$
       Calcula el factor tecnológico:
       $$\text{TechFactor} = 1000 + \text{evasion} + \text{torpedo}$$
       (donde $1000$ proviene de $\lfloor (1000.5f) \rfloor$ en `0x00E45998`).
       Normaliza en 1,000 milésimas:
       $$\text{rating} = \left\lfloor \frac{\text{BaseFactor} \times \text{TechFactor}}{1000} \right\rfloor$$
2. Asigna `*out_rating = rating` y retorna `out_rating`.

### 2. Potencia de Combate Efectiva de Formación (`CUnit::CalculateEffectiveCombatPower`, `0x005D0500`)
1. **Inicialización:**
   `*out_total = 0` (evaluado con `floor((0.0 + 0.0005) * 1000.0) = 0`).
2. **Caso Formación Vacía:**
   Si `m_subunits_head == NULL`, retorna inmediatamente 0.
3. **Iteración por Subunidades:**
   Para cada subunidad $i \in \{1, \dots, N\}$:
   - Invoca `subunit_i->m_type->CalculateCombatRating(&rating)` (`0x005BDC80`).
   - Obtiene la fuerza máxima $M_i = \text{subunit}_i\to\text{GetMaxStrength}()$ (slot 12 de vtable).
   - Lee la fuerza actual $H_i = \text{subunit}_i\to\text{m\_nStrength}$.
   - Si $M_i = 0$:
     $\text{health\_ratio}_i = -1$.
   - Si $M_i > 0$:
     - Si $H_i \in [-1610611, 2147482]$ (verificado mediante `[edi + 0x189373] <= 0x39580d`):
       $$\text{health\_ratio}_i = \left\lfloor \frac{H_i \times 1000}{M_i} \right\rfloor$$
     - De lo contrario, evalúa mediante `_allmul` y `_alldiv` de 64 bits.
   - Pondera la calificación táctica por la ratio de fuerza:
     $$\text{power}_i = \left\lfloor \frac{\text{health\_ratio}_i \times \text{rating}_i}{1000} \right\rfloor$$
   - Acumula: $\text{total\_power} \mathrel{+}= \text{power}_i$.
4. Escribe `*out_total = total_power` y retorna `out_total`.

---

## 4. Reconstrucción en Pseudocódigo C++

```cpp
CFixedPoint* CUnitType::CalculateCombatRating(CFixedPoint* out_rating) {
    if (this->m_bIsLand != 0) {
        int64_t stat_sum = (int64_t)this->m_nReconnaissance +
                           this->m_nAttack +
                           this->m_nDefense +
                           this->m_nSupport +
                           this->m_nManeuver +
                           this->m_nSiege;
        int64_t product = stat_sum * this->m_nDiscipline;
        out_rating->m_value = (int32_t)(product / 1000);
        return out_rating;
    }

    if (this->m_bAuxiliary != 0) {
        out_rating->m_value = 0;
        return out_rating;
    }

    // Buque de guerra
    int64_t base_factor = (int64_t)this->m_nGunPower + this->m_nHull + this->m_nArmor;
    int64_t tech_factor = 1000 + this->m_nEvasion + this->m_nTorpedoFire;
    out_rating->m_value = (int32_t)((base_factor * tech_factor) / 1000);
    return out_rating;
}

CFixedPoint* __thiscall CUnit::CalculateEffectiveCombatPower(CFixedPoint* out_total) {
    *out_total = CFixedPoint(0.0f);
    SubUnitNode* node = this->m_subunits_head;
    if (node == nullptr) {
        return out_total;
    }

    while (node != nullptr) {
        CSubUnit* subunit = node->subunit;
        node = node->next;

        CFixedPoint rating_fp;
        subunit->m_type->CalculateCombatRating(&rating_fp);

        CFixedPoint max_str_fp;
        subunit->GetMaxStrength(&max_str_fp, 0);
        int32_t max_str = max_str_fp.m_value;
        int32_t current_str = subunit->m_nStrength;

        int32_t health_ratio;
        if (max_str == 0) {
            health_ratio = -1;
        } else {
            if ((uint32_t)(current_str + 0x189373) <= 0x39580d) {
                health_ratio = (int32_t)(((int64_t)current_str * 1000) / max_str);
            } else {
                health_ratio = (int32_t)(__alldiv(__allmul(current_str, 1000), max_str));
            }
        }

        int32_t effective_power = (int32_t)(((int64_t)health_ratio * rating_fp.m_value) / 1000);
        out_total->m_value += effective_power;
    }

    return out_total;
}
```

---

## 5. Casos de Borde y Comportamientos Críticos
1. **Formación militar vacía:**
   Retorna exactamente 0.
2. **Subunidad naval auxiliar / transporte:**
   Su calificación de combate es idénticamente 0, aportando 0 a la potencia de combate independientemente de su salud o tonelaje de casco.
3. **Subunidad con fuerza viva cero:**
   Si $\text{current\_strength} = 0$, $\text{health\_ratio} = 0$, resultando en $\text{power} = 0$ (no contribuye al poder efectivo).
4. **Subunidad corrupta con fuerza máxima cero:**
   $\text{health\_ratio} = -1$, evitando la división por cero y aplicando una penalización centinela proporcional a la calificación del tipo.
5. **Rango de 64 bits:**
   Para ejércitos masivos o parámetros modificados por encima de 2,147,482, la conmutación a `_allmul` y `_alldiv` evita desbordamientos de 32 bits.

---

## 6. Criterio de Verificación de Evidencia
- **Verificación Estática:**
  - 58 instrucciones verificadas formalmente en `0x005BDC80..0x005BDD45`.
  - 83 instrucciones verificadas formalmente en `0x005D0500..0x005D05E2`.
  - Slots 25 en vtables de `CArmy` (`0x00DF8930`) y `CNavy` (`0x00E03030`).
  - Slot 12 en `CShip` (`0x00E02A94`) y `CRegiment` (`0x00DF88B4`).
  - Constantes de punto flotante en `0x00E45840` (0.0005), `0x00E45660` (1000.0) y `0x00E45998` (1000.5).
  - Puntos de llamada y límites de desbordamiento entero.
  - Control negativo con aserción errónea refutada (`REFUTED`) y cascada dependiente invalidada (`INVALIDATED`).
- **Verificación Dinámica:**
  - Emulación completa en Unicorn Engine contrastada contra `unit_combat_power_model.py` sobre al menos 50 fixtures heterogéneos de regimientos terrestres, buques de guerra, buques auxiliares y formaciones compuestas con 0 discrepancias.
