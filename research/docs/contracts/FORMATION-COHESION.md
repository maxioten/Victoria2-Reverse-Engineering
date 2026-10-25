# Contrato: Evaluación de Cohesión y Ratios Promedio de Fuerza y Moral en Formaciones Militares (`CUnit::CalculateAverageSubunitStrengthRatio` y `CUnit::CalculateAverageSubunitMoraleRatio`)

## 1. Identificación y Alcance
- **Binario:** `base-game/v2game.exe` (SHA-256: `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`).
- **Direcciones de las rutinas:**
  - `CUnit::CalculateAverageSubunitStrengthRatio`: `0x005CFE90..0x005CFF85` (246 bytes, 96 instrucciones).
  - `CUnit::CalculateAverageSubunitMoraleRatio`: `0x005CFF90..0x005D0099` (266 bytes, 103 instrucciones).
- **Vtables:**
  - `CArmy` (vtable base `0x00DF88CC`, RTTI COL en `0x00E4B2BC`):
    - Slot 21 (`+0x54` en `0x00DF8920`): `0x005CFE90` (`CalculateAverageSubunitStrengthRatio`).
    - Slot 22 (`+0x58` en `0x00DF8924`): `0x005CFF90` (`CalculateAverageSubunitMoraleRatio`).
  - `CNavy` (vtable base `0x00E02FCC`, RTTI COL en `0x00E5085C`):
    - Slot 21 (`+0x54` en `0x00E03020`): `0x005CFE90` (`CalculateAverageSubunitStrengthRatio`).
    - Slot 22 (`+0x58` en `0x00E03024`): `0x005CFF90` (`CalculateAverageSubunitMoraleRatio`).
  - `CRegiment` (vtable base `0x00DF8884`, RTTI COL en `0x00E4B3E4`):
    - Slot 12 (`+0x30` en `0x00DF88B4`): `0x005BFF80` (`CSubUnit::GetMaxStrength`).
    - Slot 13 (`+0x34` en `0x00DF88B8`): `0x005BFFA0` (`CSubUnit::GetMaxMorale`).
  - `CShip` (vtable base `0x00E02A64`, RTTI COL en `0x00E505F0`):
    - Slot 12 (`+0x30` en `0x00E02A94`): `0x005BFF80` (`CSubUnit::GetMaxStrength`).
    - Slot 13 (`+0x34` en `0x00E02A98`): `0x005BFFA0` (`CSubUnit::GetMaxMorale`).
- **Llamadores confirmados:**
  - `0x005D8170`: `CNavy::EvaluateResupplyNecessity` (`0x005D8120`), consulta slot 21 (`+0x54`) para decidir reabastecimiento si la ratio de fuerza cae bajo el umbral del 85.0% (`0.8505` en `0x00E45ADC`).
  - UI y subsistema de evaluación operativa de ejércitos y armadas (`CArmyView`, `CShipView`, `CCombatView`).
- **Convención de llamada:**
  - `__thiscall` con retorno de estructura `CFixedPoint` por puntero oculto:
    - `ecx = this` (puntero a `CUnit`, sea `CArmy` o `CNavy`).
    - `[esp + 4]` / `[ebp + 8]`: puntero de destino `CFixedPoint* out_ratio`.
    - Epílogo: `ret 4` (la rutina limpia el puntero de argumento).
    - Retorna `eax = out_ratio`.

---

## 2. Estructura de Memoria y Offsets

### Formación Militar (`CUnit`, base de `CArmy` y `CNavy`)
- `+0x00`: Vtable (`CArmy` en `0x00DF88CC`, `CNavy` en `0x00E02FCC`).
- `+0x38`: Puntero al primer nodo de la lista enlazada de subunidades (`SubUnitNode* m_subunits_head`).
- `+0x40`: Número total de subunidades en la formación (`int32 m_num_subunits`).

### Nodo de Lista Enlazada (`SubUnitNode`)
- `+0x00`: Puntero al objeto de subunidad (`CSubUnit* subunit`).
- `+0x08`: Puntero al siguiente nodo (`SubUnitNode* next`).

### Objeto de Subunidad (`CSubUnit`, base de `CRegiment` y `CShip`)
- `+0x00`: Vtable (`CRegiment` en `0x00DF8884`, `CShip` en `0x00E02A64`).
- `+0x38`: Puntero al descriptor de tipo (`CUnitType* m_type`).
- `+0x3C`: Fuerza actual en milésimas (`int32 m_nStrength`).
- `+0x40`: Moral actual en milésimas (`int32 m_nMorale`).
- `+0x74`: Puntero al estrato poblacional de origen (`CLocationPop* m_pop`).

### Descriptor de Estrato Poblacional (`CLocationPop`)
- `+0x164`: Bandera de lealtad rebelde / simpatizante insurreccional (`uint8 m_isRebelPop`).

---

## 3. Formulación Algorítmica y Matemática

### 1. Ratio Promedio de Fuerza / Salud (`CUnit::CalculateAverageSubunitStrengthRatio`)
1. **Inicialización:**
   `*out_ratio = 0` (mediante constructor en línea `CFixedPoint(0.0f)` evaluado con `floor((0.0 + 0.0005) * 1000.0) = 0`).
2. **Caso Formación Vacía:**
   Si `m_subunits_head == NULL`, salta directamente a la fase de división final.
3. **Iteración sobre Subunidades:**
   Para cada subunidad $i \in \{1, \dots, N\}$:
   - Consulta `vtable[12]` (`CSubUnit::GetMaxStrength(&temp, 0)`).
   - Lee `max_strength = temp.m_value`.
   - Lee `current_strength = subunit->m_nStrength`.
   - Si $\text{max\_strength} = 0$:
     $\text{ratio}_i = -1$ (centinela -0.001 en fixed-point).
   - Si $\text{max\_strength} \neq 0$:
     - Si $\text{current\_strength} \in [-1610611, 2147482]$ (rango seguro de 32 bits comprobado con `lea ecx, [ebx + 0x189373]; cmp ecx, 0x39580d`):
       $$\text{ratio}_i = \left\lfloor \frac{\text{current\_strength} \times 1000}{\text{max\_strength}} \right\rfloor$$
     - De lo contrario, ejecuta multiplicación y división de 64 bits con `__allmul` y `__alldiv`:
       $$\text{ratio}_i = \text{\_\_alldiv}(\text{\_\_allmul}(\text{current\_strength}, 1000), \text{max\_strength})$$
   - Acumula: $\text{sum\_ratio} \mathrel{+}= \text{ratio}_i$.
4. **Normalización por Conteo:**
   - Lee $C = \text{this}\to\text{m\_num\_subunits}$ (`[this + 0x40]`).
   - Si $C = 0$: no efectúa división y conserva el acumulado (que para lista vacía es 0).
   - Si $C > 0$:
     - Calcula denominador $\text{den} = C \times 1000$.
     - Computa mediante rutina de 64 bits:
       $$\text{average} = \text{\_\_alldiv}(\text{\_\_allmul}(\text{sum\_ratio}, 1000), C \times 1000) = \left\lfloor \frac{\text{sum\_ratio}}{C} \right\rfloor$$
     - Asigna `*out_ratio = average`.
5. Retorna el puntero `out_ratio` en `eax`.

### 2. Ratio Promedio de Moral (`CUnit::CalculateAverageSubunitMoraleRatio`)
1. **Inicialización:**
   `*out_ratio = 0` (idéntico a la rutina de fuerza).
2. **Caso Formación Vacía:**
   Si `m_subunits_head == NULL`, salta a la fase de división final.
3. **Iteración sobre Subunidades:**
   Para cada subunidad $i \in \{1, \dots, N\}$:
   - Comprobación de insurrección / rebelión:
     Si `subunit->m_pop != NULL` y `subunit->m_pop->m_isRebelPop != 0`:
       $\text{effective\_morale} = 0$.
     De lo contrario:
       $\text{effective\_morale} = \text{subunit}\to\text{m\_nMorale}$.
   - Consulta `vtable[13]` (`CSubUnit::GetMaxMorale(&temp, 0)`).
   - Lee `max_morale = temp.m_value`.
   - Si $\text{max\_morale} = 0$:
     $\text{ratio}_i = -1$.
   - Si $\text{max\_morale} \neq 0$:
     - Comprobación de rango seguro 32 bits ($[-1610611, 2147482]$):
       $$\text{ratio}_i = \left\lfloor \frac{\text{effective\_morale} \times 1000}{\text{max\_morale}} \right\rfloor$$
     - Si excede el rango, evaluación en 64 bits con `__allmul` y `__alldiv`.
   - Acumula: $\text{sum\_ratio} \mathrel{+}= \text{ratio}_i$.
4. **Normalización por Conteo:**
   - Si $C = 0$, conserva el valor acumulado.
   - Si $C > 0$, normaliza en 64 bits entre $C \times 1000$:
     $$\text{average} = \left\lfloor \frac{\text{sum\_ratio}}{C} \right\rfloor$$
5. Retorna el puntero `out_ratio` en `eax`.

---

## 4. Reconstrucción en Pseudocódigo C++

```cpp
CFixedPoint* __thiscall CUnit::CalculateAverageSubunitStrengthRatio(CFixedPoint* out_ratio) {
    *out_ratio = CFixedPoint(0.0f);
    SubUnitNode* node = this->m_subunits_head;
    if (node != nullptr) {
        do {
            CSubUnit* subunit = node->subunit;
            node = node->next;
            int32_t current_strength = subunit->m_nStrength;

            CFixedPoint max_str_fp;
            subunit->GetMaxStrength(&max_str_fp, 0);
            int32_t max_strength = max_str_fp.m_value;

            int32_t ratio;
            if (max_strength == 0) {
                ratio = -1;
            } else {
                if ((uint32_t)(current_strength + 0x189373) <= 0x39580d) {
                    ratio = (int32_t)(((int64_t)current_strength * 1000) / max_strength);
                } else {
                    ratio = (int32_t)(__alldiv(__allmul(current_strength, 1000), max_strength));
                }
            }
            out_ratio->m_value += ratio;
        } while (node != nullptr);
    }

    int32_t count = this->m_num_subunits;
    if (count > 0) {
        int64_t sum_scaled = __allmul(out_ratio->m_value, 1000);
        int64_t count_scaled = (int64_t)count * 1000;
        out_ratio->m_value = (int32_t)__alldiv(sum_scaled, count_scaled);
    }
    return out_ratio;
}

CFixedPoint* __thiscall CUnit::CalculateAverageSubunitMoraleRatio(CFixedPoint* out_ratio) {
    *out_ratio = CFixedPoint(0.0f);
    SubUnitNode* node = this->m_subunits_head;
    if (node != nullptr) {
        do {
            CSubUnit* subunit = node->subunit;
            node = node->next;

            int32_t current_morale;
            if (subunit->m_pop != nullptr && subunit->m_pop->m_isRebelPop != 0) {
                current_morale = 0;
            } else {
                current_morale = subunit->m_nMorale;
            }

            CFixedPoint max_mor_fp;
            subunit->GetMaxMorale(&max_mor_fp, 0);
            int32_t max_morale = max_mor_fp.m_value;

            int32_t ratio;
            if (max_morale == 0) {
                ratio = -1;
            } else {
                if ((uint32_t)(current_morale + 0x189373) <= 0x39580d) {
                    ratio = (int32_t)(((int64_t)current_morale * 1000) / max_morale);
                } else {
                    ratio = (int32_t)(__alldiv(__allmul(current_morale, 1000), max_morale));
                }
            }
            out_ratio->m_value += ratio;
        } while (node != nullptr);
    }

    int32_t count = this->m_num_subunits;
    if (count > 0) {
        int64_t sum_scaled = __allmul(out_ratio->m_value, 1000);
        int64_t count_scaled = (int64_t)count * 1000;
        out_ratio->m_value = (int32_t)__alldiv(sum_scaled, count_scaled);
    }
    return out_ratio;
}
```

---

## 5. Casos de Borde y Comportamientos Críticos
1. **Formación sin subunidades (`m_subunits_head == NULL` o `m_num_subunits == 0`):**
   Retorna exactamente $0$.
2. **Subunidad con fuerza/moral máxima cero:**
   Si una subunidad corrupta o desprovista de tipo retorna `max == 0`, su ratio aporta $-1$ ($-0.001$), evitando división por cero y penalizando la cohesión global.
3. **Unidad simpatizante rebelde:**
   Si la subunidad proviene de un estrato POP con bandera de rebelión activa (`[pop + 0x164] != 0`), su moral efectiva computada es forzada a $0.0$, degradando la moral media de la formación.
4. **Desbordamiento de 32 bits:**
   Para valores de fuerza o moral acumulados fuera del intervalo $[-1610611, 2147482]$, la rutina bifurca hacia `__allmul` y `__alldiv` de 64 bits, garantizando total precisión sin desbordamiento entero.

---

## 6. Criterio de Verificación de Evidencia
- **Verificación Estática:**
  - 96 instrucciones verificadas formalmente en `0x005CFE90..0x005CFF85`.
  - 103 instrucciones verificadas formalmente en `0x005CFF90..0x005D0099`.
  - Vtables de `CArmy` y `CNavy` (slots 21 y 22) y `CRegiment` y `CShip` (slots 12 y 13) verificadas contra el binario inmutable.
  - Constantes flotantes y de punto fijo verificadas por valor exacto.
  - Control negativo con aserción errónea refutada (`REFUTED`) y cascada dependiente invalidada (`INVALIDATED`).
- **Verificación Dinámica:**
  - Emulación completa en Unicorn Engine contrastada contra el modelo analítico en `formation_cohesion_model.py` con 0 discrepancias sobre al menos 50 configuraciones que cubren formaciones vacías, homogéneas, heterogéneas, rebeldes, con valores extremos y centinelas.
