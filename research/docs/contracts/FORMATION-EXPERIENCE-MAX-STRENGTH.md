# Contrato: Evaluación de Experiencia Media y Fuerza Máxima Total en Formaciones Militares (`CUnit::CalculateAverageExperience` y `CUnit::CalculateTotalMaxStrength`)

## 1. Identificación y Alcance
- **Binario:** `base-game/v2game.exe` (SHA-256: `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`).
- **Direcciones de las rutinas:**
  - `CUnit::CalculateAverageExperience`: `0x005CF8B0..0x005CF943` (147 bytes, 58 instrucciones).
  - `CUnit::CalculateTotalMaxStrength`: `0x005CF950..0x005CF9AF` (95 bytes, 31 instrucciones).
- **Vtables:**
  - `CArmy` (vtable base `0x00DF88CC`, RTTI COL en `0x00E4B2BC`):
    - Slot 19 (`+0x4C` en `0x00DF8918`): `0x005CF8B0` (`CalculateAverageExperience`).
    - Slot 20 (`+0x50` en `0x00DF891C`): `0x005CF950` (`CalculateTotalMaxStrength`).
  - `CNavy` (vtable base `0x00E02FCC`, RTTI COL en `0x00E5085C`):
    - Slot 19 (`+0x4C` en `0x00E03018`): `0x005CF8B0` (`CalculateAverageExperience`).
    - Slot 20 (`+0x50` en `0x00E0301C`): `0x005CF950` (`CalculateTotalMaxStrength`).
- **Convención de llamada:**
  - Ambas rutinas utilizan `__thiscall` con retorno por puntero oculto:
    - `ecx = this` (`CUnit*`).
    - `[esp + 4]` / `[ebp + 8]` = `out_val` (`CFixedPoint*`).
    - Retorno `eax = out_val`.
    - Epílogo: `ret 4`.

---

## 2. Estructura de Memoria y Offsets

### Formación Militar (`CUnit`, base común de `CArmy` y `CNavy`)
- `+0x00`: Vtable (`CArmy` en `0x00DF88CC`, `CNavy` en `0x00E02FCC`).
- `+0x38`: Puntero al nodo inicial de subunidades (`SubUnitNode* m_subunits_head`).
- `+0x40`: Conteo total de subunidades registradas (`int32 m_subunit_count`).

### Nodo de Subunidad (`SubUnitNode`)
- `+0x00`: Puntero al regimiento / buque `CSubUnit* subunit`.
- `+0x08`: Siguiente nodo de la lista `SubUnitNode* next`.

### Objeto de Subunidad (`CSubUnit`)
- `+0x34`: Experiencia militar en milésimas (`int32 m_nExperience`).
- `+0x38`: Puntero al tipo de subunidad (`CUnitType* m_type`).

### Objeto de Tipo de Unidad (`CUnitType`)
- `+0xB0`: Fuerza máxima intrínseca en milésimas (`int32 m_max_strength`).

---

## 3. Formulación Algorítmica y Matemática

### 1. Experiencia Media de Formación (`CUnit::CalculateAverageExperience`, `0x005CF8B0`)
1. **Inicialización:**
   `*out_avg_exp = 0` (evaluado con `floor((0.0 + 0.0005) * 1000.0) = 0`).
2. **Caso Formación Vacía:**
   Si `m_subunits_head == NULL`, omite el bucle y procede a comprobar el conteo.
3. **Agregación de Experiencia:**
   Para cada subunidad $i \in \{1, \dots, N\}$:
   $$\text{total\_exp} = \sum_{i=1}^{N} \text{subunit}_i\to\text{m\_nExperience}$$
4. **Normalización por Conteo:**
   Lee $C = \text{this}\to\text{m\_subunit\_count}$.
   - Si $C = 0$:
     `*out_avg_exp = total_exp`.
   - Si $C > 0$:
     Multiplica por 1,000 en 64 bits y divide entre $C \times 1,000$:
     $$\text{average\_exp} = \left\lfloor \frac{\text{total\_exp} \times 1000}{C \times 1000} \right\rfloor = \left\lfloor \frac{\text{total\_exp}}{C} \right\rfloor$$
     (utilizando `_allmul` en `0x00AC9F20` y `_alldiv` en `0x00AC02A0`).
5. Asigna `*out_avg_exp = average_exp` y retorna `out_avg_exp`.

### 2. Capacidad Nominal Máxima de Formación (`CUnit::CalculateTotalMaxStrength`, `0x005CF950`)
1. **Inicialización:**
   `*out_total_max_str = 0` (evaluado con `floor((0.0 + 0.0005) * 1000.0) = 0`).
2. **Caso Formación Vacía:**
   Si `m_subunits_head == NULL`, retorna inmediatamente 0.
3. **Agregación de Capacidad Máxima:**
   Para cada subunidad $i \in \{1, \dots, N\}$:
   $$\text{total\_max\_str} = \sum_{i=1}^{N} \text{subunit}_i\to\text{m\_type}\to\text{m\_max\_strength}$$
4. Asigna `*out_total_max_str = total_max_str` y retorna `out_total_max_str`.

---

## 4. Reconstrucción en Pseudocódigo C++

```cpp
CFixedPoint* __thiscall CUnit::CalculateAverageExperience(CFixedPoint* out_avg_exp) {
    *out_avg_exp = CFixedPoint(0.0f);
    SubUnitNode* node = this->m_subunits_head;
    int32_t total_exp = 0;

    while (node != nullptr) {
        CSubUnit* subunit = node->subunit;
        total_exp += subunit->m_nExperience;
        node = node->next;
    }
    out_avg_exp->m_value = total_exp;

    int32_t count = this->m_subunit_count;
    if (count != 0) {
        int64_t dividend = __allmul(total_exp, 1000);
        int64_t divisor = (int64_t)count * 1000;
        out_avg_exp->m_value = (int32_t)__alldiv(dividend, divisor);
    }

    return out_avg_exp;
}

CFixedPoint* __thiscall CUnit::CalculateTotalMaxStrength(CFixedPoint* out_total_max_str) {
    *out_total_max_str = CFixedPoint(0.0f);
    SubUnitNode* node = this->m_subunits_head;

    while (node != nullptr) {
        CSubUnit* subunit = node->subunit;
        out_total_max_str->m_value += subunit->m_type->m_max_strength;
        node = node->next;
    }

    return out_total_max_str;
}
```

---

## 5. Casos de Borde y Comportamientos Críticos
1. **Formación vacía:**
   Ambas rutinas retornan exactamente 0.
2. **Formación con conteo cero:**
   Si `m_subunit_count == 0`, `CalculateAverageExperience` no realiza división por cero y retorna la suma bruta.
3. **Truncamiento entero signed:**
   La división entre $C \times 1,000$ mediante `_alldiv` trunca estrictamente hacia cero conforme a los estándares de punto fijo del motor.
4. **Independencia polimórfica:**
   Ambas funciones residen en `CUnit` y son heredadas directamente tanto por `CArmy` como por `CNavy`, compartiendo los slots 19 y 20 en sus respectivas tablas virtuales.

---

## 6. Criterio de Verificación de Evidencia
- **Verificación Estática:**
  - 58 instrucciones en `0x005CF8B0..0x005CF943`.
  - 31 instrucciones en `0x005CF950..0x005CF9AF`.
  - Slots 19 y 20 en vtables de `CArmy` (`0x00DF8918` y `0x00DF891C`) y `CNavy` (`0x00E03018` y `0x00E0301C`).
  - Constantes IEEE 754 en `0x00E45840` (0.0005) y `0x00E45660` (1000.0).
  - Puntos de llamada a `_allmul` (`0x005CF923`) y `_alldiv` (`0x005CF933`).
  - Control negativo con aserción errónea refutada (`REFUTED`) y cascada dependiente invalidada (`INVALIDATED`).
- **Verificación Dinámica:**
  - Emulación completa en Unicorn Engine contrastada contra `formation_experience_max_strength_model.py` sobre al menos 50 fixtures con 0 discrepancias.
