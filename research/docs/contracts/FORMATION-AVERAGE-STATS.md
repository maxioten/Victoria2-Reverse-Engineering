# Contrato: Evaluación de Moral Media y Fuerza Media en Formaciones Militares (`CUnit::CalculateAverageMorale` y `CUnit::CalculateAverageStrength`)

## 1. Identificación y Alcance
- **Binario:** `base-game/v2game.exe` (SHA-256: `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`).
- **Direcciones de las rutinas:**
  - `CUnit::CalculateAverageMorale`: `0x005CFA90..0x005CFB03` (115 bytes, 51 instrucciones).
  - `CUnit::CalculateAverageStrength`: `0x005CFB10..0x005CFB73` (99 bytes, 46 instrucciones).
- **Vtables:**
  - `CArmy` (vtable base `0x00DF88CC`, RTTI COL en `0x00E4B2BC`):
    - Slot 17 (`+0x44` en `0x00DF8910`): `0x005CFA90` (`CalculateAverageMorale`).
    - Slot 18 (`+0x48` en `0x00DF8914`): `0x005CFB10` (`CalculateAverageStrength`).
  - `CNavy` (vtable base `0x00E02FCC`, RTTI COL en `0x00E5085C`):
    - Slot 17 (`+0x44` en `0x00E03010`): `0x005CFA90` (`CalculateAverageMorale`).
    - Slot 18 (`+0x48` en `0x00E03014`): `0x005CFB10` (`CalculateAverageStrength`).
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
- `+0x38`: Puntero al primer nodo de subunidades (`SubUnitNode* m_subunits_head`).
- `+0x40`: Conteo registrado de subunidades (`int32 m_subunit_count`).

### Nodo de Subunidad (`SubUnitNode`)
- `+0x00`: Puntero a subunidad (`CSubUnit* subunit`).
- `+0x08`: Siguiente nodo de la lista (`SubUnitNode* next`).

### Objeto de Subunidad (`CSubUnit`)
- `+0x3C`: Fuerza viva actual en milésimas (`int32 m_nStrength`).
- `+0x40`: Moral actual en milésimas (`int32 m_nMorale`).
- `+0x74`: Puntero al POP demográfico de origen (`CPop* m_pop`).

### Objeto de Población (`CPop`)
- `+0x164`: Bandera de facción rebelde activa (`uint8 m_is_rebel`).

---

## 3. Formulación Algorítmica y Matemática

### 1. Moral Media de Formación (`CUnit::CalculateAverageMorale`, `0x005CFA90`)
1. **Inicialización:**
   `*out_avg_morale = 0`.
2. **Caso Formación Vacía:**
   Si `m_subunits_head == NULL`, omite el bucle y procede a comprobar el conteo.
3. **Agregación con Filtro Rebelde:**
   Para cada subunidad $i \in \{1, \dots, N\}$:
   - Lee `pop = subunit_i->m_pop` (`[subunit + 0x74]`).
   - Si `pop != NULL` y `pop->m_is_rebel != 0` (`byte ptr [pop + 0x164] != 0`):
     $M_{\text{eff}, i} = 0$ (moral rebelde anulada).
   - De lo contrario:
     $M_{\text{eff}, i} = \text{subunit}_i\to\text{m\_nMorale}$.
   - Acumula: $\text{total\_morale} \mathrel{+}= M_{\text{eff}, i}$.
4. **Normalización por Conteo:**
   Lee $C = \text{this}\to\text{m\_subunit\_count}$ (`[ecx + 0x40]`).
   - Si $C = 0$:
     `*out_avg_morale = total_morale`.
   - Si $C > 0$:
     $$\text{average\_morale} = \left\lfloor \frac{\text{total\_morale} \times 1000}{C \times 1000} \right\rfloor = \left\lfloor \frac{\text{total\_morale}}{C} \right\rfloor$$
     (evaluado mediante `_allmul` en `0x00AC9F20` y `_alldiv` en `0x00AC02A0`).
5. Asigna `*out_avg_morale = average_morale` y retorna `out_avg_morale`.

### 2. Fuerza Viva Media de Formación (`CUnit::CalculateAverageStrength`, `0x005CFB10`)
1. **Inicialización:**
   `*out_avg_str = 0`.
2. **Caso Formación Vacía:**
   Si `m_subunits_head == NULL`, omite el bucle.
3. **Agregación de Fuerza Viva:**
   Para cada subunidad $i \in \{1, \dots, N\}$:
   $$\text{total\_strength} = \sum_{i=1}^{N} \text{subunit}_i\to\text{m\_nStrength}$$
4. **Normalización por Conteo:**
   Lee $C = \text{this}\to\text{m\_subunit\_count}$.
   - Si $C = 0$:
     `*out_avg_str = total_strength`.
   - Si $C > 0$:
     $$\text{average\_strength} = \left\lfloor \frac{\text{total\_strength} \times 1000}{C \times 1000} \right\rfloor = \left\lfloor \frac{\text{total\_strength}}{C} \right\rfloor$$
     (evaluado mediante `_allmul` en `0x00AC9F20` y `_alldiv` en `0x00AC02A0`).
5. Asigna `*out_avg_str = average_strength` y retorna `out_avg_str`.

---

## 4. Reconstrucción en Pseudocódigo C++

```cpp
CFixedPoint* __thiscall CUnit::CalculateAverageMorale(CFixedPoint* out_avg_morale) {
    *out_avg_morale = CFixedPoint(0.0f);
    SubUnitNode* node = this->m_subunits_head;
    int32_t total_morale = 0;

    while (node != nullptr) {
        CSubUnit* subunit = node->subunit;
        int32_t eff_morale = subunit->m_nMorale;
        CPop* pop = subunit->m_pop;
        if (pop != nullptr && pop->m_is_rebel != 0) {
            eff_morale = 0;
        }
        total_morale += eff_morale;
        node = node->next;
    }
    out_avg_morale->m_value = total_morale;

    int32_t count = this->m_subunit_count;
    if (count != 0) {
        int64_t dividend = __allmul(total_morale, 1000);
        int64_t divisor = (int64_t)count * 1000;
        out_avg_morale->m_value = (int32_t)__alldiv(dividend, divisor);
    }

    return out_avg_morale;
}

CFixedPoint* __thiscall CUnit::CalculateAverageStrength(CFixedPoint* out_avg_str) {
    *out_avg_str = CFixedPoint(0.0f);
    SubUnitNode* node = this->m_subunits_head;
    int32_t total_strength = 0;

    while (node != nullptr) {
        CSubUnit* subunit = node->subunit;
        total_strength += subunit->m_nStrength;
        node = node->next;
    }
    out_avg_str->m_value = total_strength;

    int32_t count = this->m_subunit_count;
    if (count != 0) {
        int64_t dividend = __allmul(total_strength, 1000);
        int64_t divisor = (int64_t)count * 1000;
        out_avg_str->m_value = (int32_t)__alldiv(dividend, divisor);
    }

    return out_avg_str;
}
```

---

## 5. Casos de Borde y Comportamientos Críticos
1. **Filtro de moral para sublevaciones rebeldes:**
   Subunidades asignadas a POPs rebeldes devuelven 0 de moral efectiva, deprimiendo el promedio general de la formación.
2. **Conteo nulo:**
   Si `m_subunit_count == 0`, no se ejecuta la división y se devuelve la suma íntegra.
3. **División signed truncada:**
   `_alldiv` trunca hacia cero en divisiones enteras.

---

## 6. Criterio de Verificación de Evidencia
- **Verificación Estática:**
  - 51 instrucciones en `0x005CFA90..0x005CFB03`.
  - 46 instrucciones en `0x005CFB10..0x005CFB73`.
  - Slots 17 y 18 en vtables de `CArmy` (`0x00DF8910` / `0x00DF8914`) y `CNavy` (`0x00E03010` / `0x00E03014`).
  - Puntos de llamada a `_allmul` y `_alldiv`.
  - Control negativo con aserción errónea refutada (`REFUTED`) y cascada dependiente invalidada (`INVALIDATED`).
- **Verificación Dinámica:**
  - Emulación completa en Unicorn Engine contrastada contra `formation_average_stats_model.py` sobre al menos 50 fixtures heterogéneos con 0 discrepancias.
