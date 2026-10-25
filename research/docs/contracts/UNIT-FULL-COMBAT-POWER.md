# Contrato: Evaluación de Potencia de Combate Completa con Moral, Experiencia y Tecnología (`CUnit::CalculateFullCombatPower`)

## 1. Identificación y Alcance
- **Binario:** `base-game/v2game.exe` (SHA-256: `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`).
- **Dirección de la rutina:** `0x005D02F0..0x005D04FB` (523 bytes, 186 instrucciones).
- **Vtables:**
  - `CArmy` (vtable base `0x00DF88CC`, RTTI COL en `0x00E4B2BC`):
    - Slot 26 (`+0x68` en `0x00DF8934`): `0x005D02F0` (`CalculateFullCombatPower`).
  - `CNavy` (vtable base `0x00E02FCC`, RTTI COL en `0x00E5085C`):
    - Slot 26 (`+0x68` en `0x00E03034`): `0x005D02F0` (`CalculateFullCombatPower`).
  - `CRegiment` (vtable base `0x00DF8884`):
    - Slot 12 (`+0x30` en `0x00DF88B4`): `0x005BFF80` (`CSubUnit::GetMaxStrength`).
    - Slot 13 (`+0x34` en `0x00DF88B8`): `0x005BFFA0` (`CSubUnit::GetMaxMorale`).
  - `CShip` (vtable base `0x00E02A64`):
    - Slot 12 (`+0x30` en `0x00E02A94`): `0x005BFF80` (`CSubUnit::GetMaxStrength`).
    - Slot 13 (`+0x34` en `0x00E02A98`): `0x005BFFA0` (`CSubUnit::GetMaxMorale`).
- **Callee confirmado:**
  - `CUnitType::CalculateCombatRating` (`0x005BDC80`): invocado en `0x005D0346`.
- **Convención de llamada:**
  - `__thiscall` con retorno por puntero oculto: `ecx = this` (`CUnit*`), `[esp + 4]` / `[ebp + 8]` = `out_total` (`CFixedPoint*`).
  - Retorna `eax = out_total`. Epílogo `ret 4`.

---

## 2. Estructura de Memoria y Offsets

### Formación Militar (`CUnit`, base de `CArmy` y `CNavy`)
- `+0x00`: Vtable (`CArmy` en `0x00DF88CC`, `CNavy` en `0x00E02FCC`).
- `+0x90`: Puntero al primer nodo de subunidades seleccionadas / activas (`SubUnitNode* m_selected_subunits_head`).
- `+0xC0`: Identificador de país soberano índice (`uint32 m_owner_id`).
- `+0xC4`: Identificador de país soberano tipo (`uint32 m_owner_type`).

### Nodo de Subunidad (`SubUnitNode`)
- `+0x00`: Puntero al regimiento / buque `CSubUnit* subunit`.
- `+0x08`: Siguiente nodo `SubUnitNode* next`.

### Objeto de Subunidad (`CSubUnit`)
- `+0x00`: Vtable (`slot 12` -> `GetMaxStrength`, `slot 13` -> `GetMaxMorale`).
- `+0x34`: Experiencia militar en milésimas (`int32 m_nExperience`).
- `+0x38`: Puntero a `CUnitType* m_type`.
- `+0x3C`: Fuerza actual en milésimas (`int32 m_nStrength`).
- `+0x40`: Moral actual en milésimas (`int32 m_nMorale`).
- `+0x74`: Puntero al POP de origen (`CPop* m_pop`).

### Objeto de Población (`CPop`)
- `+0x164`: Bandera de facción rebelde activa (`uint8 m_is_rebel`).

### Estado Global y Modificadores Nacionales
- `0x012587E4`: Array de punteros de países (`CCountry**`).
  - `country + 0xBCC`: Estructura militar de país (`CMilitaryStats*`).
  - `[country + 0xBCC] + 0x70`: Bono tecnológico / doctrina táctica nacional (`int32 m_combat_factor_bonus`).
- `0x012586DC`: Gestor de definiciones globales (`CDefines*`).
  - `defines + 0x20`: Puntero a MilitaryDefines (`CMilitaryDefines*`).
  - `[defines + 0x20] + 0xE0`: Factor base de combate militar (`int32 m_base_combat_factor`, default 1000).
- `0x0125FED8`: Multiplicador global de experiencia militar (`int32 m_experience_combat_factor`, inicializado desde `0x00E45BBC` = `10.5f` -> `10`).
- `0x00E45A18`: Constante IEEE 754 de fuerza mínima (`100.5f` -> `floor(100.5f) = 100`).

---

## 3. Formulación Algorítmica y Matemática

### 1. Inicialización
1. `*out_total = 0`.
2. Lee `head = this->m_selected_subunits_head` (`[ecx + 0x90]`).
   Si `head == nullptr`, salta directamente a la fase de escalado tecnológico con `*out_total = 0`, retornando 0.
3. Lee constante flotante `100.5f` en `0x00E45A18`, aplica `floor` y `_ftol2`, obteniendo `min_strength = 100` (`[ebp - 0xC]`).

### 2. Bucle de Subunidades Seleccionadas
Para cada nodo $i$ en la lista enlazada:
1. **Calificación Táctica:**
   Invoca `subunit_i->m_type->CalculateCombatRating(&rating)` (`0x005BDC80`).
2. **Ratio de Fuerza Viva:**
   Lee $S_{\text{curr}} = \text{subunit}_i\to\text{m\_nStrength}$ y consulta $S_{\text{max}} = \text{subunit}_i\to\text{GetMaxStrength}()$ (slot 12).
   - Si $S_{\text{max}} = 0$: $H_r = -1$.
   - Si $S_{\text{max}} > 0$:
     $$H_r = \left\lfloor \frac{S_{\text{curr}} \times 1000}{S_{\text{max}}} \right\rfloor$$
     (evaluado con fast-path de 32 bits si $S_{\text{curr}} \in [-1610611, 2147482]$, o `_allmul`/`_alldiv` en overflow).
3. **Potencia de Salud:**
   $$P_h = \left\lfloor \frac{H_r \times \text{rating}}{1000} \right\rfloor$$
4. **Ratio de Moral (con Filtro Rebelde):**
   Comprueba el POP de origen:
   - Si `subunit->m_pop != nullptr` y `pop->m_is_rebel != 0`:
     $M_{\text{eff}} = 0$ (moral efectiva anulada).
   - En caso contrario:
     $M_{\text{eff}} = \text{subunit}_i\to\text{m\_nMorale}$.
   Consulta $M_{\text{max}} = \text{subunit}_i\to\text{GetMaxMorale}()$ (slot 13).
   - Si $M_{\text{max}} = 0$: $M_r = -1$.
   - Si $M_{\text{max}} > 0$:
     $$M_r = \left\lfloor \frac{M_{\text{eff}} \times 1000}{M_{\text{max}}} \right\rfloor$$
5. **Multiplicador de Experiencia:**
   Lee $E = \text{subunit}_i\to\text{m\_nExperience}$.
   Lee factor global $F_{\text{exp}} = [0x0125FED8]$ (default 10).
   $$E_{\text{bonus}} = \left\lfloor \frac{E \times F_{\text{exp}}}{1000} \right\rfloor$$
   $$E_{\text{mult}} = 1000 + E_{\text{bonus}}$$
6. **Potencia Táctica Integrada:**
   $$P_{\text{morale}} = \left\lfloor \frac{M_r \times P_h}{1000} \right\rfloor$$
   $$P = \left\lfloor \frac{P_{\text{morale}} \times E_{\text{mult}}}{1000} \right\rfloor$$
7. **Penalización por Desmoralización o Quebranto:**
   Si $S_{\text{curr}} < \text{min\_strength} (100)$ O $M_{\text{curr}} < 1000$ (1.0 de moral):
   $$P = \left\lfloor \frac{P \times 1000}{2000} \right\rfloor = \left\lfloor \frac{P}{2} \right\rfloor$$
   (aplica una penalización del 50% por degradación operativa).
8. **Acumulación:**
   $\text{total\_power} \mathrel{+}= P$.

### 3. Escalado Tecnológico y Doctrinal Nacional
1. Obtiene el puntero al país soberano: `country = CGameState::GetCountry(unit->m_owner_id)`.
2. Lee `bonus = country->m_military_stats->m_combat_factor_bonus` (`[country + 0xBCC] + 0x70`).
3. Lee `base_tech = CDefines::MilitaryDefines->m_base_combat_factor` (`[0x012586DC + 0x20] + 0xE0`).
4. Totaliza el factor tecnológico:
   $$T_f = \text{base\_tech} + \text{bonus}$$
5. Escala la potencia de la formación:
   $$\text{final\_power} = \left\lfloor \frac{\text{total\_power} \times T_f}{1000} \right\rfloor$$
6. Escribe `*out_total = final_power` y retorna `out_total`.

---

## 4. Reconstrucción en Pseudocódigo C++

```cpp
CFixedPoint* __thiscall CUnit::CalculateFullCombatPower(CFixedPoint* out_total) {
    *out_total = CFixedPoint(0.0f);
    SubUnitNode* node = this->m_selected_subunits_head;

    if (node != nullptr) {
        int32_t min_strength = (int32_t)floorf(100.5f); // 100

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

            int32_t health_power = (int32_t)(((int64_t)health_ratio * rating_fp.m_value) / 1000);

            // Filtro de facción rebelde
            int32_t current_mor = subunit->m_nMorale;
            CPop* pop = subunit->m_pop;
            if (pop != nullptr && pop->m_is_rebel != 0) {
                current_mor = 0;
            }

            CFixedPoint max_mor_fp;
            subunit->GetMaxMorale(&max_mor_fp, 0);
            int32_t max_mor = max_mor_fp.m_value;

            int32_t morale_ratio;
            if (max_mor == 0) {
                morale_ratio = -1;
            } else {
                if ((uint32_t)(current_mor + 0x189373) <= 0x39580d) {
                    morale_ratio = (int32_t)(((int64_t)current_mor * 1000) / max_mor);
                } else {
                    morale_ratio = (int32_t)(__alldiv(__allmul(current_mor, 1000), max_mor));
                }
            }

            int32_t exp = subunit->m_nExperience;
            int32_t exp_factor = g_experience_combat_factor; // [0x0125FED8], default 10
            int32_t exp_bonus = (int32_t)(((int64_t)exp * exp_factor) / 1000);
            int32_t exp_mult = 1000 + exp_bonus;

            int32_t morale_power = (int32_t)(((int64_t)morale_ratio * health_power) / 1000);
            int32_t power = (int32_t)(((int64_t)morale_power * exp_mult) / 1000);

            // Penalización por desmoralización (<1.0) o quebranto (<100)
            if (subunit->m_nStrength < min_strength || subunit->m_nMorale < 1000) {
                power = (int32_t)(__alldiv(__allmul(power, 1000), 2000)); // power / 2
            }

            out_total->m_value += power;
        }
    }

    // Escalado por tecnología militar nacional
    CCountry* country = CGameState::Instance()->GetCountry(this->m_owner_id);
    int32_t tech_bonus = country->m_military_stats->m_combat_factor_bonus;
    int32_t base_tech = CDefines::Instance()->m_military->m_base_combat_factor;
    int32_t tech_factor = base_tech + tech_bonus;

    out_total->m_value = (int32_t)(((int64_t)out_total->m_value * tech_factor) / 1000);
    return out_total;
}
```

---

## 5. Casos de Borde y Comportamientos Críticos
1. **Formación sin subunidades seleccionadas:**
   Retorna exactamente 0.
2. **Subunidad rebelde:**
   Moral efectiva 0 $\to$ ratio de moral 0 $\to$ potencia calculada 0.
3. **Subunidad con fuerza viva < 100 o moral < 1.0 (1000 milésimas):**
   Sufre una penalización estricta del 50% mediante `(power * 1000) / 2000`.
4. **Escala por experiencia:**
   Cada punto de experiencia aporta un incremento lineal de efectividad (factor 10 en milésimas, 100 exp = +100% potencia).
5. **Escalado tecnológico nacional:**
   El poder total se amplifica o atenúa por la suma de la base de defines (`+0xE0`) y el bono del país (`+0x70`), permitiendo representar doctrinas de combate avanzadas.

---

## 6. Criterio de Verificación de Evidencia
- **Verificación Estática:**
  - 186 instrucciones verificadas formalmente en `0x005D02F0..0x005D04FB`.
  - Slots 26 en vtables de `CArmy` (`0x00DF8934`) y `CNavy` (`0x00E03034`).
  - Slots 12 y 13 en vtables de `CRegiment` y `CShip`.
  - Constantes de punto flotante en `0x00E45A18` (`100.5f`) y `0x00E45BBC` (`10.5f`).
  - Punteros globales en `0x012587E4`, `0x012586DC` y `0x0125FED8`.
  - Control negativo con aserción errónea refutada (`REFUTED`) y cascada dependiente invalidada (`INVALIDATED`).
- **Verificación Dinámica:**
  - Emulación completa en Unicorn Engine contrastada contra `unit_full_combat_power_model.py` sobre al menos 50 fixtures heterogéneos con 0 discrepancias.
