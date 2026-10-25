# Contrato: Ciclo Diario de Mantenimiento Naval y Aplicación de Daño por Atrición (`CNavy::DailyUpdate` y `CSubUnit::SetStrength`)

## 1. Identificación y Alcance
- **Binario:** `base-game/v2game.exe` (SHA-256: `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`).
- **Direcciones de las rutinas:**
  - `CNavy::DailyUpdate`: `0x005C7AE0..0x005C7B79` (153 bytes, 54 instrucciones).
  - `CSubUnit::SetStrength`: `0x005C02F0..0x005C036A` (122 bytes, 46 instrucciones).
- **Vtables:**
  - `CNavy` (vtable base en `0x00E02FCC`, RTTI COL en `0x00E5085C`):
    - Slot 29 (`+0x74` en `0x00E03040`): `0x005C7AE0` (`CNavy::DailyUpdate`).
    - Slot 31 (`+0x7C` en `0x00E03048`): `0x005D7EC0` (`CNavy::CalculateSeaAttrition`).
  - `CArmy` (vtable base en `0x00DF88CC`, RTTI COL en `0x00E4B2BC`):
    - Slot 29 (`+0x74` en `0x00DF8940`): `0x005C7B80` (`CArmy::DailyUpdate`).
  - `CShip` / `CRegiment` (`CSubUnit`):
    - Slot 12 (`+0x30` en `0x00E02A94` / `0x00DF88B4`): `0x005BFF80` (`CSubUnit::GetMaxStrength`).
- **Llamadores confirmados:**
  - `CNavy::DailyUpdate` (`0x005C7AE0`): invocado polimórficamente a través del slot 29 (`+0x74`) por el despachador de actualización diaria de unidades navales del motor (`0x00452CC1`, `0x005C5E80`).
  - `CSubUnit::SetStrength` (`0x005C02F0`):
    - `0x005C7B69` en `CNavy::DailyUpdate` (aplicación de atrición marítima).
    - `0x005C8D2A` en `CArmy::DailyUpdate` (aplicación de bajas y refuerzo terrestre).
    - `0x005D0813` en división y reorganización de unidades militares.
- **Convención de llamada:**
  - `CNavy::DailyUpdate`: `__thiscall`, `ecx = this` (`CNavy*`), epílogo `ret`.
  - `CSubUnit::SetStrength`: `__thiscall` o fastcall con `this` en `esi`/`ecx`, argumento `new_strength` en `[esp + 4]` / `[ebp + 8]`. Epílogo `ret 4`.

---

## 2. Estructura de Memoria y Offsets

### Estado Global del Juego (`CGameState`, puntero en `0x012588E8`)
- `+0xD1C`: `uint8 m_bNavalAttrition` (conmutador maestro de atrición naval; si es 0, la rutina aborta el procesamiento de atrición).

### Objeto de Definiciones Globales (`CDefines`, puntero en `0x012586DC`)
- `+0x20`: Puntero al bloque militar `CDefines::MilitaryDefines`.

### Definiciones Militares (`MilitaryDefines`)
- `+0xE4`: `int32 m_nNavalRangeDivisor` (umbral de alcance y divisor logístico de travesía).
- `+0xE8`: `int32 m_nMinShipStrength` (suelo mínimo de fuerza por debajo del cual la atrición no causa daño al buque).
- `+0xEC`: `int32 m_nMaxNavalAttrition` (atrición máxima porcentual diaria en milésimas).
- `+0xF0`: `int32 m_nNavalAttritionGracePeriod` (periodo de gracia en milisegundos / milésimas).

### Objeto Flota Naval (`CNavy`)
- `+0x00`: Vtable (`0x00E02FCC`).
- `+0x38`: Puntero a la lista enlazada de buques (`SubUnitNode* m_subunits_head`).
- `+0xB0`: Eficiencia logística / alcance de suministro actual (`int32 m_nSupplyEfficiency`).
- `+0x1BC`: Contador de días en navegación sin aprovisionamiento (`int32 m_nTimeAtSea`).

### Nodo de Subunidad (`SubUnitNode`)
- `+0x00`: Puntero al buque `CSubUnit* ship`.
- `+0x08`: Siguiente nodo `SubUnitNode* next`.

### Objeto Buque / Subunidad (`CSubUnit`)
- `+0x00`: Vtable (`0x00E02A64` para buques `CShip`).
- `+0x38`: Puntero al descriptor de tipo `CUnitType* m_type`.
- `+0x3C`: Fuerza actual en milésimas (`int32 m_nStrength`).

---

## 3. Formulación Algorítmica y Matemática

### 1. Ciclo Diario Naval (`CNavy::DailyUpdate`, `0x005C7AE0`)
1. **Actualización Base:**
   Invoca la rutina base de unidad `CUnit::DailyUpdate` (`0x005C7B80`).
2. **Comprobación de Atrición Global:**
   Lee `[0x012588E8] + 0xD1C`. Si es igual a 0, finaliza inmediatamente sin modificar el estado naval.
3. **Control de Abastecimiento y Días en Alta Mar:**
   Compara la eficiencia logística de la flota $S = \text{this}\to\text{m\_nSupplyEfficiency}$ (`[this + 0xB0]`) contra el umbral $R = \text{defines}\to\text{m\_nNavalRangeDivisor}$ (`[defines + 0xE4]`):
   - Si $S \ge R$ (la flota se encuentra debidamente aprovisionada):
     $$\text{this}\to\text{m\_nTimeAtSea} = 0$$
   - Si $S < R$ (la flota carece de línea de suministro suficiente):
     $$\text{this}\to\text{m\_nTimeAtSea} \mathrel{+}= 1$$
4. **Cálculo de Desgaste por Travesía:**
   Invoca virtualmente `this->CalculateSeaAttrition(&attrition)` (slot 31 en `0x005D7EC0`):
   - Si $\text{attrition} \le 0$, finaliza el ciclo sin infligir daño.
5. **Aplicación de Daño a Buques:**
   Si $\text{attrition} > 0$:
   - Lee el umbral mínimo $F = \text{defines}\to\text{m\_nMinShipStrength}$ (`[defines + 0xE8]`).
   - Itera por cada buque $U_k$ en `this->m_subunits_head`:
     - Lee la fuerza viva actual $H_k = U_k\to\text{m\_nStrength}$.
     - Si $H_k \le F$, salta al siguiente buque sin aplicar reducción.
     - Si $H_k > F$:
       $$H_k' = \max(F, H_k - \text{attrition})$$
       Invoca `U_k->SetStrength(H_k')` (`0x005C02F0`).

### 2. Fijación y Clamping de Fuerza (`CSubUnit::SetStrength`, `0x005C02F0`)
1. Consulta la fuerza máxima $M = U_k\to\text{GetMaxStrength}()$ (slot 12 de vtable).
2. Aplica limitador superior:
   $$\text{val}_1 = \min(M, \text{new\_strength})$$
3. Evalúa la cota inferior $0$ mediante constructor en línea `CFixedPoint(0.0f)` ($\lfloor (0.0 + 0.0005) \times 1000.0 \rfloor = 0$).
4. Aplica limitador inferior:
   $$\text{clamped} = \max(0, \text{val}_1) = \text{clamp}(\text{new\_strength}, 0, M)$$
5. Asigna `this->m_nStrength = clamped`.

---

## 4. Reconstrucción en Pseudocódigo C++

```cpp
void __thiscall CNavy::DailyUpdate() {
    // 1. Invocar actualización base de unidad
    CUnit::DailyUpdate();

    // 2. Comprobar si la atrición naval está activa en el mundo
    if (g_pGameState->m_bNavalAttrition == 0) {
        return;
    }

    // 3. Evaluar alcance logístico y actualizar contador de días en mar
    int32_t range_divisor = g_pDefines->m_pMilitaryDefines->m_nNavalRangeDivisor;
    if (this->m_nSupplyEfficiency >= range_divisor) {
        this->m_nTimeAtSea = 0;
    } else {
        this->m_nTimeAtSea++;
    }

    // 4. Calcular atrición por travesía marítima (slot 31)
    CFixedPoint attrition;
    this->CalculateSeaAttrition(&attrition);

    if (attrition.m_value <= 0) {
        return;
    }

    // 5. Aplicar desgaste a cada buque respetando el umbral mínimo
    int32_t min_strength = g_pDefines->m_pMilitaryDefines->m_nMinShipStrength;
    SubUnitNode* node = this->m_subunits_head;
    while (node != nullptr) {
        CSubUnit* ship = node->subunit;
        node = node->next;

        int32_t current_strength = ship->m_nStrength;
        if (current_strength > min_strength) {
            int32_t damaged_strength = current_strength - attrition.m_value;
            if (damaged_strength < min_strength) {
                damaged_strength = min_strength;
            }
            ship->SetStrength(damaged_strength);
        }
    }
}

void __thiscall CSubUnit::SetStrength(int32_t new_strength) {
    CFixedPoint max_str_fp;
    this->GetMaxStrength(&max_str_fp, 0);
    int32_t max_strength = max_str_fp.m_value;

    int32_t clamped = new_strength;
    if (clamped > max_strength) {
        clamped = max_strength;
    }

    int32_t zero_bound = CFixedPoint(0.0f).m_value; // 0
    if (clamped < zero_bound) {
        clamped = zero_bound;
    }

    this->m_nStrength = clamped;
}
```

---

## 5. Casos de Borde y Comportamientos Críticos
1. **Atrición desactivada globalmente (`m_bNavalAttrition == 0`):**
   La rutina aborta de inmediato en `0x005C7AFA`; `m_nTimeAtSea` no cambia y ningún buque recibe daño.
2. **Flota debidamente abastecida (`m_nSupplyEfficiency >= range`):**
   `m_nTimeAtSea` se reinicia a 0 en `0x005C7B1B`, lo que reinicia el periodo de gracia y previene cualquier atrición.
3. **Flota desabastecida (`m_nSupplyEfficiency < range`):**
   `m_nTimeAtSea` se incrementa en 1 cada día. Al superar el periodo de gracia en `CalculateSeaAttrition`, comienza a generar atrición diaria.
4. **Piso de supervivencia (`m_nMinShipStrength`):**
   Los buques cuya fuerza sea igual o inferior a este umbral (típicamente 100 milésimas) no sufren daño adicional por atrición marítima pura, impidiendo que la atrición hunda buques pacíficamente sin combate (el hundimiento total se reserva para el combate naval o stackwipe).
5. **Clamping estricto en `SetStrength`:**
   Garantiza que la fuerza del buque nunca exceda su capacidad de casco (`max_strength`) ni caiga por debajo de cero.

---

## 6. Criterio de Verificación de Evidencia
- **Verificación Estática:**
  - 54 instrucciones de `CNavy::DailyUpdate` (`0x005C7AE0..0x005C7B79`).
  - 46 instrucciones de `CSubUnit::SetStrength` (`0x005C02F0..0x005C036A`).
  - Vtable slots: `CNavy` slot 29 (`+0x74`), `CNavy` slot 31 (`+0x7C`), `CArmy` slot 29 (`+0x74`), `CShip` slot 12 (`+0x30`).
  - Punteros globales de singletons: `0x012588E8` y `0x012586DC`.
  - Constantes de defines y offsets de objetos.
  - Control negativo con aserción errónea refutada (`REFUTED`) y cascada dependiente invalidada (`INVALIDATED`).
- **Verificación Dinámica:**
  - Emulación completa en Unicorn Engine de la rutina original `0x005C7AE0` interactuando con la rutina original `0x005C02F0` y el método virtual real `0x005D7EC0` (`CalculateSeaAttrition`), contrastada con `navy_daily_update_model.py` con 0 discrepancias.
