# Contrato de Evidencia Formal: Potencia de Combate de Formación Directa y Agregada (Suite 90)

## 1. Resumen Ejecutivo y Anclaje Binario

Este contrato formaliza la especificación matemática y de bajo nivel para el cálculo de potencia de combate de formaciones militares completas en el ejecutable PE32 `base-game/v2game.exe` (SHA-256: `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`).

El sistema articula dos métodos virtuales complementarios de la jerarquía polimórfica `CUnit`:
1. **`CUnit::CalculateDirectFormationCombatPower` (0x005D00E0..0x005D02E8, Slot 23 / `+0x5C`):**
   - Recorre la lista enlazada canónica de todas las subunidades directas de la formación (`[ecx + 0x38]`).
   - Evalúa cada subunidad integrando:
     - Calificación táctica intrínseca (`CUnitType::CalculateCombatRating` en `0x005BDC80`).
     - Ratio de salud/fuerza efectiva (`CSubUnit::GetMaxStrength` en slot 12 de `CSubUnit`).
     - Ratio de moral viva con anulación estricta a 0 para POPs de origen rebelde (`[pop + 0x164] != 0`).
     - Multiplicador de experiencia militar por factor 10 derivado de la constante `10.5f` (`0x00E45BBC` -> `0x0125FED8`).
     - Penalización por desmoralización o quebranto: si `strength < 100` (derivado de `100.5f` en `0x00E45A18`) o `morale < 1000`, la potencia sufre una reducción estricta del 50%: `(power * 1000) / 2000 = power / 2`.
   - Suma las potencias individuales y escala linealmente por la doctrina y tecnología nacional:
     $$\text{total\_tech} = \text{base\_combat\_power} (\text{MilitaryDefines} +0\text{xE0}) + \text{country\_tech\_bonus} (\text{MilitaryStats} +0\text{x70})$$
     $$\text{final\_power} = \lfloor \frac{\text{total\_power} \times \text{total\_tech}}{1000} \rfloor$$

2. **`CUnit::CalculateAggregateFormationCombatPower` (0x005D00A0..0x005D00D5, Slot 24 / `+0x60`):**
   - Recorre la lista enlazada de formaciones subordinadas o unidades agrupadas (`[ecx + 0x4C]`).
   - Invoca polimórficamente a través de su vtable el método slot 23 (`[child->vtable + 0x5C]`, `CalculateDirectFormationCombatPower`) para cada unidad hija:
     $$\text{aggregate\_power} = \sum_{\text{child} \in [ecx + 0x4C]} \text{child}->\text{CalculateDirectFormationCombatPower}()$$
   - Retorna la suma acumulada directa sin reescalado adicional, dado que cada formación hija ya integró sus respectivos modificadores nacionales.

---

## 2. Ubicación en Vtables y Constantes PE32

### Vtables de Formaciones Militares
| Entidad | Slot | Offset Vtable | Dirección Función | Nombre Simbólico |
|---|---|---|---|---|
| `CArmy` | 23 | `+0x5C` (`0x00DF8928`) | `0x005D00E0` | `CUnit::CalculateDirectFormationCombatPower` |
| `CArmy` | 24 | `+0x60` (`0x00DF892C`) | `0x005D00A0` | `CUnit::CalculateAggregateFormationCombatPower` |
| `CNavy` | 23 | `+0x5C` (`0x00E03028`) | `0x005D00E0` | `CUnit::CalculateDirectFormationCombatPower` |
| `CNavy` | 24 | `+0x60` (`0x00E0302C`) | `0x005D00A0` | `CUnit::CalculateAggregateFormationCombatPower` |

### Constantes y Singletons Globales
- **`0x00E45A18` (`float 100.5f`):** Convertido a entero `100` (`0x005D00FF..0x005D011B`), umbral de fuerza mínima bajo el cual se penaliza la unidad al 50%.
- **`0x0125FED8` (`int32` = 10):** Factor global de experiencia (proveniente de `10.5f` en `0x00E45BBC`), milésimas de bonificación por punto de experiencia.
- **`0x012587E4` (`Country Array`):** Puntero al array global de países indexado por `m_owner_country_id` (`[ecx + 0xC4]`).
- **`0x012586DC` (`MilitaryDefines Singleton`):** Puntero a la estructura global de definiciones militares, conteniendo el puntero de configuración en `+0x20` y la base en `+0xE0`.

---

## 3. Formulación Matemática Exacta

### A. Potencia de Subunidad Individual (`0x005D0120..0x005D0287`)
Para cada subunidad $i \in [ecx + 0x38]$:

1. **Ratio de Fuerza ($R_{str}$):**
   $$R_{str} = \begin{cases} -1 & \text{si } \text{max\_str} = 0 \\ \lfloor \frac{\text{strength} \times 1000}{\text{max\_str}} \rfloor & \text{en otro caso} \end{cases}$$
2. **Potencia de Salud ($P_{health}$):**
   $$P_{health} = \lfloor \frac{R_{str} \times \text{rating}}{1000} \rfloor$$
3. **Ratio de Moral ($R_{mor}$):**
   $$\text{eff\_mor} = \begin{cases} 0 & \text{si } \text{pop} \neq \text{NULL} \land \text{pop.rebel} \neq 0 \\ \text{morale} & \text{en otro caso} \end{cases}$$
   $$R_{mor} = \begin{cases} -1 & \text{si } \text{max\_mor} = 0 \\ \lfloor \frac{\text{eff\_mor} \times 1000}{\text{max\_mor}} \rfloor & \text{en otro caso} \end{cases}$$
4. **Multiplicador de Experiencia ($M_{exp}$):**
   $$M_{exp} = 1000 + \lfloor \frac{\text{exp} \times 10}{1000} \rfloor$$
5. **Potencia Combinada ($P_{raw}$):**
   $$P_1 = \lfloor \frac{R_{mor} \times P_{health}}{1000} \rfloor$$
   $$P_{raw} = \lfloor \frac{P_1 \times M_{exp}}{1000} \rfloor$$
6. **Penalización por Desmoralización / Fuerza Quebrantada:**
   $$P_{sub} = \begin{cases} \lfloor \frac{P_{raw} \times 1000}{2000} \rfloor = \lfloor \frac{P_{raw}}{2} \rfloor & \text{si } \text{strength} < 100 \lor \text{morale} < 1000 \\ P_{raw} & \text{en otro caso} \end{cases}$$

### B. Potencia de Formación Directa (`0x005D0298..0x005D02DE`)
$$P_{direct} = \lfloor \frac{(\sum_{i} P_{sub, i}) \times (\text{base\_tech} + \text{country\_bonus})}{1000} \rfloor$$

### C. Potencia Agregada (`0x005D00A0..0x005D00CD`)
$$P_{agg} = \sum_{\text{child} \in [ecx + 0x4C]} \text{child}->\text{CalculateDirectFormationCombatPower}()$$

---

## 4. Requisitos de Evidencia y Validación

1. **Verificación Estática PE32 (Reverify):**
   - Instrucciones exactas de `CUnit::CalculateDirectFormationCombatPower` (`0x005D00E0..0x005D02E8`, 186 insns, 520 bytes).
   - Instrucciones exactas de `CUnit::CalculateAggregateFormationCombatPower` (`0x005D00A0..0x005D00D5`, 25 insns, 53 bytes).
   - Verificación de slots 23 y 24 en vtables de `CArmy` (`0x00DF8928` / `0x00DF892C`) y `CNavy` (`0x00E03028` / `0x00E0302C`).
   - Verificación de lectura de constantes `0x00E45A18` y `0x0125FED8`.
2. **Control Negativo Reverify:**
   - Aserción alterada (`push ebp` cambiado por `sub ebp`) en el prólogo de `0x005D00A0` refutada (`REFUTED`), invalidando la cascada dependiente (`INVALIDATED`).
3. **Emulación Dinámica Unicorn Engine:**
   - 45+ fixtures independientes cubriendo formaciones vacías, subunidades individuales y mixtas, filtros rebeldes, penalización del 50%, escalado nacional y agregación de múltiples formaciones subordinadas vía virtual dispatch, con 0 discrepancias frente a `formation_combat_power_model.py`.
