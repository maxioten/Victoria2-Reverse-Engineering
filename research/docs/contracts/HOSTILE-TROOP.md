# Contrato: Determinación de Amenaza Hostil Provincial y Fuerzas Beligerantes (`CProvince::CalculateHostileTroopDivisions` y `CProvince::CountHostileRegiments`)

## 1. Identificación y Alcance
- **Binario:** `base-game/v2game.exe` (SHA-256: `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`).
- **Direcciones de las rutinas:**
  - `CProvince::CalculateHostileTroopDivisions`: `0x005DC7C0..0x005DC8AD` (238 bytes, 76 instrucciones).
  - `CProvince::CountHostileRegiments`: `0x005DC8B0..0x005DC938` (137 bytes, 49 instrucciones).
- **Llamadores confirmados:**
  - `CalculateHostileTroopDivisions` (`0x005DC7C0`):
    - `0x00828CF4` en `CArmyView::EvaluateThreatRatio` (`0x00828CA0`), comparando la presencia de divisiones hostiles frente a las fuerzas amigas para evaluar retiradas tácticas.
    - `0x00829484` en `CArmyView::UpdateSiegeThreat` (`0x00829400`).
  - `CountHostileRegiments` (`0x005DC8B0`):
    - `0x00828A13` en `CArmyView::CheckEnemyPresence` (`0x00828A00`), verificando si existe al menos 1 regimiento hostil en la provincia (`cmp eax, 1; jge ...`).
    - `0x0082A666` en `CArmyView::CanSplitOrMerge` (`0x0082A600`).
    - `0x0082DAF9`, `0x0082DBF0` en `CArmyView::UpdateCommandButtons` (`0x0082DA00`).
- **Convención de llamada:**
  - Ambas rutinas son funciones de ayuda territorial con el puntero a la lista provincial de ejércitos en `eax` (`ArmyNode** pArmyListHead`), y argumentos en pila:
    - `[ebp + 8]`: Tag de 3 caracteres del país objetivo (e.g. `"ENG"` o `"REB"`).
    - `[ebp + 0xc]`: Identificador numérico del país objetivo (`target_country_id`, `int32`).
  - Epílogo: `ret 8`. Retornan el resultado entero en `eax`.

---

## 2. Estructura de Memoria y Offsets

### Nodo de Ejército (`ArmyNode`)
- `+0x00`: Puntero a la formación militar `CArmy`
- `+0x08`: Puntero al siguiente `ArmyNode*`

### Formación Militar (`CArmy`)
- `+0x00`: Puntero a tabla virtual (`vtable`)
  - Slot 15 (`+0x3C`): `virtual bool IsNavy() const`
- `+0x38`: Puntero a la lista de subunidades / regimientos (`SubUnitNode*`)
- `+0x40`: Recuento total de subunidades en la formación (`subunit_count`, `int32`)
- `+0xC4`: Identificador numérico del país propietario (`country_id`, `int32`)

### Nodo de Subunidad (`SubUnitNode`)
- `+0x00`: Puntero al regimiento `CRegiment`
- `+0x08`: Puntero al siguiente `SubUnitNode*`

### Objeto Regimiento (`CRegiment`)
- `+0x3C`: Efectivos vivos actuales del regimiento (`strength`, `int32`)

### Gestor Mundial y Estructura Diplomática
- `0x012587E4`: Puntero global al motor del mundo (`pWorld`)
- `[pWorld + 4]`: Array de punteros a países (`CCountry** countries`)
- `[country + 0x1C]`: Tag nacional de 3 caracteres ASCII (`tag`, e.g. `"REB"`, `"FRA"`, `"PRU"`)
- `[country + 0x20]`: Identificador del país (`country_id`, `int32`)
- `[country + 0xBE8]`: Matriz de relaciones diplomáticas (`CDiplomaticRelation**`)
- `[relation + 0x34]`: Estado de guerra formal (`is_at_war`, `int32`: 1 si existe guerra, 0 de lo contrario)

---

## 3. Formulación Algorítmica y Lógica de Hostilidad

Para cada formación $A_k \in \mathcal{L}_{\text{armies}}$:
1. **Filtro Naval:**
   Invoca virtualmente `A_k->IsNavy()` (slot 15, `+0x3C`). Si retorna `true` (`al != 0`), la formación naval es descartada inmediatamente.
2. **Filtro Nacional Propio:**
   Recupera el objeto país propietario $C_k = \text{countries}[A_k.\text{country\_id}]$.
   Si $C_k.\text{country\_id} == \text{target\_country\_id}$, la unidad es aliada y se descarta.
3. **Determinación Diplomática de Beligerancia:**
   - Comprueba la tabla de relaciones diplomáticas: $\text{rel} = C_k.\text{relations}[\text{target\_country\_id}]$.
   - Si $\text{rel}.\text{is\_at\_war} \neq 0$: la unidad está formalmente en guerra ($\text{hostile} = \text{true}$).
   - Si no hay guerra formal:
     - Comprueba si el país objetivo es la facción rebelde ($\text{target\_tag} == \texttt{"REB"}$, bytes `0x52, 0x45, 0x42`). Si coincide: $\text{hostile} = \text{true}$.
     - Comprueba si el país del ejército es la facción rebelde ($C_k.\text{tag} == \texttt{"REB"}$). Si coincide: $\text{hostile} = \text{true}$.
   - Si ninguna condición se cumple, la unidad neutral no beligerante es ignorada.
4. **Agregación de Masa Militar:**
   - **En `CalculateHostileTroopDivisions` (`0x005DC7C0`):**
     Inicializa con $0.0005 \times 1000.0 = 0$.
     Recorre todos los regimientos $R_{k,j} \in A_k$ y acumula sus efectivos vivos ($R_{k,j}.\text{strength}$ en `+0x3C`).
     Suma al total provincial: $\text{TotalHostileMen} \mathrel{+}= \text{ArmyHostileMen}$.
     Al finalizar todos los ejércitos, normaliza a divisiones estándar de 1,000 hombres mediante división entera optimizada con la constante mágica $\texttt{0x10624DD3}$:
     $$\text{HostileDivisions} = \left\lfloor \frac{\text{TotalHostileMen}}{1000} \right\rfloor$$
     Retorna `eax = HostileDivisions`.
   - **En `CountHostileRegiments` (`0x005DC8B0`):**
     Acumula directamente el número nominal de subunidades del ejército hostil:
     $$\text{TotalHostileRegiments} \mathrel{+}= A_k.\text{subunit\_count}$$
     Retorna `eax = TotalHostileRegiments`.

---

## 4. Criterio de Evidencia y Verificación
- Verificación estática con Reverify sobre las 125 instrucciones en PE32 de ambas rutinas (`0x005DC7C0` y `0x005DC8B0`).
- Comprobación de la constante de división entera `0x10624DD3`.
- Comprobación de las constantes de caracteres ASCII para la detección rebelde (`0x52` = 'R', `0x45` = 'E', `0x42` = 'B').
- Verificación de los call sites en `CArmyView` (`0x00828A13`, `0x00828CF4`, `0x00829484`).
- Control negativo `REFUTED` y control dependiente `INVALIDATED`.
- Emulación dinámica con Unicorn Engine en un espectro exhaustivo de estados geopolíticos:
  - Formaciones vacías.
  - Flotas navales (filtradas).
  - Tropas del mismo país (filtradas).
  - Países neutrales en paz (filtrados).
  - Países beligerantes en guerra declarada.
  - Ejércitos rebeldes (`"REB"`).
  - Provincias rebeldes ocupadas.
  - Agrupaciones multinacionales combinadas sin discrepancias frente al modelo analítico Python.
