# Contrato: Determinación de Fuerza Hostil Naval y Censo Directo de Beligerancia Provincial (`CProvince::CalculateHostileNavalDivisions` y `CProvince::CountHostileUnitsDirect`)

## 1. Identificación y Alcance
- **Binario:** `base-game/v2game.exe` (SHA-256: `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`).
- **Direcciones de las rutinas:**
  - `CProvince::CalculateHostileNavalDivisions`: `0x005DC940..0x005DCA2F` (240 bytes, 78 instrucciones).
  - `CProvince::CountHostileUnitsDirect`: `0x005DCA30..0x005DCAB4` (133 bytes, 50 instrucciones).
- **Llamadores confirmados:**
  - `CalculateHostileNavalDivisions` (`0x005DC940`):
    - `0x005B9AC3`: Evaluación de hostilidad naval en patrulla costera / bloqueo marítimo (`0x005B9A30`), multiplicando por 1000 (`imul eax, eax, 0x3e8`) para calcular el contingente naval enemigo total en la zona.
    - `0x005B9CB2`: Verificación de superioridad marítima contra flota interceptora (`0x005B9C9E`), comparando el contingente hostil provincial (`divisions * 1000`) contra la potencia de flota propia (`[fleet + 0x8C]`).
  - `CountHostileUnitsDirect` (`0x005DCA30`):
    - `0x008238F0` en `CArmyView::UpdateCombatOdds` (`0x00823890`), censando directamente la totalidad de regimientos hostiles en la provincia (almacenado en `[esp + 0x30]`).
- **Convención de llamada:**
  - `CalculateHostileNavalDivisions` (`0x005DC940`):
    - `eax`: Puntero a la cabecera de la lista provincial de formaciones (`ArmyNode** pArmyListHead`).
    - `[esp + 4]` / `[ebp + 8]`: Tag ASCII de 3 caracteres del país objetivo (e.g. `"ENG"` o `"REB"`).
    - `[esp + 8]` / `[ebp + 0xc]`: Identificador numérico del país objetivo (`target_country_id`, `int32`).
    - Epílogo: `ret 8`. Retorna el número de divisiones/escuadrones navales hostiles (`int32`) en `eax`.
  - `CountHostileUnitsDirect` (`0x005DCA30`):
    - `ecx`: Puntero a la cabecera de la lista provincial de formaciones (`ArmyNode** pArmyListHead`).
    - `[esp + 4]` / `[ebp + 8]`: Tag ASCII de 3 caracteres del país objetivo.
    - `[esp + 8]` / `[ebp + 0xc]`: Identificador numérico del país objetivo (`target_country_id`, `int32`).
    - Epílogo: `ret 8`. Retorna el censo total de regimientos/subunidades hostiles (`int32`) en `eax`.

---

## 2. Estructura de Memoria y Vtables

### Tabla Virtual Polimórfica de `CUnit` (`CArmy` y `CNavy`)
- `CArmy` (vtable base en `0x00DF88CC`):
  - Slot 14 (`+0x38`, `0x00DF8904`): `virtual bool IsLand() const` -> `0x00A31490` (`mov al, 1; ret`). Retorna `true`.
  - Slot 15 (`+0x3C`, `0x00DF8908`): `virtual bool IsNavy() const` -> `0x0058CFD0` (`xor al, al; ret`). Retorna `false`.
- `CNavy` (vtable base en `0x00E02FCC`):
  - Slot 14 (`+0x38`, `0x00E03004`): `virtual bool IsLand() const` -> `0x0058CFD0` (`xor al, al; ret`). Retorna `false`.
  - Slot 15 (`+0x3C`, `0x00E03008`): `virtual bool IsNavy() const` -> `0x00A31490` (`mov al, 1; ret`). Retorna `true`.

### Nodo de Formación (`ArmyNode`)
- `+0x00`: Puntero a la formación militar `CUnit*` (`CArmy` o `CNavy`).
- `+0x08`: Puntero al siguiente `ArmyNode*`.

### Formación Militar (`CUnit`)
- `+0x00`: Puntero a vtable (`0x00DF88CC` o `0x00E02FCC`).
- `+0x38`: Puntero a la lista enlazada de subunidades (`SubUnitNode*`).
- `+0x40`: Conteo total de subunidades / regimientos en la formación (`subunit_count`, `int32`).
- `+0xC4`: Identificador numérico del país propietario (`country_id`, `int32`).

### Objeto Subunidad (`CSubUnit` / `CShip` / `CRegiment`)
- `+0x3C`: Efectivos vivos actuales / potencia del buque (`strength`, `int32`).

### Gestor Mundial y Diplomacia
- `0x012587E4`: Puntero global al motor del mundo (`pWorld`).
- `[pWorld + 4]`: Array de punteros a objetos país (`CCountry** countries`).
- `[country + 0x1C]`: Tag nacional de 3 caracteres ASCII (`tag`, e.g. `"REB"`, `"ENG"`).
- `[country + 0x20]`: Identificador del país (`country_id`, `int32`).
- `[country + 0xBE8]`: Matriz de relaciones diplomáticas (`CDiplomaticRelation**`).
- `[relation + 0x34]`: Estado de guerra formal (`is_at_war`, `int32`: 1 si existe guerra, 0 de lo contrario).

---

## 3. Formulación Algorítmica y Lógica de Beligerancia

### A. Cálculo de Divisiones Navales Hostiles (`CalculateHostileNavalDivisions`, `0x005DC940`)
Para cada formación $U_k \in \mathcal{L}_{\text{units}}$:
1. **Filtro Terrestre Polimórfico:**
   Invoca virtualmente `U_k->IsLand()` (slot 14, `+0x38`).
   Si retorna `true` (`al != 0`), la formación terrestre es descartada. Esta rutina procesa exclusivamente flotas navales (`CNavy`).
2. **Filtro Nacional Propio:**
   Recupera el objeto país propietario $C_k = \text{countries}[U_k.\text{country\_id}]$.
   Si $C_k.\text{country\_id} == \text{target\_country\_id}$, la flota es aliada propia y se descarta.
3. **Determinación Diplomática y Rebelde:**
   - Comprueba la tabla de relaciones: $\text{rel} = C_k.\text{relations}[\text{target\_country\_id}]$.
   - Si $\text{rel}.\text{is\_at\_war} \neq 0$: la unidad está formalmente en guerra ($\text{hostile} = \text{true}$).
   - Si no hay guerra formal:
     - Si $\text{target\_tag} == \texttt{"REB"}$ (`0x52, 0x45, 0x42`): $\text{hostile} = \text{true}$.
     - Si $C_k.\text{tag} == \texttt{"REB"}$: $\text{hostile} = \text{true}$.
   - De lo contrario, la flota neutral es ignorada.
4. **Agregación de Potencia Naval y Normalización:**
   - Inicializa acumulador mediante $0.0005 \times 1000.0 = 0$.
   - Recorre todos los buques $S_{k,j} \in U_k$ sumando su potencia ($S_{k,j}.\text{strength}$ en `+0x3C`).
   - Acumula en el total provincial: $\text{TotalHostileMen} \mathrel{+}= \text{FleetMen}$.
   - Al finalizar, normaliza a divisiones navales estándar con la constante mágica $\texttt{0x10624DD3}$:
     $$\text{NavalDivisions} = \left\lfloor \frac{\text{TotalHostileMen}}{1000} \right\rfloor$$
     Retorna `eax = NavalDivisions`.

### B. Censo Directo de Beligerancia Provincial (`CountHostileUnitsDirect`, `0x005DCA30`)
Para cada formación $U_k \in \mathcal{L}_{\text{units}}$:
1. **Sin Filtro de Rama Militar:**
   No invoca métodos virtuales; evalúa de manera homogénea formaciones terrestres y navales en la provincia.
2. **Filtro Nacional Propio y Evaluación Diplomática/Rebelde:**
   Aplica exactamente las mismas reglas de beligerancia (exclusión de país propio, guerra formal activa o presencia del tag `"REB"`).
3. **Agregación de Unidades Brutas:**
   Acumula directamente el conteo nominal de regimientos/buques en la formación:
   $$\text{TotalHostileUnits} \mathrel{+}= U_k.\text{subunit\_count}$$
   Retorna `eax = TotalHostileUnits`.

---

## 4. Criterio de Evidencia y Verificación
- Verificación estática Reverify:
  - 78 instrucciones de `0x005DC940..0x005DCA2F`.
  - 50 instrucciones de `0x005DCA30..0x005DCAB4`.
  - Punteros de vtable en slot 14 (`IsLand`, `+0x38`) en `CArmy` (`0x00DF8904` -> `0x00A31490`) y `CNavy` (`0x00E03004` -> `0x0058CFD0`).
  - Punteros de vtable en slot 15 (`IsNavy`, `+0x3C`) en `CArmy` (`0x00DF8908` -> `0x0058CFD0`) y `CNavy` (`0x00E03008` -> `0x00A31490`).
  - Constante de división entera `0x10624DD3`.
  - Constantes de punto flotante `0x00E45840` ($0.0005$) y `0x00E45660` ($1000.0$).
  - Caracteres ASCII rebeldes (`0x52`, `0x45`, `0x42`).
  - Call sites en `0x005B9AC3`, `0x005B9CB2`, `0x008238F0`.
  - Control negativo `REFUTED` y cascada `INVALIDATED`.
- Emulación dinámica Unicorn:
  - Cobertura integral de flotas navales, regimientos de infantería, formaciones combinadas, ejércitos aliados, países neutrales, beligerantes en guerra declarada y fuerzas rebeldes insurgentes con 0 discrepancias frente a `hostile_naval_direct_model.py`.
