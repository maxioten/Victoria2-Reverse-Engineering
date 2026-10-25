# Contrato: Suficiencia de Suministro y Carga Logística Provincial (`CArmy::EvaluateSupplySufficiency`)

## 1. Identificación y Alcance
- **Binario:** `base-game/v2game.exe` (SHA-256: `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`).
- **Dirección de la rutina:** `0x005D5E30..0x005D5EE3` (180 bytes, 69 instrucciones).
- **Vtable slot 3 (`+0x0C`):**
  - `0x00DF8950`: Entrada en la vtable de `CArmy` (`0x00DF8944 + 0x0C`).
- **Convención de llamada:** `__thiscall` con `ecx = pArmy`, argumento en pila `[esp + 4] = pProvince`. Retorno booleano en `al` (`setge al`), epílogo `ret 4`.

---

## 2. Estructuras de Memoria y Offsets

### Objeto `CArmy`
- `+0x00`: Puntero a vtable (`0x00DF8944`)
- `+0x40`: `supply_weight` (int32, demanda de suministro en regimientos/milésimas)
- `+0xC4`: `country_id` (int32, identificador numérico de país)
- `+0x164`: `is_embarked` (uint8, flag de transporte naval)
- Vtable slot 14 (`+0x38`): `IsAlliedTo`
- Vtable slot 15 (`+0x3C`): `IsSupplyContributor`

### Objeto `CProvince`
- `+0x5C`: Puntero a tipo de terreno `CTerrainType*`
- `+0xEC`: Puntero a lista enlazada de ejércitos estacionados `stationed_armies_head` (nodos de 12 bytes con `[node] = pArmy`, `[node + 8] = pNext`)

### Objeto `CTerrainType`
- `+0x2A`: `is_water` (uint8, indicador de zona marítima)

---

## 3. Formulación Algorítmica y Matemática

1. **Bifurcación Marítima vs Terrestre:**
   - Si `[pTerrainType + 0x2A] != 0` (marítima):
     - Si `[pArmy + 0x164] != 0` (embarcado en transporte protegido): retorna `True` (1).
     - Si no: delega a `pArmy->CanTraverseSea(pProvince)` (`0x005CD2F0`).
2. **Agregación Logística en Provincia Terrestre:**
   - Demanda inicial: $\text{demanded} = \text{this\_army.supply\_weight}$.
   - Capacidad inicial: $\text{capacity} = 0$.
   - Para cada ejército estacionado $A_i \ne \text{this\_army}$:
     - Si $A_i.\text{country\_id} == \text{this\_army.country\_id}$:
       - Si $A_i.\text{IsAlliedTo}()$ es verdadero:
         $$\text{demanded} \mathrel{+}= A_i.\text{supply\_weight}$$
       - Si $A_i.\text{IsSupplyContributor}()$ es verdadero:
         $$\text{capacity} \mathrel{+}= \text{GetArmyEffectiveCapacity}(A_i)$$
3. **Criterio de Suficiencia:**
   $$\text{return } (\text{capacity} \ge \text{demanded})$$
   Retorna en `al` 1 si hay autosuficiencia logística (sin desgaste por sobrecarga), o 0 si la demanda supera la capacidad (provocando desgaste provincial).

---

## 4. Criterio de Evidencia y Verificación
- Verificación estática con Reverify sobre todas las 69 instrucciones en PE32 de `0x005D5E30..0x005D5EE3`.
- Verificación de slot de vtable (`bytes_at`) en `CArmy` (`0x00DF8950`).
- Control negativo en target offset desfasado (`REFUTED`).
- Cascada de invalidación dependiente (`INVALIDATED`).
- Emulación dinámica con Unicorn en memoria sintética, cubriendo provincias marítimas (embarcado vs no embarcado), ejércitos solitarios, coaliciones del mismo país con superávit o déficit, y ejércitos de terceros países ignorados con 0 discrepancias frente a `army_supply_sufficiency_model.py`.
