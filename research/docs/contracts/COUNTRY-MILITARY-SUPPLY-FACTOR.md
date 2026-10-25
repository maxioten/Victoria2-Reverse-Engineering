# Contrato Formal: Agregación de Modificadores Tecnológicos y Suministro Militar (COUNTRY-MILITARY-SUPPLY-FACTOR)

- **Binario objetivo:** `base-game/v2game.exe`
- **SHA-256:** `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`
- **Rutina objeto:** `0x00520150..0x00520485` en `CCountry::DailyUpdateMilitarySupply` (bloque de cálculo `0x005203E3..0x00520460`)
- **Llamadores confirmados (22 sitios en total):**
  - `0x00538055` en el despachador diario de subsistemas nacionales (`0x00538040`)
  - `0x0068BF20` en actualización económica completa (`EconomyManager_UpdateFull`)
  - `0x00524D3F` en evaluación presupuestaria de IA militar
  - `0x00662B5F` en declaración de guerra y movilización
  - `0x0067F737` en liquidación de tratados de paz y desmovilización

---

## 1. Mapeo de Estructuras y Registros

| Parámetro / Campo | Registro / Offset | Descripción |
|---|---|---|
| `this` (`CCountry`) | `EBX` | Instancia nacional del país |
| `party_policy` | `[EBX + 0xA60]` | Objeto de política del partido gobernante |
| `party_military_bonus` | `[party + 0x380]` | Bonificación militar por política de partido |
| `tech_manager` | `[EBX + 0xBCC]` | Gestor tecnológico nacional |
| `tech_military_bonus` | `[tech_mgr + 0x60]` | Bonificación militar por tecnologías investigadas |
| `defines_sub` | `[0x12586DC + 0x40]` | Puntero al sub-bloque de defines militares y económicos |
| `global_military_base` | `[defines_sub + 0x10]` | Valor base global de suministro militar |
| `secondary_supply_def` | `[defines_sub + 0x70]` | Modificador secundario de suministro militar |
| `maintenance_pool_1` | `[EBX + 0x14E0]` | Acumulador de mantenimiento naval/militar (reseteado a 0) |
| `maintenance_pool_2` | `[EBX + 0x13E8]` | Acumulador secundario de mantenimiento (reseteado a 0) |

---

## 2. Lógica Algorítmica y Normalización a 30 Bits

1. **Agregación Tripartita de Modificador de Suministro Primario:**
   El motor combina aditivamente las tres fuentes de doctrina militar:
   $$\text{total\_bonus} = \text{party\_military\_bonus} + \text{global\_military\_base} + \text{tech\_military\_bonus}$$
2. **Normalización a Punto Fijo de 15 bits:**
   Escala $\text{total\_bonus}$ a 30 bits mediante dos corrimientos consecutivos de 15 bits (`shld/shl 15`, luego `shld/shl 15`)
   y divide por la constante universal de defines $32,768,000$ ($32,768 \times 1000$) vía `__alldiv` (`0x00AC02A0`):
   $$\text{primary\_supply\_factor} = \left\lfloor \frac{\text{total\_bonus} \ll 30}{32,768,000} \right\rfloor$$
   Almacenado como entero con signo de 64 bits en `[EBP - 0x54 : EBP - 0x50]`.
3. **Reseteo de Pool de Mantenimiento Primario:**
   $$[EBX + 0\text{x}14\text{E}0] = 0$$
4. **Normalización del Factor de Suministro Secundario:**
   Normaliza el define secundario `[defines_sub + 0x70]`:
   $$\text{secondary\_supply\_factor} = \left\lfloor \frac{\text{secondary\_supply\_def} \ll 30}{32,768,000} \right\rfloor$$
   Almacenado en `[EBP - 0xA4]`.
5. **Reseteo de Pool de Mantenimiento Secundario:**
   $$[EBX + 0\text{x}13\text{E}8] = 0$$

---

## 3. Criterio de Verificación

1. **Reverify Estático:**
   - 52 aserciones de instrucciones binarias cubriendo los 5 llamadores clave, el prólogo y el bloque de cálculo de factores de suministro.
   - Control negativo contra objetivo erróneo con veredicto `REFUTED`.
   - Control dependiente con invalidación formal `INVALIDATED`.
2. **Emulación Dinámica en Unicorn:**
   - Contrastación del modelo formal en Python `country_military_supply_model.py` contra la ejecución nativa PE32.
   - Fixtures exhaustivos cubriendo bonificaciones positivas, negativas, nulas, valores altos y diversas combinaciones de doctrinas militares.
