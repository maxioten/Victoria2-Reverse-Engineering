# Contrato: Cálculo de Organización y Moral Máxima de Regimientos (`CRegiment::CalculateMaxMorale`)

## 1. Identificación y Alcance
- **Binario:** `base-game/v2game.exe`
- **SHA-256:** `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`
- **Dirección VA:** `0x005BFFA0..0x005C010C` (365 bytes, 126 instrucciones)
- **Símbolo inferido:** `CRegiment::CalculateMaxMorale(int* out_max_morale, void* context)` / virtual slot 13 (`+0x34`)
- **Entradas en VTables canónicas:**
  - `CRegiment::vtable[13]` en `0x00DF88B8` apunta a `0x005BFFA0`
  - `CSubUnit::vtable[13]` en `0x00E02A20` apunta a `0x005BFFA0`
- **Constantes de presupuesto militar:**
  - `0x00E45AC0` (`750.5` $\to 750$, componente variable del gasto militar)
  - `0x00E45A40` (`250.5` $\to 250$, piso rígido del 25% de moral nacional)

---

## 2. Convención de Llamada y Estructura de Objetos
- **Convención:** `thiscall` / registro `ecx` (`edi = this`), con 2 argumentos en pila (`ret 8`):
  - `[ebp + 8]`: Puntero a entero de 32 bits de salida (`int* out_max_morale`).
  - `[ebp + 0xC]`: Contexto adicional.
- **Estructura del Regimiento (`CRegiment` / `CSubUnit`):**
  - `+0x00`: Puntero a vtable virtual (`m_vtable`).
    - `vtable[9]` (`+0x24`): Método virtual `IsNavy()`.
    - `vtable[10]` (`+0x28`): Método virtual `IsArmy()`.
  - `+0x38`: Puntero al prototipo de unidad (`CSubUnitType*`).
    - `[type + 0xB4]` (DWORD): Moral / organización base de la unidad (escalada por 1000).
  - `+0x60` (DWORD / ASCII): Tag del país o facción propietaria (`m_tag` de 3 bytes: e.g. `'REB'`, `'FRA'`).
  - `+0x64` (DWORD): Índice del país en el registro de países (`0x012587E4`).
  - `+0x74`: Puntero al líder asignado (`CLeader*`, general o almirante).
    - `[leader + 0xD8]`: Puntero al rasgo de personalidad (`CTrait*`).
    - `[trait + 0x48]`: Puntero al bloque modificador (`CModifier*`).
    - `[modifier + 0x20]` (DWORD): Bono de moral del líder (escalado por 1000).
- **Estructura del País (`CCountry`):**
  - `+0xA60`: Puntero al partido gobernante (`CParty*`).
    - `[party + 0x68]` (DWORD): Modificador de doctrina naval del partido.
    - `[party + 0x70]` (DWORD): Modificador de doctrina militar/terrestre del partido.
  - `+0x1448 : 0x144C` (QWORD): Slider de gasto militar naval (30 bits, $32,768,000$).
  - `+0x1450 : 0x1454` (QWORD): Slider de gasto militar terrestre (30 bits, $32,768,000$).

---

## 3. Comportamiento y Algoritmo Exacto

1. **Lectura de moral base:**
   Recupera `base_morale = [type + 0xB4]` y almacena el valor inicial en `*out_morale`.

2. **Modificador de doctrina del partido gobernante:**
   - Si la unidad es naval (`IsNavy() == true`):
     $$\text{morale} = \left\lfloor \frac{\text{morale} \times (\text{naval\_doctrine} + 1000)}{1000} \right\rfloor$$
   - Si la unidad es terrestre (`IsArmy() == true`):
     $$\text{morale} = \left\lfloor \frac{\text{morale} \times (\text{army\_doctrine} + 1000)}{1000} \right\rfloor$$

3. **Modificador del líder militar:**
   - Si existe un general o almirante asignado (`[regiment + 0x74] != NULL`):
     $$\text{morale} = \left\lfloor \frac{\text{morale} \times (\text{leader\_morale\_mod} + 1000)}{1000} \right\rfloor$$

4. **Excepción de rebeldes (`"REB"`):**
   - Comprueba los primeros 3 bytes del tag en `[regiment + 0x60]`:
     Si `byte[0] == 0x52 ('R')` y `byte[1] == 0x45 ('E')` y `byte[2] == 0x42 ('B')`:
     Salta inmediatamente a `0x005C0104`, **omitiendo totalmente el presupuesto militar**. Los rebeldes combaten con el 100% de su moral sin verse afectados por recortes presupuestarios nacionales.

5. **Ajuste presupuestario por slider de gasto militar nacional:**
   - Para países soberanos, lee el slider correspondiente:
     - Armada: `slider = [country + 0x1448]`
     - Ejército: `slider = [country + 0x1450]`
   - Escala el valor a punto fijo mediante multiplicación y desplazamiento de 30 bits:
     $$\text{scaled} = (\text{slider} \times 32,768,000) \gg 30$$
   - Aplica la función lineal de presupuesto acotada entre 25% y 100%:
     $$\text{budget\_mult} = 250 + \left\lfloor \frac{\text{scaled} \times 750}{1000} \right\rfloor$$
     Esto garantiza un piso rígido del **25.0%** de moral incluso con gasto militar al 0%.
   - Aplica el multiplicador final a la moral acumulada:
     $$\text{final\_morale} = \left\lfloor \frac{\text{morale} \times \text{budget\_mult}}{1000} \right\rfloor$$
   - Persiste el resultado en `*out_morale`.

---

## 4. Garantías de Evidencia
- **Reverify:** 130 afirmaciones formales sobre las 126 instrucciones, ranuras virtuales 13 en `0x00DF88B8` y `0x00E02A20`, y constantes flotantes en `0x00E45AC0` y `0x00E45A40`.
- **Control Negativo e Invalidación en Cascada:**
  - Control negativo con instrucción corrupta en `0x005BFFA0` refutado (`REFUTED`).
  - Claim dependiente invalidado (`INVALIDATED`).
- **Emulación Dinámica con Unicorn:**
  - 140+ fixtures cubriendo unidades navales y terrestres, con y sin líder, facciones soberanas y rebeldes (`"REB"`), gasto militar de 0%, 50%, 100% y arbitrario con 0 discrepancias frente a `regiment_max_morale_model.py`.
