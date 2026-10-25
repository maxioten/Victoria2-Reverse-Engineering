# Contrato: Prioridad Táctica y Ordenación de Reserva de Combate (`CSubUnit::CompareTacticalValue`)

## 1. Identificación y Alcance
- **Binario:** `base-game/v2game.exe` (SHA-256: `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`).
- **Dirección de la rutina:** `0x0059B780..0x0059B833` (84 bytes, 64 instrucciones).
- **Punto de llamada identificado (xref):**
  - Inserción ordenada en la cola de reserva de combate: `0x005AB8B7` (`call 0x0059B780` en `CLandCombatant::InsertReserveRegiment`).
- **Convención de llamada:** Pasaje por registros `edx` (puntero a `CSubUnit` A) y `eax` (puntero a `CSubUnit` B). Retorno booleano en `al` (`setl al`), indicando si $A < B$ bajo orden débil estricto para inserción prioritaria descendente.

---

## 2. Estructuras de Memoria y Offsets

### Objeto `CSubUnit` (Regimiento / Subunidad)
- `+0x38`: Puntero a tipo de unidad `CUnitType*`
- `+0x3C`: `strength` (int32, hombres en milésimas)
- `+0x40`: `organization` (int32, moral/organización en milésimas)
- `+0x74`: Puntero a líder asignado `CLeader*`

### Objeto `CUnitType` (Definición de Tipo de Unidad)
- `+0x230`: `fire_attack` (int32, poder de fuego en milésimas)
- `+0x234`: `shock_attack` (int32, poder de choque en milésimas)
- `+0x240`: `maneuver` (int32, maniobra táctica en milésimas)

### Objeto `CLeader` (Líder / General)
- `+0x164`: `is_inoperative` / flag de inhabilitación (uint8, bool)

---

## 3. Formulación Algorítmica y Matemática

Para cada subunidad evaluada $U \in \{A, B\}$:

1. **Agregación de atributos tácticos:**
   $$\text{stat\_sum}(U) = \text{fire\_attack}(U) + \text{shock\_attack}(U) + \text{maneuver}(U)$$

2. **Evaluación de liderazgo e inoperatividad moral:**
   Si la unidad tiene líder asignado (`pLeader != NULL`) y el líder está inhabilitado (`is_inoperative != 0`):
   $$\text{effective\_org}(U) = 0$$
   En caso contrario:
   $$\text{effective\_org}(U) = \text{organization}(U)$$

3. **Escalado primario (Ponderación Moral-Táctica):**
   A través de multiplicación de 64 bits y llamada a `_alldiv` (`0x00AC02A0`) con divisor 1000:
   $$\text{step}_1(U) = \left\lfloor \frac{\text{effective\_org}(U) \times \text{stat\_sum}(U)}{1000} \right\rfloor$$

4. **Escalado secundario (Ponderación de Masa Física):**
   A través de multiplicación de 64 bits y llamada a `_alldiv` (`0x00AC02A0`) con divisor 1000:
   $$\text{score}(U) = \left\lfloor \frac{\text{step}_1(U) \times \text{strength}(U)}{1000} \right\rfloor$$

5. **Comparación Estricta:**
   $$\text{return } (\text{score}(A) < \text{score}(B))$$

---

## 4. Criterio de Evidencia y Verificación
- Verificación estática con Reverify sobre todas las 64 instrucciones en PE32 de `0x0059B780..0x0059B833`.
- Verificación del call-site en `0x005AB8B7`.
- Control negativo en target offset desfasado (`REFUTED`).
- Cascada de invalidación dependiente (`INVALIDATED`).
- Emulación dinámica con Unicorn en memoria sintética, cubriendo permutaciones de fuerza, organización, estadísticas fuego/choque/maniobra y líder deshabilitado con 0 discrepancias frente a `combat_reserve_priority_model.py`.
