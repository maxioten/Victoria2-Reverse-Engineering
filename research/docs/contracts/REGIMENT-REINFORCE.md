# Contrato: Viabilidad de Refuerzo Demográfico de Regimiento (`CRegiment::CanReinforce`)

## 1. Identificación y Alcance
- **Binario:** `base-game/v2game.exe` (SHA-256: `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`).
- **Dirección de la rutina:** `0x005CC4D0..0x005CC529` (90 bytes, 35 instrucciones).
- **Vtable slot 20 (`+0x50`):**
  - `0x00DF88D4`: Entrada en la tabla de métodos virtuales de `CRegiment` (`0x00DF8884 + 0x50`).
- **Convención de llamada:** `__thiscall` con `ecx = pRegiment`. Retorno booleano en `al` (1 si puede reforzarse, 0 si está bloqueado), epílogo `ret` (0 bytes).

---

## 2. Estructura de Memoria y Offsets

### Objeto `CRegiment`
- `+0x00`: Puntero a vtable (`0x00DF8884`)
- `+0xC0`: Identificador o coordenada de ubicación del regimiento (`regiment_location`, struct de 4 bytes)
- `+0xC4`: `country_id` (int32, código numérico de país soberano)
- `+0x108`: Puntero al POP de soldados base `pHomePop` (`CPop*`)

### Objeto `CPop` (Soldier POP de Origen)
- Vtable slot 22 (`+0x58`): Método virtual `GetPopResidenceLocation(&location_struct)`

---

## 3. Formulación Algorítmica y Matemática

1. **Existencia del POP de Soporte:**
   - Si `[pRegiment + 0x108] == NULL`:
     $$\text{return } \text{False}$$
     (Un regimiento cuyo POP de origen fue completamente exterminado, asimilado o convertido no puede recibir reemplazos humanos).
2. **Jurisdicción Territorial y Control Nacional:**
   - Invoca virtualmente `GetPopResidenceLocation` (slot 22, `+0x58`) sobre `pHomePop`, recibiendo la tupla `(province_id, pop_country_id)` en la pila.
   - Compara el país del regimiento con el país donde se ubica el POP:
     $$\text{if } (\text{regiment.country\_id} == \text{pop\_country\_id}): \text{return } \text{True}$$
3. **Comprobación de Corredor Logístico / Acceso Militar:**
   - Si el POP reside en una provincia ocupada por el enemigo o fuera de las fronteras soberanas:
   - Invoca a `HasMilitaryAccessOrSupplyRoute(regiment_location, pop_location)` (`0x005CC2E0`).
   - Si retorna 1 (existe continuidad de acceso militar o corredor naval abierto):
     $$\text{return } \text{True}$$
   - Si retorna 0 (provincia aislada por ocupación hostil o falta de tratados de paso):
     $$\text{return } \text{False}$$

---

## 4. Criterio de Evidencia y Verificación
- Verificación estática con Reverify sobre todas las 35 instrucciones en PE32 de `0x005CC4D0..0x005CC529`.
- Verificación de slot de vtable (`bytes_at`) en `CRegiment` (`0x00DF88D4`).
- Control negativo en target offset desfasado (`REFUTED`).
- Cascada de invalidación dependiente (`INVALIDATED`).
- Emulación dinámica con Unicorn en memoria sintética, cubriendo POP extinto (NULL), coincidencia de país soberano, desajuste con corredor de acceso válido y desajuste con bloqueo territorial con 0 discrepancias frente a `regiment_reinforce_model.py`.
