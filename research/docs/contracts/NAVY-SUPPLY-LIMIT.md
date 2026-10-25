# Contrato: Capacidad de Aprovisionamiento y Límite de Suministro Naval (`CNavy::CalculateSupplyLimit`)

## 1. Identificación y Alcance
- **Binario:** `base-game/v2game.exe` (SHA-256: `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`).
- **Dirección de la función:** `0x005D81A0..0x005D82FE` (351 bytes, 117 instrucciones).
- **Vtable asociada:** `CNavy` slot 30 (`+0x78`) en `0x00E03044` (vtable base en `0x00E02FCC`).
- **Convención de llamada:** `__thiscall` con puntero `this` en `ecx` (`CNavy*`), argumento de salida `out_limit` en `[esp + 4]`, retorno en `eax` (`out_limit`), epílogo `ret 4`.

---

## 2. Estructura de Memoria y Offsets

### Formación Naval (`CNavy`)
- `+0x00`: Puntero a vtable (`0x00E02FCC`).
- `+0xC0`: Información nacional (`tag_or_country`).
- `+0xC4`: Identificador numérico del país propietario (`country_id`, `int32`).
- `+0xD8`: Puntero al almirante/líder asignado (`CLeader*`).
- `+0xDC`: Puntero a la provincia actual de estacionamiento (`CProvince*`).
- `+0x1B8`: Nivel base de intendencia naval / puerto (`naval_base_level`, `int32`).

### Objeto Provincia (`CProvince`)
- `+0x5C`: Puntero a descriptores geográficos y de terreno (`CTerrainInfo*`).
- `+0x5C` -> `+0x2A`: Flag de zona marítima (`is_water`, `uint8`).
- `+0x5C` -> `+0xD9`: Flag de base naval construida (`has_naval_base`, `uint8`).

### Objeto Almirante (`CLeader`)
- `+0x00`: Puntero a vtable de líder.
  - Slot 8 (`+0x20`): `virtual bool HasActiveSupplyTrait() const`.
- `+0x48`: Puntero a objeto de modificadores del líder.
  - `+0x38`: Bonificación de suministro del almirante (`leader_supply_bonus`, `int32`).

### Gestor de Estado Global (`CGameState` en `0x012588E8`)
- `+0xAEC`: Puntero a tabla de bases navales activas por país (`int32*`).
- `+0xAF0`: Puntero de fin de tabla de bases navales (`int32*`).
  - Capacidad: `(af0 - aec) / 4`.

### Gestor Mundial (`pWorld` en `0x012587E4`)
- `+0x04`: Array de punteros a objetos país (`CCountry** countries`).
- `[country + 0xBCC]`: Puntero a modificadores tecnológicos navales.
  - `+0x24`: Bonificación tecnológica a límite de suministro naval (`tech_naval_supply`, `int32` en milésimas).

---

## 3. Formulación Algorítmica y Matemática

La rutina calcula el límite máximo de suministro y capacidad portante para una flota naval:

1. **Verificación de Registro de Bases Navales Nacionales:**
   Inspecciona la tabla de bases en `[0x012588E8]`:
   - Si $\text{country\_id} < \text{capacity}$ y $\text{table\_aec}[\text{country\_id}] == 0$:
     El país carece de infraestructura marítima activa. Escribe `*out_limit = 0` (mediante floor de $0.0005 \times 1000.0$) y concluye inmediatamente.

2. **Verificación de Aguas Abiertas vs Puerto:**
   Inspecciona `is_water` (`[pProvince + 0x5C]->0x2A`):
   - En mar abierto (`is_water != 0`): la flota no dispone de límite provincial fijo de abastecimiento (depende de bases lejanas o atrición de crucero); escribe `*out_limit = 0` y retorna.
   - En provincia costera/puerto (`is_water == 0`): invoca `0x004B7DB0(pProvince, &navy.country)`. Si no hay acceso a dique o muelle, escribe `*out_limit = 0` y retorna.

3. **Verificación de Hostilidad y Bloqueo:**
   Si la provincia dispone de base naval (`has_naval_base != 0` en `+0xD9`):
   - Invoca `0x00539260(pCountry, pProvince)` para comprobar ocupación hostil o beligerancia enemiga.
   - Si la provincia está bajo control hostil o bloqueada por el adversario, escribe `*out_limit = 0` y retorna.

4. **Cómputo de Capacidad Base:**
   La intendencia base se escala a razón de 2,000 milésimas por nivel de base naval más 1,000 milésimas de margen intrínseco:
   $$\text{base\_supply} = (\text{naval\_base\_level} \times 2000) + 1000$$

5. **Bonificación de Rasgo de Almirante:**
   Si la flota tiene un comandante asignado (`pLeader = [this + 0xD8]`):
   - Invoca virtualmente `pLeader->HasActiveSupplyTrait()` (slot 8, `+0x20`).
   - Si es verdadero:
     $$\text{base\_supply} \mathrel{+}= \text{leader\_supply\_bonus}$$

6. **Piso a Cero:**
   $$\text{base\_supply} = \max(0, \text{base\_supply})$$

7. **Escalado Tecnológico Nacional (en 64 bits):**
   Recupera el modificador tecnológico naval en `[country + 0xBCC]->0x24` ($\text{tech}$ en milésimas):
   $$\text{scaled\_limit} = \left\lfloor \frac{\text{base\_supply} \times (\text{tech} + 1000)}{1000} \right\rfloor$$
   Calculado mediante producto entero de 64 bits y división `_alldiv` (`0x00AC02A0`).

8. **Almacenamiento y Retorno:**
   Escribe el límite final en `*out_limit` y retorna `eax = out_limit`.

---

## 4. Criterio de Evidencia y Verificación
- 117 afirmaciones Reverify cubriendo todas las instrucciones en PE32 de `0x005D81A0..0x005D82FE`.
- Verificación del puntero en slot 30 de `CNavy` (`0x00E03044` -> `0x005D81A0`).
- Constantes enteras `0x7D0` (2000) y `0x3E8` (1000).
- Constantes flotantes IEEE 754 en `0x00E45840` ($0.0005$) y `0x00E45660` ($1000.0$).
- Singletons globales en `0x012588E8` (`CGameState`) y `0x012587E4` (`pWorld`).
- Control negativo `REFUTED` y cascada dependiente `INVALIDATED`.
- Emulación dinámica con Unicorn en memoria sintética, cubriendo países sin bases, mar abierto, puertos bloqueados, puertos aliados, niveles escalonados de base naval, modificadores de almirante y tecnología logística sin discrepancias frente a `navy_supply_limit_model.py`.
