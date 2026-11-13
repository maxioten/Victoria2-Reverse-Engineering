# Contrato de escritores del vector de provincias de `CCountry` (`+0x9D8`)

- **Binario objetivo**: `base-game/v2game.exe` (`ImageBase = 0x00400000`, RVA = VA - `0x00400000`).
- **SHA-256**: `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648` (`[confirmed]` vía `sha256sum base-game/v2game.exe`).
- **Propósito (V1 de `Country_Recalculate` variante c)**: Verificar el layout exacto de `CCountry+0x9D8`, enumerar todos los escritores/mutadores de las provincias poseídas y de `CProvince.owner_id`, comprobar el invariante `(*(country_mgr+4))[idx]->+0x20 == idx` (`"---"` / `"REB"` / `ChangeTag`), evaluar seguridad TBB y emitir veredicto **GO / NO-GO** para V2.

---

## 1. Layout exacto del vector de provincias de `CCountry` (`[confirmed]`)

- **Tamaño de `CCountry`**: `0x1608` bytes (`push 0x1608` en `0x0055A824` y `0x0055AEFA` dentro de `0x0055A790`). `[confirmed]`
- **Vector de provincias poseídas (`std::vector<int>`, 12 bytes, sin `_Myproxy`)**: inicia en **`+0x9D8`**, NO en `+0x9D4`:
  - `CCountry + 0x9D8` (`RVA` dentro de objeto): `_Myfirst` (`int*`) — puntero al primer `province_id` (`CProvince+0x58`).
  - `CCountry + 0x9DC`: `_Mylast` (`int*`) — puntero al final lógico (`_Mylast - _Myfirst == count * 4`).
  - `CCountry + 0x9E0`: `_Myend` (`int*`) — fin de capacidad asignada.
- **Evidencia sobre `+0x9D4` (`[confirmed]`)**:
  - En `CCountry::ctor` (`0x004F6A10`, RVA `0x0F6A10`): `0x004F718E` construye un subobjeto de `0x24` bytes en `[ebx + 0x9B4]` llamando a `0x005E6570`, y justo a continuación `0x004F7199..0x004F71A5` pone a cero `[ebx+0x9D8]`, `[ebx+0x9DC]` y `[ebx+0x9E0]`. `0x005E6570` escribe `[ecx + 0x20] = parent` (`0x005E658E`), que corresponde exactamente a `CCountry + 0x9D4` (`0x9B4 + 0x20 = 0x9D4`).
  - En `CCountry::~CCountry` (`0x004F8340`, RVA `0x0F8340`): `0x004F90DA..0x004F9100` libera `[ebx+0x9D8]` con `0x00AAE91B` (`operator delete`), pone a cero `+0x9D8..+0x9E0`, y luego destruye el subobjeto `[ebx+0x9B4]` con `0x005EDA70` (`0x004F910A`).
  - Todos los accesos de lectura/escritura observados en `.text` para el vector de provincias operan sobre `+0x9D8/+0x9DC/+0x9E0` (ej. `Country_Recalculate` en `0x00515F1E..0x00515F24`: `mov ecx, [eax+0x9dc]; sub ecx, [eax+0x9d8]`). Ningún hit de `0x9D4` en `.text` accede a `[country + 0x9D4]` como vector.

---

## 2. Enumeración exhaustiva de escritores y mutadores (`[confirmed]`)

### 2.1 Escaneo global de escrituras directas en `.text` a `[reg + 0x9D8 / 0x9DC / 0x9E0]`

Al desensamblar todas las funciones de `research/evidence/generated/ghidra-converged/functions.csv` en `.text`, las únicas escrituras directas no-stack a `[reg + 0x9D8/+0x9DC/+0x9E0]` están en:
1. `CCountry::ctor` (`0x004F6A10`): `0x004F7199`, `0x004F719F`, `0x004F71A5` (`mov dword ptr [ebx + 0x9d8/0x9dc/0x9e0], edi`, con `edi=0`).
2. `CCountry::~CCountry` (`0x004F8340`): `0x004F90F4`, `0x004F90FA`, `0x004F9100` (`mov dword ptr [ebx + 0x9d8/0x9dc/0x9e0], esi`, con `esi=0`, tras liberar `[ebx+0x9d8]`).

*(Los únicos otros hits en `.text` son variables locales en `[esp + 0x9dc]` en `0x004337B2` y `[esp + 0x9d8]` en `0x00666103`.)*

### 2.2 Helpers de `std::vector<int>` que mutan `+0x9D8` vía puntero

| Helper VA (RVA) | Semántica verificada (`[confirmed]`) | Sitios que pasan `CCountry + 0x9D8` |
|---|---|---|
| `0x004E9B90` (`0x0E9B90`) | `std::vector<int>::push_back(edi=vec*, eax=const int*)` | **Solo** `CProvince::SetOwner` (`0x004B55C9`) |
| `0x0068F020` (`0x28F020`) | `std::vector<int>::erase_one(esi=vec*, ecx=const_iterator*)` | **Solo** `CProvince::SetOwner` (`0x004B555C`) |
| `0x0054AB90` (`0x14AB90`) | `std::vector<int>::erase(vec*, first, last)` (`ret_iter*=edi`) | **Solo** `CCountry::Reset` (`0x00503020` en `0x00504409`: `erase(begin, end)`) |
| `0x00461F90` (`0x061F90`) | `vector_free_zero(esi=vec*)` | **Solo** unwinds SEH de `CCountry::ctor` (`0x00B53673`, `0x00BA7F1B..0x00BA7F1E`) |
| `0x009BEEB0` (`0x5BEEB0`) | `std::vector<int>::operator=(eax=dst*, [ebp+8]=src*)` | Solo como **`src`** (lectura): `0x004F98AA` (`CCountry::ChangeTag`) y `0x00518A68` |

### 2.3 Lista completa de mutadores de `CCountry + 0x9D8`

1. **`CCountry::ctor` (`0x004F6A10`, RVA `0x0F6A10`)** — inicializa `+0x9D8..+0x9E0 = 0` (`0x004F7199..0x004F71A5`) y llama a `CCountry::Reset` (`0x004F8284`).
   - Callers directos: **2**, ambos en `CCountryManager::Init` (`0x0055A790` en `0x0055A84F` y `0x0055AF32`). Referencias imm32 en `.rdata`/`.text`: `0`.
   - Unwinds SEH asociados: `0x00B53673` y `0x00BA7F1B` (`-> 0x00461F90`).
2. **`CCountry::~CCountry` (`0x004F8340`, RVA `0x0F8340`)** — libera y limpia `+0x9D8..+0x9E0` (`0x004F90DA..0x004F9100`).
   - Caller directo: **1** (`0x004F82A7` en scalar deleting dtor `0x004F82A0`, slot 0 de vtable `0x00DFFACC`, llamado desde `CCountryManager::~CCountryManager` `0x0055C7E0` en `0x0055C82C`). Referencias imm32 directas a `0x004F8340`: `0`.
3. **`CCountry::Reset` (`0x00503020`, RVA `0x103020`, `__stdcall (CCountry*)`, `ret 4` en `0x005046FC`)** — vacía `CCountry + 0x9D8` mediante `0x0054AB90(vec, begin, end)` en `0x005043FD..0x00504409`.
   - Callers directos: **2**: `0x004F8284` (`CCountry::ctor`) y `0x0067E78A` (`CWorld::Reset` `0x0067E1C0`, bucle sobre todos los países de `CWorld+0xADC` antes de llamar a `CProvince::Reset` en `0x0067E7BA`). Referencias imm32 en `.rdata`/`.text`: `0`.
4. **`CProvince::SetOwner` (`0x004B52E0..0x004B5728`, RVA `0x0B52E0`, `__thiscall (CProvince* ecx, CTag* new_tag, ..., uint8_t arg3, uint8_t arg4)`, `ret 0x10`)** — **único mutador activo en carga de partida y gameplay**:
   - `0x004B5341..0x004B5350`: si el tag nuevo es `"REB"`, retorno temprano sin modificar `owner` ni `+0x9D8`.
   - `0x004B54F6..0x004B5561`: lee `old_id = [edi + 0x12C]`. Si `old_id != 0` (`test esi, esi` en `0x004B550A`) **y** `arg4 == 0` (`cmp byte ptr [ebp+0x14], 0` en `0x004B550E`), busca `[edi + 0x58]` (`province_id`) en `(*(country_mgr+4))[old_id] + 0x9D8` y lo borra con `0x0068F020` (`0x004B555C`).
   - `0x004B5565..0x004B5570`: escribe `CProvince+0x128` (chars) y `CProvince+0x12C` (`new_id`).
   - `0x004B5576..0x004B55D2`: si `new_id != 0` (`0x004B5576`) **y** `arg4 == 0` (`0x004B557A`), comprueba duplicado en `(*(country_mgr+4))[new_id] + 0x9D8` (`0x004B55A8..0x004B55BD`) y si no está, inserta `province_id` con `0x004E9B90` (`0x004B55C9`).
   - Referencias imm32 en `.rdata`/`.text`: `0`.
   - **Los 7 callers directos en todo el binario (`[confirmed]`)**:
     - `0x004A9B5B` (en `CProvince::ReadMember` `0x004A9980`): `arg4 = 0` — carga de `owner` desde historial y archivos de guardado (`.v2`).
     - `0x004B5965` (en `CProvince::SetController` `0x004B5730`): `arg4 = 0` — colonización de provincia sin dueño.
     - `0x004B5CC5` (en `0x004B5A90`): `arg4 = 0`.
     - `0x004EC6F4` (en `0x004EC660`): `arg4 = 0`.
     - `0x004F9900` (en `CCountry::ChangeTag` `0x004F97C0`): **`arg4 = 1`** (`push 1; push 1` en `0x004F98E2..0x004F98E4`) — actualiza `CProvince+0x128/+0x12C` sin tocar `+0x9D8`.
     - `0x00537170` (en `0x005370F0`): `arg4 = 0`.
     - `0x005F4020` (en `0x005F3EE0`): `arg4 = 0`.

### 2.4 Auditoría de `lea/add +0x9D8` restantes y escritores de `CProvince + 0x12C` (`[confirmed]`)

- **Resto de sitios `lea/add +0x9D8` (37 sitios)**: todos auditados como solo lectura:
  - `0x0050E230` (`add eax, 0x9d8; ret`): 0 xrefs imm32, 4 callers (`0x006C7D61`, `0x006C867C`, `0x006C8984`, `0x006C8C48`), todos iteradores de solo lectura.
  - `0x0051D140`: recibe `const std::vector<int>&` en `[ebp+0xC]` solo para lectura (`0x0051D4E2`).
  - `0x004F9888` y `0x00518A68`: pasan `country+0x9D8` como `src` de lectura a `0x009BEEB0` para copiar a un vector local en stack.
  - `0x00735416` y `0x00735F0F`: leen `country+0x9D8` y solo hacen `push_back` en un vector local de stack (`[ebp-0x9C]` / `[ebp-0x30]`).
  - Los restantes (`0x00438421`, `0x00438911`, `0x004E6F4F`, `0x004ED4EB`, `0x004F5E3F`, `0x0051E73C`, `0x0057FF04`, `0x005C0642`, `0x0060A196`, `0x006A065A`, `0x006ADBDD`, `0x006AE1A9`, `0x00714A4A`, `0x00715915`, `0x00772078`, `0x007C3470`, `0x0082350C`, `0x008470D9`, `0x0084A78C`, `0x0085ECBA`, `0x00889DAA`, `0x0088B635`, `0x0089B576`, `0x008ABD6B`, `0x008B0754`, `0x008C6D1B`, `0x008C724E`, `0x0091195F`, `0x009119B5`, `0x00918B6E`, `0x00952053`) solo calculan tamaño, vacío o iteran elementos.
- **Escrituras a `[reg + 0x12C]` en el rango de `CProvince` (`0x004A0000..0x004C0000`)**:
  - `0x004A85F2` en `CProvince::ctor` (`0x004A84C0`): inicializa `owner` a `0` (`"---"`).
  - `0x004AA9A2` en `CProvince::Reset` (`0x004AA4B0`): reinicia `owner` a `0` (`"---"`), llamado tras `CCountry::Reset` en `0x0067E7BA`.
  - `0x004B5570` en `CProvince::SetOwner` (`0x004B52E0`).
  - *(Nota: `0x004BFE1B` en `0x004BFCA0` pertenece a otro struct que copia campos `+0x4..+0x13C`, no a `CProvince::owner_id`.)*

---

## 3. Invariante `(*(country_mgr+4))[idx]->+0x20 == idx`, `"---"` (`id == 0`) y `"REB"` (`[confirmed]`)

- **Construcción inicial (`CCountryManager::Init`, `0x0055A790`, RVA `0x15A790`, 1 caller `0x0063D551`)**:
  1. `0x0055A824..0x0055A8C9`: reserva `0x1608` bytes, construye `"---"` con `id = 0` (`0x0055A840..0x0055A84F`), lo empuja en índice `0` de `country_mgr+4` (`[0x012587E4]+4`) y fija `[country_mgr] = 1`.
  2. `0x0055AEEC..0x0055B15E`: lee `common/countries.txt` en orden secuencial, construyendo cada tag con `id = [country_mgr+0]` (`1, 2, 3, ...`), insertando `CCountry*` al final de `country_mgr+4` y `{chars, id}` en `country_mgr+0x414` y la tabla hash `country_mgr+0x14`.
  3. En `base-game/common/countries.txt` línea 4, la primera entrada es `REB = "countries/rebels.txt"`, por lo que `"REB"` ocupa `idx = 1` (`0x0055C240` salta explícitamente `eax <= 1` al validar colores históricos).
- **Comportamiento de `id == 0` (`"---"`) y `"REB"`**:
  - `CProvince::SetOwner` (`0x004B52E0`) bloquea `"REB"` en `0x004B5341..0x004B5350`, y omite `erase`/`push_back` sobre `+0x9D8` cuando `old_id == 0` (`0x004B550A`) o `new_id == 0` (`0x004B5576`). Por tanto, ni `"---"` (`id=0`) ni `"REB"` (`id=1`) poseen nunca entradas en `+0x9D8`.
- **Preservación del invariante tras `CWorld::ChangeTag` (`0x006881D0`, RVA `0x2881D0`, `__stdcall (CWorld*, CTag*, CTag*)`, 1 caller `0x00880F83`)**:
  - `0x006887B6` y `0x006887C3` llaman a `CCountry::ChangeTag` (`0x004F97C0`), que:
    - Itera `old_country + 0x9D8` y actualiza `CProvince+0x128/+0x12C` llamando a `SetOwner(..., arg4=1)` (`0x004F9900`, **sin modificar `+0x9D8`**).
    - Reescribe `+0x1C/+0x20` (y `+0x214/+0x218`, `+0x36C/+0x370`) en ambos `CCountry*` (`0x004F99AA..0x004F99C8`).
  - Luego, `0x00688D67..0x00688D88` **intercambia los punteros `CCountry*`** en `(*(country_mgr+4))[old_id]` <-> `(*(country_mgr+4))[new_id]`, y `0x00688D89..0x00688DB5` intercambia también `CWorld+0xADC[old_id]` <-> `[new_id]`.
  - **Consecuencia doble (`[confirmed]`)**:
    1. Una vez finaliza `CWorld::ChangeTag`, el invariante `(*(country_mgr+4))[idx]->+0x20 == idx` **se mantiene** tras carga de partida y tras cambios de tag (salvo transitoriamente dentro de `CWorld::ChangeTag` entre `0x006887B6` y `0x00688D88`).
    2. Sin embargo, **`CWorld::ChangeTag` transfiere un vector `+0x9D8` no vacío desde `old_id` a `new_id` sin pasar por `SetOwner(..., arg4=0)`**. Un país que forma otro tag (ej. `PRU` -> `NGF`/`GER`) mueve su estado "vivo" de `old_id` a `new_id`.

---

## 4. Seguridad respecto a TBB / hilos concurrentes (`[confirmed]`)

- **Importaciones TBB (`tbb.dll` IAT `0x00C8A570..0x00C8A5A0`) y raíces de tareas**:
  1. `0x0068F3F0` -> vtable `0x00E0AEC8` -> `0x00685780` (`TBB_prov_worker`, llamado desde `0x00685E86`).
  2. `0x0068F4C0` -> vtable `0x00E0AED8` -> `0x00520150` (`TBB_decisions_worker`, llamado desde `0x00685FD6` bajo `[0x1258A66] = 1` en `0x00685FA4`).
  3. `0x0099EA38..0x0099EB5A` -> vtable `0x00E384C8` -> `0x0099ED40`.
- **Alcance estático (`functions.csv` con `body_bytes`, omitiendo `_CxxThrowException` `0x00AAD3AD`)**:
  - `0x00685780`: `421` funciones alcanzables por llamadas/saltos directos; `0` hits a `SetOwner`, `CCountry::ctor`, `CCountry::dtor`, `CCountry::Reset`, `CCountry::ChangeTag`, `CWorld::ChangeTag`, `0x004E9B90` o `0x0068F020`. Solo 2 lecturas de `+0x9D8/+0x9DC` en `0x00958DF0` (`0x00958EE4..0x00958EEA`).
  - `0x00520150`: `372` funciones alcanzables por llamadas/saltos directos; `0` hits a los mutadores de `+0x9D8`. Lecturas de `+0x9D8/+0x9DC` únicamente en `0x00514F20` (`0x00514F4B..0x00514FA9`) y `0x00520150` (`0x00520295..0x0052029B`).
  - `0x0099ED40`: `2` funciones alcanzables; `0` referencias a `+0x9D8`.
  - *(Nota sobre llamadas indirectas: `0x00685780` y `0x00520150` contienen `219` y `196` call sites indirectos respectivamente; no obstante, los 6 mutadores listados en §2.3 tienen **`0` referencias imm32 en `.rdata` y `.text`**, salvo `CCountry::~CCountry` vía slot 0 `0x004F82A0`, por lo que ningún `call reg` / `call [mem]` puede despacharlos.)*
- **Conclusión**: Ningún escritor de `CCountry + 0x9D8` ni `CWorld::ChangeTag` es alcanzable desde workers TBB. Todos los cambios de propiedad y vida/muerte ocurren en el hilo principal fuera de las regiones paralelas TBB.

---

## 5. Veredicto GO / NO-GO para V2 (`[confirmed]`)

### Veredicto: **GO** (con el conjunto acotado de 3 hooks obligatorios)

Es viable capturar el 100% de las transiciones vivo/muerto de países mediante hooks acotados sin riesgo de perder escrituras inline ni carreras TBB, **siempre que se incluya `CWorld::ChangeTag` además de `SetOwner` y `Reset`**:

1. **`CProvince::SetOwner` (`0x004B52E0`, `__thiscall`, `ret 0x10`)**:
   - Captura tanto la carga inicial/de guardados (`0x004A9B5B`) como toda colonización o transferencia territorial en gameplay (`0x004B5965`, `0x004B5CC5`, `0x004EC6F4`, `0x00537170`, `0x005F4020`).
   - En el wrapper: si `arg4 != 0`, delegar sin actualizar el bitmap/contador (evita trabajo redundante durante `ChangeTag`). Si `arg4 == 0`, leer `old_id = [this+0x12C]` antes de llamar y tras retornar verificar `old_id` (si `!= 0`) y `new_id = [this+0x12C]` (si `!= 0`) — o comprobar directamente si `country->+0x9DC != country->+0x9D8` para ambos IDs.
2. **`CWorld::Reset` (`0x0067E1C0`) o `CCountry::Reset` (`0x00503020`, `ret 4`)**:
   - Limpia el estado del side-table en `New Game` / `Load Save` cuando `CWorld::Reset` vacía todos los `CCountry+0x9D8` en `0x0067E78A` antes de recargar provincias vía `SetOwner`.
3. **`CWorld::ChangeTag` (`0x006881D0`, `__stdcall`, `ret 0xC`) — OBLIGATORIO para side-table indexado por `country_id`**:
   - Como `CWorld::ChangeTag` intercambia los punteros `CCountry*` entre `old_id` y `new_id` en `country_mgr+4` (`0x00688D67..0x00688D88`) usando `SetOwner(..., arg4=1)`, omitir este hook dejaría `live[old_id] == 1` y `live[new_id] == 0` desincronizados al formar países (`PRU -> NGF/GER`, etc.).
   - En el post-hook de `0x006881D0`, intercambiar las entradas `old_id <-> new_id` del side-table (o recomputar `live` para `old_id` y `new_id` desde `(*(country_mgr+4))[id]->+0x9D8/+0x9DC`).

**Regla de inicialización segura**: si el parche V2 se carga antes del bucle principal de juego (antes de `CProvince::ReadMember`), estos 3 hooks mantienen el side-table exacto; aun así, un hook tardío puede inicializar el side-table una sola vez escaneando `(*(country_mgr+4))[0..N-1]` antes de activar el fast-path.

---

## 6. Procedimiento de reproducción (`[confirmed]`)

```bash
source research/env.sh
sha256sum base-game/v2game.exe
# Esperado: 62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648
```

Con `pefile`, `capstone` y `research/evidence/generated/ghidra-converged/functions.csv` (`entry_va` + `body_bytes`):
1. Desensamblar `0x004F7160..0x004F71D0`, `0x005E6570..0x005E6598`, `0x004F90B0..0x004F9120`, `0x005043C0..0x0050444A`, `0x004B5320..0x004B55E0`, `0x004F97C0..0x004F99E6` y `0x00688780..0x00688DF0` para verificar offsets, argumentos `arg4` y el swap en `country_mgr+4`/`CWorld+0xADC`.
2. Escanear instrucciones en `.text` buscando escrituras a `+ 0x9d8]`, `+ 0x9dc]`, `+ 0x9e0]` y llamadas `E8`/`E9` a `0x004B52E0`, `0x00503020`, `0x004F6A10`, `0x004F8340`, `0x004F97C0`, `0x006881D0`, además de referencias imm32 en `.rdata` y `.text`.
3. Ejecutar BFS directo sobre `functions.csv` desde `0x00685780`, `0x00520150` y `0x0099ED40` (excluyendo `_CxxThrowException` `0x00AAD3AD`) para confirmar `0` mutadores alcanzables.
