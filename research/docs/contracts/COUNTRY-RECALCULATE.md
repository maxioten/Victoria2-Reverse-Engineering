# Contrato de optimización: `FUN_00515490` (`Country_Recalculate`)

**Estado**: prerrequisitos estáticos cerrados para Paso B (`[confirmed]` en las observaciones de binario/perfilado citadas; las identidades operativas de clase como `CCountry` / `CRelation` se marcan `[inferred]`).

- **Ejecutable objetivo**: `base-game/v2game.exe` (`SHA-256 62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`).
- **Base VA preferida**: `0x00400000` (`VA = RVA + 0x00400000`).

---

## 1. Identidad, rango, callers y perfilado base

| Propiedad | RVA | VA / Valor | Estado | Evidencia |
| --- | --- | --- | --- | --- |
| Entrada (`Country_Recalculate`) | `0x00115490` | `0x00515490` | `[confirmed]` | `functions.csv`, prólogo `55 8b ec 83 e4 f8` |
| Fin inclusivo (`ret 4`) | `0x001163BA` | `0x005163BA` | `[confirmed]` | `c2 04 00` en `0x005163B8..0x005163BA`, seguido de `int3` (`0x005163BB`) |
| Tamaño inclusivo | — | `3883 B` | `[confirmed]` | `0x005163BA - 0x00515490 + 1` |
| Prólogo (primeros 16 B) | `0x00115490` | `55 8b ec 83 e4 f8 6a ff 68 50 34 b9 00 64 a1 00` | `[confirmed]` | Lectura directa de `base-game/v2game.exe` |
| Convención ABI / retorno | — | `__stdcall` (`ret 4`), `void`, marco SEH `0x00B93450` | `[confirmed]` | `[ebp+8] -> EBX`, `ret 4` en `0x005163B8` |
| Parámetro | — | `[ebp+8]`: puntero `self` (`CCountry*` `[inferred]`) | `[confirmed]` | `0x005154AF mov ebx, [ebp+8]` |
| Callers estáticos | — | `43` sitios `call rel32` (`E8`), `0` `E9` / `ptr32` | `[confirmed]` | `python3 research/scripts/find_callers.py base-game/v2game.exe 0x00515490` |
| Perfil GFM 1830 (`1311` muestras) | — | `56` own (`4.27%`) / `76` incl (`5.80%`), `55/56` (`98.2%`) en `0x00515EC0..0x00516285` | `[confirmed]` | `base-game/performance_patch_samples.tsv` |
| Perfil SPA 1837 (`5023` muestras, `run-01..05`) | — | `76` own (`1.51%`) / `113` incl (`2.25%`), `57/76` (`75.0%`) en `0x00515EC0..0x00516285` | `[confirmed]` | `research/perf/raw/run-01..05/performance_patch_samples.tsv` |

Desglose de muestras propias en el bucle caliente `0x00515EC0..0x00516285`:
- **GFM 1830**: `23` en chequeo de tag muerto (`0x00515EC0..0x00515F35`, `41.1%` de own: `0x00515F24` [16], `0x00515ED1` [5], `0x00515F1E` [1], `0x00515F2A` [1]); `19` en dereferencias de relación (`0x00515FCF` [14], `0x0051611F` [5], `33.9%` de own); resto del bucle `13` (`23.2%`). Solo `1` muestra (`0x005157EE`) cae fuera del bucle `[confirmed]`.
- **SPA 1837** (`run-01..05`, `5023` muestras): `19` en chequeo de tag muerto (`0x00515ED1` [9], `0x00515F24` [8], `0x00515ECE` [1], `0x00515F0B` [1], `25.0%` de own); `10` en `0x00515FCF` [6] + `0x0051611F` [4] (`13.2%`); `20` en el recorrido interno de lista `[ebx+0x9F8]` al final del mismo bucle (`0x00516210..0x0051626F`: `0x0051626F` [8], `0x0051621A` [5], `0x00516210` [3], `0x00516220` [2], `0x00516226` [2]); y `8` en el cuerpo intermedio del bucle (`0x005160EE` [4], `0x00515F43` [1], `0x0051601A` [1], `0x00516026` [1], `0x00516134` [1]; `19 + 10 + 20 + 8 = 57`) `[confirmed]`.

---

## 2. Estructura y aislamiento SESE del bucle `0x00515EA6..0x00516285`

`FUN_00515490` se divide en tres bloques disjuntos (`[confirmed]`):
1. **Pre-bucle (`0x00515490..0x00515EA5`, `2582 B`)**:
   - Limpia listas y vectores en `self` (`0x00541EC0`, `[ebx+0xD38..0xD98]`, `[ebx+0xEA4/+0xEB4]`, `[ebx+0xA28..0xA40]`, `[ebx+0xD08/+0xD18/+0xD28]`, `[ebx+0xDB8]`, contadores `[ebx+0xDD0..0xDE4]`).
   - Guarda los punteros globales `[0x012588E8]` y `[0x012587E4]` en la pila (`0x005154DB..0x005154FF`).
   - Usa x87/SSE y `__ftol2_sse` (`0x00B31C00`, en `0x00515510` y `0x00515C63`) junto con `0x00401000`.
   - Recorre las provincias de `self` (`[ebx+0x9D8..0x9DC]`, `0x00515960..0x00515CCF`, llamando `0x004B8870` en `0x00515995`), las unidades `[ebx+0x7B4]` (`0x00515D6F..0x00515DB0`) y la lista `[ebx+0x9E8]` (`0x00515E11..0x00515EA0`).
2. **Bucle caliente de relaciones — región SESE (`0x00515EA6..0x00516285`, `992 B`)**:
   - **Verificación CFG de entrada/salida única (`[confirmed]`)**: inspeccionando todos los saltos de `0x00515490..0x005163BA`:
     - **Única entrada desde fuera de `[0x00515EA6, 0x00516286)`**: `0x00515EA6` (por caída secuencial tras `0x00515EA0` o por `0x00515E19: je 0x00515EA6`).
     - **Única salida hacia fuera de `[0x00515EA6, 0x00516286)`**: `0x00516286` (por `0x00515EBA: jle 0x00516286` o caída secuencial tras `0x00516280: jl 0x00515EC0`).
3. **Post-bucle y epílogo (`0x00516286..0x005163BA`, `309 B`)**:
   - Si `[ebx+0xA00] != 0`, reescala `[ebx+0x1AC]` con `__allmul` (`0x00AC9F20`) / `__alldiv` (`0x00AC02A0`).
   - Si `[esp+0x20] > [esp+0x3C]`, reescala `0..[esp+0x18]-1` en `[ebx+0xDB8]` con `__allmul` / `__alldiv` (`0x005162C3..0x00516313`).
   - Recorre `[ebx+0x9F8]` para `[ebx+0xE28]` (`0x00516315..0x00516394`), llama `0x0051F4D0`, `0x0051F990`, `0x00545BE0`, restaura SEH desde `[esp+0x54]` (`0x005163A7`) y sale con `ret 4` (`0x005163B8`).

### Contrato exacto de pila y registros en la frontera SESE (`0x00515EA6` -> `0x00516286`)

Observado directamente sobre todas las referencias `[esp+disp]` y registros de `0x00515490..0x005163BA` (`[confirmed]`):

| Recurso | Valor / origen antes de `0x00515EA6` | Uso en `0x00515EA6..0x00516285` | Uso en `0x00516286..0x005163BA` | Requisito para reemplazo |
| --- | --- | --- | --- | --- |
| `EBX` | `[ebp+8]` (`self`) | Lectura y escritura sobre `self` | Lectura y escritura sobre `self` | **Preservar** (callee-saved) |
| `EBP`, `ESP` | Marco alineado (`and esp, -8`) | Base de pila fija en entrada/salida | Restauración de SEH y `ret 4` | **Preservar** |
| `[esp+0x14]` | `[0x012588E8]` (escrito en `0x005154FB` con `push` activo) | Leído en `0x00516214` | No leído | Solo entrada |
| `[esp+0x28]` | `[0x012587E4]` (escrito en `0x005154FF` con `push` activo; `0x00515E4E` está tras `push 0x10` y toca `+0x24`, no `+0x28`) | Leído en `0x00515EA6` y `0x00515EC0` | No leído | Solo entrada |
| `[esp+0x18]` | Scratch en pre-bucle | Escrito en `0x00515EAC` con `*country_mgr` (`total_tags`) | Leído en `0x005162CF` y `0x0051630F` (cota de `[ebx+0xDB8]`) | **Debe quedar escrito** = `*(uint32_t*)*(uintptr_t*)0x012587E4` antes de entrar en `0x00516286` |
| `[esp+0x20]`, `[esp+0x3C]`, `[esp+0x54]` | Escritos en prólogo/pre-bucle | No tocados | Leídos en `0x005162C3`, `0x005162C7`, `0x005163A7` | **No tocar** |
| `[esp+0x0C]`, `[esp+0x1C]`, `[esp+0x2C]`, `[esp+0x30]`, `[esp+0x34]`, `[esp+0x48]`, `[esp+0x4C]` | — | Temporales internos del bucle | `[esp+0x48]/[0x4C]` se reescriben en `0x005162D6..0x005162DA`; los demás nunca se leen | Pueden omitirse o usarse como scratch si no tocan otros slots |
| `EAX, ECX, EDX, ESI, EDI` | Scratch | Scratch | Todos se reescriben antes de leerse en cualquier camino desde `0x00516286` | Pueden quedar sucios al saltar a `0x00516286` (con `DF=0`) |

---

## 3. Semántica, escrituras globales y llamadas indirectas del bucle `0x00515EC0..0x00516285`

### A. Filtro inicial sin efectos secundarios (`0x00515EC0..0x00515F35`)

Para cada índice `idx = 0 .. total_tags - 1`:
1. `entry = (*(country_mgr + 4))[idx]`.
2. `other_id = *(uint32_t*)(entry + 0x20)`, `other_tag = *(uint32_t*)(entry + 0x1C)`.
3. Descarta si `other_id == *(uint32_t*)(self + 0x20)` (`0x00515EDC`), `other_id == 0` (`0x00515EE5`), o los primeros 3 bytes de `other_tag` son `"REB"` (`0x52, 0x45, 0x42`, `0x00515EED..0x00515F02`).
4. `other = (*(country_mgr + 4))[other_id]`. Descarta si `(*(int32_t*)(other + 0x9DC) - *(int32_t*)(other + 0x9D8)) & ~3 <= 0` (`0x00515F1E..0x00515F30`) — es decir, `other` no tiene provincias (`[inferred]`).

Hasta `0x00515F30` inclusive **no hay ninguna escritura en memoria ni llamada a función** `[confirmed]`.

### B. Procesamiento de relación y escrituras globales (`0x00515F36..0x00516272`)

Cuando `other` pasa el filtro (`[confirmed]`):
1. Obtiene `relation = (*(self + 0xBE8))[other_id]` (`edi`).
2. Si `0x004A8300(eax=self)` es `true` (`[ebx+0x7D8] != 0 && ([ebx+0xCF5] != 0 || [ebx+0xCF4] != 0)`), `[ebx+0xCFC] == other_id` y `[relation+0x20] == 0` (`0x00515F49..0x00515F6C`):
   - Asigna `0x24` bytes (`0x00AAE9AF`), construye comando `0x00DFFB0C` (`0x005163C0`), rellena campos `+0x08..+0x18`, llama `cmd->vtable[+0x28]` (`0x00515FB7`, estáticamente `0x0092C760`), y **añade `cmd` a la lista global `[0x012588E8] + 0xA7C`** mediante `0x004A7BC0` (`0x00515FB9..0x00515FC6`).
3. Actualiza contadores y vectores de `self`:
   - Si `[relation+0x20] != 0`: `++[ebx+0xDD8]` y push `other_tag/id` a `[ebx+0xD58]` (`0x004D61D0`).
   - Si `[relation+0x28]` coincide en tag `+0x08/+0x0C` con `relation`: push a `[ebx+0xD78]`.
   - Si `[relation+0x24] != 0` y `vtable[+0x1C] == 0x336` o `0x93A` y `+0x10/+0x14` coinciden con `relation+0x08/+0x0C`: `++[ebx+0xDDC]` y push a `[ebx+0xD38]`.
   - Si `[relation+0x24] != 0` y `vtable[+0x1C] == 0x93A` y `+0x10/+0x14` coinciden con `relation+0x08/+0x0C`: `++[ebx+0xDE0]` y push a `[ebx+0xD48]`.
   - Si no cumple condiciones de exención (`relation+0x20 == 0 && relation+0x24 == 0`, etc., y `relation+0x70 == 0`): push a `[ebx+0xD68]`.
4. Si `cmd = [relation+0x38] != NULL` (`0x00516134..0x005161C2`):
   - Si `[other+0x67C] != 0 && [relation+0x34] == 0`: añade `other` al vector `[ebx+0xEA4]` (`call 0x004E9B90`).
   - En caso contrario: busca el nodo `*node == cmd` en la **lista global `[0x012588E8] + 0xA84`**, lo desenlaza/libera mediante `0x005F2AE0` (`0x0051619D`), invoca `cmd->vtable[+0x2C]` (`0x005161A9`), marca `[relation+0x71] = 1` y `[relation+0x38] = 0`, e invoca `cmd->vtable[+0x00](1)` (`0x005161C2`).
5. Llama `0x00511140(edx=self+0x1C, [esp+4]=other)` (`0x005161D8`): si devuelve `!= 0`, añade `other` a `[ebx+0xEB4]` (`0x004E9B90`).
6. Si `[ebx+0x9F8]` no es vacía (`0x005161FF..0x00516271`): recorre esa lista ligada y, para cada elemento cuyo dueño `[elem+0x12C] == other_id`, llama `0x009692C0(eax=elem+0x1A8)` y suma `0x3E8` o el float `[0x00E45A40]` convertido vía `0x00401000` + `0x00B31C00` a `[ebx+0x1AC]`.

### C. Prueba de invarianza de `other+0x9D8/+0x9DC` y `[0x012587E4]` bajo las 6 llamadas indirectas del bucle

Se inspeccionaron todas las vtables en `.rdata` de `base-game/v2game.exe` con destructor `+0x00 == 0x004F62D0` o slot `+0x2C` de esta jerarquía (`12` vtables: `2` clases base abstractas `0x00E0175C`, `0x00E34B04` con `_purecall` `0x00AAEA2F`, y `10` concretas: `0x00DFFB0C`, `0x00E01790`, `0x00E03E74`, `0x00E337B4`, `0x00E337E8`, `0x00E34B38`, `0x00E34B6C`, `0x00E34BA0`, `0x00E34BD4`, `0x00E34C08`) (`[confirmed]`):

| Callsite VA | Slot virtual | Implementaciones posibles observadas | Mutaciones observadas | ¿Toca `other+0x9D8/C` o `[0x012587E4]`? |
| --- | --- | --- | --- | --- |
| `0x00515FB7` | `[esi]->+0x28` | `0x0092C760` (vtable fija `0x00DFFB0C` creada en `0x00515F7C`) | `self->relations[other]` y `other->relations[self]` (`+0x20`, `+0x71`), más `[world+0xB24]+0x74/+0x78` si `[world+0xD1C]!=0` | **No** (`[confirmed]`) |
| `0x00516026`, `0x00516037`, `0x0051607E` | `[edi+0x24]->+0x1C` | `0x008325F0` (`0x332`), `0x0092D080` (`0x336`), `0x0092D090` (`0x93A`), `0x0092CF50` (`0x443`), `0x0090E1E0` (`0x470`), `0x005EC4B0` (`0x333`), `0x005EC4C0` (`0x8E0`), `0x005EC4E0` (`0x8E5`), `0x0092CE90` (`0x8A4`), `0x005EC4D0` (`0x343`) | Todas son `mov eax, imm32; ret` puras (sin escrituras) | **No** (`[confirmed]`) |
| `0x005161A9` | `[edi]->+0x2C` | `0x004010C0` (`ret`); `0x0092C800`/`0x0092C930`/`0x0092CB10`/`0x0092CCA0` (limpian `+0x20/+0x28/+0x2C/+0x30` en ambas `CRelation` + opcional `[world+0xB24]`); `0x0092CFF0` (limpia `+0x24` y llama `0x00519920` sobre `[country+0xCF4..0xCFC]`); `0x0092CEF0` (limpia `+0xA8` y llama `0x0051C890` sobre `[country+0xAA8]`); `0x0092D3C0` (llama `0x0092F0A0` + `0x005F2AE0` sobre `relation+0x50`) | Solo campos de relación, flags/modificadores `+0xCF4..0xCFC`/`+0xAA8`, mensajes UI y `[world+0xB24]` | **No** (`[confirmed]`) |
| `0x005161C2` | `[edi]->+0x00` | `0x004F62D0` (todas las vtables de la jerarquía) | Restaura vtable `0x00E34B04` y llama `free` (`0x00AAE91B`) | **No** (`[confirmed]`) |

Además:
- `0x00511140` (`0x005161D8`) únicamente realiza una inicialización perezosa de `[0x0125A69C]` si es `NULL` y luego consultas de solo lectura (`0x005661B0`, `0x005068B0`) `[confirmed]`.
- Las otras 2 llamadas indirectas de `FUN_00515490` (`0x00515B86` y `0x00515D7F`) pertenecen al pre-bucle (unidades/flotas) y permanecen intactas fuera de la región SESE.
- **Seguridad TBB**: `0x00515EC0..0x00516285` **NO es thread-safe** `[confirmed]` — muta las listas globales `[0x012588E8]+0xA7C` y `+0xA84`, `[0x012588E8]+0xB24` y las entradas simétricas `other->relations[self]`.

### D. Tabla de convenciones de llamada de helpers invocados dentro de `0x00515EC0..0x00516285`

Para Paso B en C/ASM, todas las llamadas directas internas del bucle han sido verificadas (`[confirmed]`):

| Dirección | Rol inferido | Convención observada | Limpieza de pila |
| --- | --- | --- | --- |
| `0x004A8300` | Check bandera en `self` | `eax = self`; devuelve `al` | `ret` (`0 B`) |
| `0x004D61D0` | `vector<pair<tag,id>>::push_back` | `eax = &item (8 B)`, `edi = vector*` | `ret` (`0 B`) |
| `0x004E9B90` | `vector<ptr>::push_back` | `eax = &ptr (4 B)`, `edi = vector*` | `ret` (`0 B`) |
| `0x004A7BC0` | `list<ptr>::push_back` | `esi = list*`, `[esp+4] = ptr` | `ret 4` |
| `0x005F2AE0` | `list::erase(node)` | `esi = list*`, `[esp+4] = node*` | `ret 4` |
| `0x00511140` | Check relación/diplomacia | `edx = &self->tag` (`ebx+0x1C`), `[esp+4] = other*`; devuelve `al` | `ret 4` |
| `0x009692C0` | Índice dominante de mapa/array | `eax = base+0x1A8`; devuelve `eax` | `ret` (`0 B`) |
| `0x005163C0` | Ctor comando `0x00DFFB0C` (`0x24 B`) | `eax = buf`, devuelve `eax = buf` | `ret` (`0 B`) |
| `0x00AAE9AF` | `operator new` | `__cdecl (size_t)` | `ret` (caller limpia 4 B) |
| `0x00401000` / `0x00B31C00` | `round`/`__ftol2_sse` | `[esp] = float`, tras llamada a `0x00401000` y `add esp,4`, `0x00B31C00` devuelve `eax` | `ret` (`0 B`) |

---

## 4. Cierre de la ruta RNG condicional (`0x00515995 -> 0x004B8870 -> 0x004B88FC`)

`0x00515995` (`call 0x004B8870`, dentro del bucle de provincias del pre-bucle) **no ejecuta RNG en estado estacionario** (`[confirmed]`):
1. `0x004B8893..0x004B88C5`: solo si `[0x0131BB34] == 0`, asigna `0x188` bytes y publica el singleton una sola vez en la vida del proceso.
2. `0x004B88CA..0x004B88E6`: fija `esi = [0x0131BB34] + 0x0C`, calcula `ebx = ([esi+4] - [esi]) >> 2` (tamaño del vector de poptypes) e inicia `edi = 1` con condición `edi < ebx` (`0x004B88E4 cmp ebx, edi; jle 0x4b8960` y `0x004B8940 cmp edi, ebx; jl 0x4b88f0`).
3. En la cabeza del bucle (`0x004B88F0..0x004B88FA`), vuelve a calcular `eax = ([esi+4] - [esi]) >> 2` sobre el **mismo** vector y comprueba `cmp edi, eax; jle 0x004B8903`.
4. El cuerpo (`0x004B8903..0x004B893F`) únicamente lee `[eax+0x42]`, `[edx+0x194]`, la lista `+0x27C` y llama a `0x00965870` (solo lectura sobre `[0x012586DC]+0x20`, `[ebx+0x58]` y `0x004B64E0`, que a su vez solo lee `[eax+0x148..0x14C]`), sin modificar jamás `[0x0131BB34]` ni su vector `+0x0C`.
5. Por tanto, `1 <= edi < ebx == eax => edi <= eax` es una **tautología algebraica** para cualquier estado consistente del vector: `jle 0x004B8903` siempre se toma y `0x004B88FC call 0x0096BB70` (la ruta hacia `RE_RngNext_Signed32`) **es inalcanzable en ejecución estacionaria**. Además, con el detour SESE en `0x00515EA6`, `0x00515995` queda intacto en el binario original.

---

## 5. Estrategia de parcheo recomendada para Paso B

### Opción A (Recomendada): Detour inline SESE sobre `0x00515EA6..0x00516285`

- **Punto de hook**: `0x00515EA6..0x00515EAB` (**6 bytes exactos**: `8b 54 24 28 8b 02`, `mov edx, [esp+0x28]; mov eax, [edx]`), sustituidos por `E9 <rel32>` (`jmp detour_stub`) + `90` (`nop`), retornando directamente por `jmp 0x00516286`.
- **Por qué es superior a reemplazar la función completa**:
  1. Intercepta automáticamente los **43 callers** de `FUN_00515490` desde un único sitio de `6 B`, sin tocar prólogo SEH, pre-bucle (`0x00515490..0x00515EA5`) ni post-bucle (`0x00516286..0x005163BA`).
  2. Mantiene `100%` originales el pre-bucle x87/SSE/`0x004B8870`/`0x00515B86`/`0x00515D7F` y el post-bucle `__allmul`/`__alldiv`/`0x0051F4D0`/`0x0051F990`/`0x00545BE0`.
- **Algoritmo equivalente exacto del detour**:
  1. Leer `country_mgr = *(uint32_t**)[esp+0x28]`, `total_tags = country_mgr[0]`, `entries = (uint8_t**)country_mgr[1]`, `world = *(uint8_t**)[esp+0x14]`.
  2. Escribir **`*(int32_t*)[esp+0x18] = (int32_t)total_tags`** (requerido por `0x005162CF`/`0x0051630F`). Si `total_tags <= 0`, retornar directo a `0x00516286`.
  3. Mantener una lista densa en orden **estrictamente ascendente** de índices `idx` vivos (`(*(int32_t*)(other + 0x9DC) - *(int32_t*)(other + 0x9D8)) & ~3 > 0`, excluyendo `other_id == 0` y `"REB"`), reconstruible cuando cambie el tick o mediante caché por frame/país (con invalidación cuando no coincida con un barrido de validación). Para cada `living_idx` (saltando `other_id == self->id`):
     - Emitir `_mm_prefetch` (`PREFETCHT0`) a distancia `+2..+4` sobre `entries[next_living]`, `self_relations[next_id]` y `next_relation + 0x70` (verificando rango antes de dereferenciar).
     - Ejecutar exactamente la lógica de `0x00515F36..0x00516272` invocando los helpers de la tabla §3.D con sus convenciones exactas, preservando `EBX = self`, `EBP`, `ESP`, `[esp+0x20]`, `[esp+0x3C]`, `[esp+0x54]` y retornando a `0x00516286`.
  4. **Criterio de validación obligatoria antes de declarar PASS**: comparación bit-a-bit de estado final de país, vectores `[ebx+0xD38..0xD78]`, `[ebx+0xEA4/+0xEB4]`, `[ebx+0x1AC]`, listas `[0x012588E8]+0xA7C/+0xA84` y checksum de savegame en `base-game` / SPA 1837 frente al original sin filtrar.

### Opción B (Alternativa): Hook P2 completo en `0x00515490`

- ABI compatible con Paso A (`arg_bytes = 4`, `55 8b ec 83 e4 f8`, `C_hook = 56.3 ns`), pero **no recomendada inicialmente** porque exige reimplementar y verificar `2.8 KB` adicionales de pre/post-bucle sin ganancia sobre la Opción A (solo `1/56` muestras GFM en el pre-bucle).

### Diferencia respecto a `Country_PrePass` (`0x00508590`)

- `experiments/tick-country-prepare-lab` solo parchea `0x00685AA9..0x00685AE4` (`[confirmed]`) y no cubre `0x00508590` (llamado en `0x00685C2C`).
- En `0x00508590`, el bucle de stall `0x00508DEE` (`0x00508DA7..0x00508F1E`) filtra por `relation+0x2C != NULL` y **no** por `other+0x9DC - other+0x9D8 > 0` (`[confirmed]`). La lista de tags vivos de `COUNTRY-RECALCULATE.md` **no** puede reutilizarse en `0x00508590` sin demostrar aparte que `relation+0x2C == NULL` para todo tag sin provincias.

---

## 6. Auditoría C1b (variante b): `world+0xADC..0xAE0` — **NO-GO** (`[confirmed]`)

Se auditó si `world+0xADC..0xAE0` (`[0x012588E8] + 0xADC`) podía sustituir al barrido completo `0 .. total_tags - 1` de `[0x012587E4]+4` como lista pre-filtrada de tags vivos al entrar en `0x00515EA6`:

### A. Todos los escritores y mantenedores de `world+0xADC..0xAE0` (`[confirmed]`)

Búsqueda exhaustiva en `.text` de `base-game/v2game.exe` sobre los desplazamientos `0xADC` / `0xAE0` / `0xAE4` y los getters asociados (`0x00424A80`, `0x008687B0`):

| Sitio / Función | Operación sobre `world+0xADC..0xAE4` | Callers / Frecuencia | Estado |
| --- | --- | --- | --- |
| `0x0067F790` (ctor `CWorld` `[inferred]`) | Inicializa `+0xADC/+0xAE0/+0xAE4` a `0` (`edi`) | Construcción del mundo | `[confirmed]` |
| `0x0067FE40` (`0x0068018D..0x006801AC`, dtor/limpieza `CWorld` `[inferred]`) | Libera buffer (`0x00AAE91B`) y pone `+0xADC/+0xAE0/+0xAE4` a `0` | Destrucción del mundo | `[confirmed]` |
| `0x00680450` (`0x0068048D..0x00680507`) | Limpia `world+0xADC`, redimensiona vía `0x0068EA30` y **copia 1:1 todo el vector `[0x012587E4]+4`** (`CCountryManager`, `0 .. total_tags - 1`) en `world+0xADC..0xAE0`; después invoca `0x0068D250(world, 1)` | **1 único caller**: `0x0067DCA9` (carga/inicialización de partida) | `[confirmed]` |
| Lectores (`0x00424A80` -> `0x006C0F74`, `0x006C2DA9`, `0x006C5305`, `0x006C9204`; `0x0067D810` `vt[+0x1C]`; `0x00685AA9`, `0x00685C09`, `0x00685FBF`, `0x0068666F`, `0x00686F23`, `0x0068D364`, `0x00522AFF`, `0x005302F8`, `0x0061D903`, etc.) | Solo lectura (iteración o copia de snapshot local vía `0x009BEEB0` en UI/economía) | `0` mutaciones sobre `world+0xADC` | `[confirmed]` |

### B. Evaluación de las 4 condiciones en `0x00515EA6` (`[confirmed]`)

1. **¿Contiene exactamente los países con `(other+0x9DC - other+0x9D8) & ~3 > 0`?** — **NO.** `0x00680450` copia literalmente todos los tags definidos desde `[0x012587E4]+4`, incluidos todos los tags muertos (`0` provincias). De hecho, `0x0068D250` (`0x0068D364..0x0068D386`) itera `world+0xADC` y comprueba explícitamente `(esi+0x9DC - esi+0x9D8) & ~3 > 0` para poblar otro vector distinto (`world+0xBD0..0xBD4`).
2. **¿Excluye `other_id == 0` y `"REB"`?** — **NO.** Ambos permanecen en `[0x012587E4]+4` y en `world+0xADC`: por ello `Country_DailyUpdate` (`0x00685C15: mov esi, 1`) salta a mano el índice `0` al recorrer `world+0xADC` para llamar `Country_PrePass` (`0x00508590`), y `0x005089B5..0x005089DB` sigue llamando a `0x00515490` sobre `"REB"`.
3. **¿Está en orden ascendente `idx` coincidente con `[0x012587E4]+4` (`0 .. total_tags - 1`)?** — **SÍ**, precisamente porque es un espejo sin filtrar de `[0x012587E4]+4`, lo que da **0% de reducción de iteraciones**.
4. **¿Se actualiza síncronamente cuando cambia el dueño de una provincia?** — **NO.** `world+0xADC..0xAE0` no se actualiza tras `0x0067DCA9 -> 0x00680450`.
   - *Nota informativa sobre `world+0xBD0..0xBD4`*: el vector derivado que sí filtra `(other+0x9DC - other+0x9D8) & ~3 > 0` en `0x0068D250` **tampoco** cumple los requisitos para sustituir directamente el bucle de `0x00515EA6`, porque: (i) `0x0068FB80` / `0x0068FC60` (`0x00691520`) lo ordenan por puntuación (`+0x1A4/+0x1A0`) en lugar de por `idx` ascendente, (ii) no excluye `id == 0` ni `"REB"` si tuvieran provincias, y (iii) solo se reconstruye en los `8` callers de `0x0068D250` (en `Country_DailyUpdate`, en `0x0068636D`, **después** de `Country_PrePass` en `0x00685C2C`).

### C. Veredicto C1b

- **Veredicto binario para variante (b) (`world+0xADC..0xAE0`)**: **`NO-GO`** (`[confirmed]`).
- Cualquier futura variante con filtrado de tags vivos en Paso B deberá mantener su propia lista densa ordenada ascendentemente por `idx` (o bitset reconstruido/invalidado antes de la iteración) filtrada explícitamente por `other_id != 0 && tag != "REB" && (other+0x9DC - other+0x9D8) & ~3 > 0`, nunca `world+0xADC` ni `world+0xBD0` sin reordenar/validar.

---

## Comandos de reproducción

```bash
source research/env.sh
python3 research/scripts/find_callers.py base-game/v2game.exe 0x00515490
python3 research/scripts/find_callers.py base-game/v2game.exe 0x00680450
python3 research/scripts/find_callers.py base-game/v2game.exe 0x0068D250
python3 research/scripts/disasm_fn.py 0x00515490 --csv research/evidence/generated/ghidra-converged/functions.csv
```
