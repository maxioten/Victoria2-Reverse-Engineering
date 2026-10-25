# Job diario de IA por país — cadena y estructura

Estado: **en curso**. Este documento fija lo que está verificado con bytes y llamadas, y separa
explícitamente lo que sigue siendo inferencia. No es un contrato cerrado: no hay todavía
reverify ni emulación Unicorn para este bloque.

- Binario: `../base-game/v2game.exe`, SHA-256
  `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`
- Base preferida `0x00400000`; todas las direcciones son VA salvo que diga RVA.
- **Nomenclatura**: en este documento `world` = `0x012588E8`, el global que el repositorio ya
  documenta como `g_ProvinceManager` en [PROVINCE-EVENT-SPAWN](contracts/PROVINCE-EVENT-SPAWN.md).
  Es el mismo objeto; se mantiene el alias por legibilidad del código desensamblado.
- **Aviso de método**: el desensamblado lineal de Rizin se desincroniza dentro de
  `FUN_00876240` (aparecen instrucciones `invalid` y `mov gs` alrededor de `0x0087673E`). Las
  lecturas de esa zona se verificaron con Capstone, que da `cmp [ebp+8],ecx / jle / lea edx,[edi+0x40] /
  call 0x9B7910 / idiv [ebp+8]`. No publicar desensamblados de Rizin de esa función sin
  contrastarlos.

## Resumen del bloque

| pieza | VA | tamaño | papel verificado |
| --- | --- | --- | --- |
| `AI_FrameUpdate` | `0x006874C0` | 282 B | consume cola con presupuesto de tiempo; spin por `[country+0x208]` |
| `FUN_0081e9e0` | `0x0081E9E0` | 196 B | job de un país; descarta `REB`; 6 sub-rutinas |
| `AI_DecisionUpdate` | `0x00821190` | 885 B | evalúa candidatos y tira RNG dos veces |
| `FUN_0081E5B0` | `0x0081E5B0` | 1060 B | milésimas + recorrido de `[country+0x7B4]` |
| `0x00821510` | — | — | refresca `[nodo+0xA0]` en la lista del país |
| `0x005DCAC0` / `0x005DCB70` | — | — | arma y descarta acumulador de la lista del país |
| `FUN_00820DF0` | `0x00820DF0` | 788 B | recorre `[country+0xCE4]`, filtra por slot 27 y `[+0x24]==1` |
| `FUN_0081E280` | `0x0081E280` | 812 B | milésimas + elección aleatoria `arr[rand()%n]` |
| `FUN_00876240` | `0x00876240` | 1793 B | 7 llamadores; 551 instr., 32 calls, 1 bucle real + 8 salidas |

Hecho clave: **el job consume `rand()` del CRT con estado por hilo** (`ptd+0x14`, 15 bits), y
`FUN_00876240` usa además un LCG aparte con estado en `this+0x40`.

## `AI_FrameUpdate` — consumidor de una cola con presupuesto de tiempo

`FUN_006874c0` (`0x006874C0..0x006875DA`, 282 bytes) **no** recorre la lista de países: consume
una cola de trabajos.

1. Inicialización perezosa de un singleton en `0x00F20C18`: si es cero, `push 4; call 0xAae9af`
   (alloc de 4 bytes), escribe `0x00E38B28` en `[eax]` y guarda el puntero. Al final de la función
   repite exactamente el mismo bloque, es decir el objeto se crea y se vuelve a asegurar en la
   misma llamada. `0x00E38B28` apunta a una tabla de funciones, pero **no tiene locator RTTI**, así
   que la clase no se puede nombrar por esa vía.
2. Lee el reloj: `mov ecx,[0x1258A8C]; mov eax,[ecx]; mov edx,[eax+0x14]; call edx;
   fstp qword [ebp-0x0C]` — un `double` que queda como presupuesto de tiempo del frame.
3. `mov esi,[ebp+8]; mov esi,[esi]` y `cmp dword [esi+8], 0; jle fin` — la cola tiene su contador
   en `+0x8`; si está vacía termina.
4. Extrae un nodo (`[eax]`, `[eax+4]`, `[eax+0xC]`, ajuste de `[esi]`/`[esi+4]`), lo libera con
   `call 0xAae91b` y hace `dec dword [esi+8]`.
5. Con el índice de país del trabajo (`edi`):
   ```
   country = ((Countries*)0x12587E4)->begin[edi];
   if (((country->[0x9DC] - country->[0x9D8]) & ~3) <= 0) goto fin;
   esi = country->[0x208];
   while (esi == 0) ;                    // spin: 0x00687572..0x00687574 salta a sí mismo
   FUN_0081e9e0(esi);
   ```

El **spin** de `0x00687574` espera a que `[country+0x208]` deje de ser cero antes de ejecutar el
job. `inferred`: inicialización perezosa del nodo de IA del país, o una bandera de "ocupado" que
otro contexto publica. Es un punto a auditar antes de cualquier paralelización, porque un spin
sobre estado compartido con varios hilos puede colgar el proceso.

Esto explica por qué `fast_ai_queue` (que drena la cola en un frame) rinde tanto: sin él la cola
se corta por presupuesto y el trabajo se reparte entre frames, pagando la re-entrada cada vez.

## Cadena verificada

Perfil de muestreo sobre el hilo principal (sección `stack`), más los sitios de llamada
localizados con [`scripts/find_callers.py`](../scripts/find_callers.py):

```
AI_FrameUpdate  FUN_006874c0
  └── loop: nodo = nodo->[+0x208]          0x00687578  (call)   confirmed
        └── FUN_0081e9e0  job de IA de un país
              ├── 0x00821510                      0x0081EA32                      confirmed
              ├── 0x005DCAC0                      0x0081EA3D  (arma acumulador)
              ├── (virtual [vtable+0x24])         0x0081EA4A  call eax
              ├── 0x005DCB70                      0x0081EA52  (descarta acumulador)
              ├── 0x00820DF0                      0x0081EA58                      confirmed
              ├── 0x0081F3B0                      0x0081EA5E                      confirmed
              ├── 0x0081FB00                      0x0081EA82  (gate [+0xBB8]==0)
              ├── 0x00820760                      0x0081EA88  (mismo gate)
              ├── 0x0081E5B0                      0x0081EA8E                      confirmed
              ├── 0x0081E280                      0x0081EA94                      confirmed
              └── 0x00821190  AI_DecisionUpdate   0x0081EA9B  (llamador único)  confirmed
```

`FUN_0081e9e0` tiene exactamente **tres** llamadores, los tres recorriendo la misma lista
enlazada por `+0x208`:

| sitio de llamada | dentro de | patrón del bucle |
| --- | --- | --- |
| `0x00687578` | `AI_FrameUpdate` (`0x006874C0`) | `mov eax,[eax+0x208]; cmp eax,ebx; ...; mov esi,eax; call` |
| `0x0064F01C` | recorrido alternativo por array de punteros | `mov eax,[edi]; add edi,4; ...; mov esi,[eax+0x208]; call` |
| `0x006690CD` | idem, con `cmp [eax+0x208],0; jz` antes de llamar | igual al anterior |

Lectura (`inferred`): `+0x208` es el puntero `next` de una lista de países, y los tres bucles
son el recorrido por país del AI. `esi` transporta el nodo; `[esi+0x30]`/`[esi+0x34]` son la
identidad del país.

## `FUN_0081e9e0` (196 bytes, `0x0081E9E0..0x0081EAA4`)

Estructura verificada por desensamblado:

1. `mov eax,[esi+0x30]; mov ecx,[esi+0x34]` — identidad del país en dos palabras.
2. `cmp al,'R'; jnz; shr edx,8; cmp dl,'E'; jnz; shr eax,16; cmp al,'B'; jz 0x81EAA0` —
   comparación contra los bytes `'R','E','B'`. `confirmed` en los bytes; `inferred`: es el tag
   `REB` (rebeldes) y esos países se saltan el job normal.
3. `mov ecx,[0x12587E4]; mov edx,[ecx+4]; mov edi,[edx+eax*4]` — vector global indexado por la
   segunda palabra de la identidad, elementos de 4 bytes. `inferred`: tabla de países;
   `0x12587E4` guarda `begin` en `+4`.
4. `mov eax,[edi+0x9DC]; sub eax,[edi+0x9D8]; test eax,0xFFFFFFFC; jle 0x81EAA0` — si un vector
   en `+0x9D8` (begin) .. `+0x9DC` (end) está vacío, salta al final sin trabajo.
5. `lea eax,[edi+0x7B4]; call 0x5DCAC0` … llamada virtual `mov ecx,[esi+0x38]; mov edx,[ecx];
   mov eax,[edx+0x24]; call eax` … `lea eax,[edi+0x7B4]; call 0x5DCB70`.
   **Corregido tras desensamblar**: `0x5DCAC0` no es un lock. Construye una lista auxiliar de
   nodos de 16 bytes (`alloc 0x10` por `0xAae9af`) recorriendo las listas internas
   (`next` en `+8`) de cada nodo de `[arg]`, encadenándolos en `head`/`tail` (`+0x90`/`+0x94`),
   incrementando el contador `+0x98`, escribiendo un backpointer `[elem+0x78] = arg` y sumando
   `[elem+0x3C]` en el acumulador `+0x8C`. `0x5DCB70` recorre esa lista, libera cada nodo con
   `0xAae91b` y pone a cero `+0x8C`, `+0x90`, `+0x94` y `+0x98`.
   **No hay mutex en esta ruta.**
6. Después del acumulador, la secuencia verificada de llamadas (Capstone, todas con su sitio):

   | sitio | destino | nota |
   | --- | --- | --- |
   | `0x0081EA32` | `0x00821510` | refresco de `[nodo+0xA0]` |
   | `0x0081EA3D` | `0x005DCAC0` | arma acumulador |
   | `0x0081EA4A` | `call eax` | virtual `[vtable+0x24]` |
   | `0x0081EA52` | `0x005DCB70` | descarta acumulador |
   | `0x0081EA58` | `0x00820DF0` | — |
   | `0x0081EA5E` | `0x0081F3B0` | cálculo con doubles |
   | `0x0081EA82` | `0x0081FB00` | bajo `byte [country+0xBB8]==0` |
   | `0x0081EA88` | `0x00820760` | mismo gate |
   | `0x0081EA8E` | `0x0081E5B0` | milésimas + recorrido |
   | `0x0081EA94` | `0x0081E280` | — |
   | `0x0081EA9B` | `0x00821190` | `AI_DecisionUpdate` |

Preguntas abiertas:

- Qué representa exactamente `[country+0x7B4]`: la lista externa tiene `next` en `+8` y sus
  nodos exponen listas internas en `[nodo+0x38]`. Falta identificar el tipo (candidatos:
  unidades por provincia o grupos militares) y el significado de `[elem+0x3C]`, que se acumula.
- `0x5DCAC0`/`0x5DCB70` también se llaman desde `0x0081DFF2`/`0x0081E01E` (otra función de IA),
  lo que sugiere que el acumulador es un patrón repetido y no algo exclusivo del job diario.
- Slot real, vtable y firma del virtual `+0x24`.
- Origen y contrato de `0x12587E4`: quién lo escribe y si el vector puede crecer durante el
  bucle (afectaría cualquier paralelización).
- Qué país recibe `ebx` en el bucle de `0x00687574` (el `cmp eax,ebx` no está resuelto).

## `FUN_00821190` — `AI_DecisionUpdate` (885 bytes, `0x00821190..0x00821505`)

- **Un solo llamador**: `0x0081EA9B`, dentro de `FUN_0081e9e0`. `confirmed`.
- Usa SEH (`push 0xffffffff; push 0xBA0ADC; mov eax,fs:[0]`), 45 bytes de pila local y objetos
  temporales de 56 bytes (`push 0x38; call 0xAAE9AF`), lo que sugiere contenedores locales.
- Prefijo `-0x60` construido con `push 0x2D` (45) antes de las dos palabras de identidad del
  país: `inferred`, algún tipo de filtro o scope por país.

### Consumo de RNG (confirmado)

La función llama **dos veces** al generador LCG del CRT, en `0x008212FA` y `0x00821453`, con
exactamente el mismo patrón:

```
call  pe_008212dc        ; devuelve un float (probabilidad) en xmm0
cvtss2sd xmm0, xmm0
mulsd xmm0, qword [0x00E455E8]     ; constante double 100.0
cvtsd2ss xmm0, xmm0
fld   dword [ebp-0x10]
fistp dword [ebp-0x14]             ; umbral entero 0..100
call  0x00AB047B                   ; LCG
cdq; mov ecx,0x64; idiv ecx        ; edx = rand % 100
cmp   edx, dword [ebp-0x14]
jnl   ...
```

- `0x00AB047B` es el LCG de MSVC: `mov eax,[ecx+0x14]; imul eax,eax,0x343FD;
  add eax,0x269EC3; mov [ecx+0x14],eax; shr eax,0x10`. Mismo par de constantes que
  `lcg_step` en [`scripts/event_spawn_model.py`](../scripts/event_spawn_model.py) y el contrato
  [EVENT-SPAWN](contracts/EVENT-SPAWN.md). **No** es el MT19937 de
  [RNG](contracts/RNG.md) (`0x009B7610`, estado de 2.500 bytes): son dos generadores distintos.
- `0x00E455E8` contiene el double `100.0` (`0x4059000000000000`), leído del archivo.
- La forma `rand() % 100 < (int)(chance * 100.0)` es una tirada de probabilidad porcentual.

**De dónde sale el estado (resuelto).** `0x00AB047B` no es una función suelta: el desensamblado
con Capstone muestra que empieza llamando a `0x00AB98AF`, que es el `__acrt_getptd()` de MSVC
(`call 0x00AB9836`, y si devuelve cero `push 0x10; call 0x00AB220B`). El estado vive en
`ptd+0x14` y la rutina completa es:

```
call 0x00AB98AF            ; ptd = __acrt_getptd()
ecx = eax
eax = [ecx+0x14]           ; seed
eax = eax * 0x343FD + 0x269EC3
[ecx+0x14] = eax
eax >>= 16
eax &= 0x7FFF              ; 15 bits
ret
```

Es decir **`rand()` del CRT, con estado por hilo**, y coincide exactamente con `lcg_step` +
`& 0x7FFF` de [`event_spawn_model.py`](../scripts/event_spawn_model.py) y del contrato
[EVENT-SPAWN](contracts/EVENT-SPAWN.md). `0x00AB047B` tiene 38 referencias en el binario.

Consecuencia para paralelizar: al repartir el bucle de países entre hilos, cada hilo tendría su
propio `ptd` y por tanto su propia secuencia; el resultado deja de coincidir con la partida
secuencial. Mantener el determinismo exige un estado controlado por país (o serializar el
consumo), que ya no es una transformación transparente.

Aparte, `FUN_00876240` usa **otro** generador: `0x009B7910` recibe el estado explícitamente en
`this+0x40` y hace dos pasos del mismo LCG. Los dos conviven; no son el mismo objeto.

### Construcción del `CEventScope`

`0x008A88D0` (112 bytes) escribe `0x00E2C904` en `[eax]` y `0x18D` en `[eax+4]`, y copia tres
palabras desde `[ecx+8]`, `[ecx+0xC]` y `[ecx+0x10]`. Por RTTI, `0x00E2C904` es la vtable de
`CEventScope`, así que la función construye (o copia) un ámbito de evento. El literal
`Event_Election_Window` de `0x00E2C918`, apuntado desde `0x004010C0`, es un campo de la tabla y
no el nombre de la clase.

### Los dos bucles: evaluador de condiciones

Los dos bucles tienen la **misma forma** (`0x0082127F` y `0x008213D8`), sobre un array de
punteros con `begin`/`end` en `[ebx]`/`[ebx+4]`:

```
for (edi = begin; edi < end; edi += 4) {
    esi = *(void**)edi;                        // candidato
    if (!((C*)esi)->vtable[6]())            continue;   // [vtable+0x18]
    if (!((C*)esi)->vtable[6]())            continue;   // idéntica a la anterior
    if (!((C*)(esi+0x24))->vtable[6](&ctx)) continue;
    if (!((C*)(esi+0x40))->vtable[6](&ctx)) continue;
    if (rand() % 100 >= (int)(chance * 100.0)) continue;
    ...
}
```

- El slot 6 (`+0x18` de la vtable) devuelve `bool` en `al` y es el mismo en las cuatro llamadas:
  `inferred`, es el `Evaluate` genérico de un nodo de condición.
- `lea ecx,[esi+0x24]` y `lea ecx,[esi+0x40]` pasan direcciones de **subobjetos embebidos** como
  `this`, no punteros: son miembros del propio candidato (patrón de composición de condiciones).
- Las dos primeras llamadas son **idénticas** (mismo `esi`, mismo slot, sin argumentos). No se
  puede asumir que sean redundantes sin auditar efectos laterales, pero es un candidato obvio de
  memoización *si* se demuestra que el método es puro.

Esto explica el coste medido del bloque: cada candidato cuesta cuatro llamadas virtuales más una
tirada de RNG, y el motor evalúa del orden de mil candidatos por país y lote.

### Estructura de control

14 llamadas directas, 14 virtuales y dos bucles reales (`0x008212A0 → 0x0082127F` con cuatro
entradas y `0x008213F9 → 0x008213D8` con dos). Los objetos temporales se crean con
`push 0x38; call 0xAAE9AF` y se inicializan con `0x8750A0`/`0x876010`; `0x876010` compara su
argumento contra el global `0x1319730`.

## Evaluadores de condiciones (la cadena del 18 % del perfil)

Los cuatro nodos que el perfil de muestreo atribuye al AI tienen forma de evaluador genérico:

| VA | tamaño | forma verificada |
| --- | --- | --- |
| `0x008B8260` | 66 B | **AND**: recorre `[this+8]..[this+0xC]` (punteros, `>>2`) y devuelve `false` en cuanto un `elem->vtable[6](arg)` da falso |
| `0x008B9240` | 66 B | **OR**: mismo recorrido, pero `cmp al,1; jz` devuelve `true` en cuanto uno da verdadero |
| `0x008B94B0` | 117 B | **selección aleatoria**: construye contexto (`0x008A8650`), llama `0x00876240` con `[this+0x1C]` y luego evalúa el vector |
| `0x008E2A70` | 47 B | **hoja comparadora**: `country = Countries->begin[arg->[0xC]]; return country->[0xE64] == this->[0x1C]` (`setz al`) |

Los dos primeros son idénticos salvo la condición de corte, y ambos comparten el slot
`[vtable+0x18]` (slot 6) como método de evaluación de cada elemento. La hoja `0x008E2A70` es el
patrón de comparación más simple que aparece en toda la cadena: resuelve un país por índice y
compara un único campo (`+0xE64`) contra un valor guardado en el nodo.

Esto encaja con el coste medido: la evaluación es un árbol de llamadas virtuales de dos
instrucciones útiles por nodo, con `vtable[6]` invocado una vez por elemento y por nivel.

## Sub-updates del job

### `0x00821510` — refresco de un campo cacheado por nodo

```
country = ((Countries*)0x12587E4)->begin[[node+0x34]]
for (n = country->[0x7B4]; n != NULL; n = n->[0x8]) {
    if (n->[0xEC] > 0)  n->[0xA0] = *(uint32_t*)n->[0xE8];   // doble indirección
    else                n->[0xA0] = 0;
}
```

- Es el **mismo** `[country+0x7B4]` que usa `0x5DCAC0`, recorrido con `next` en `+0x8`.
- `[+0xEC]` es un contador o tamaño; `[+0xE8]` un puntero que se desreferencia dos veces antes de
  guardarse en `[+0xA0]`. `inferred`: refresca un valor derivado (posiblemente un puntero a la
  entidad "actual" del nodo) antes de que la IA lo consulte.

### `0x0081E5B0` — 1060 bytes, cálculo en milésimas y recorrido de la lista del país

Es la sub-rutina más grande del job (`0x0081E5B0..0x0081E9D4`). Tiene dos partes:

**a) Prólogo de cálculo** (`0x0081E5B0..0x0081E665`):

```
if (country->[0x67C] != 0) return ...;                  // gate booleano por país
num = country->[0x160] * 1000 + bias;                   // bias = [0x131736C]
den = country->[0x168] * 1000 + bias;
if (den == 0) return -1;
if (num in [-1610611, 2147482])  result = num * 1000 / den;      // 32-bit
else                             result = _alldiv(_allmul(num,1000), den);  // 0x00AC9F20 / 0x00AC02A0
if (result < [0x13173CC]) jump a 0x0081E7C2;
```

Los límites `0xFFE76C8C`/`0x20C49B` y la secuencia `imul 0x3E8` + `_allmul`/`_alldiv` son **los
mismos** que el repo ya documentó para los ratios de formación en
[FORMATION-COHESION](contracts/FORMATION-COHESION.md): el job de IA reutiliza el mismo helper de
división en milésimas. `0x00AC02A0` (169 bytes) es la rutina de 64 bits que aparecía con 2.5 % en
el perfil de muestreo.

**b) Recorrido de la lista del país** (`0x0081E671` en adelante): `esi = [country+0x7B4]`,
`next` en `[esi+8]`, y por nodo llama `pe_0081E692`, comprueba `[nodo+0x74] != 0` y ejecuta dos
virtuales (`[vtable+0x3C]` y `[vtable+0x30]`), comparando `[eax+0x1AC]` contra cero. Es decir,
la misma lista `[country+0x7B4]` que recorren `0x00821510` y `0x005DCAC0` — es la estructura
central del job.

Advertencia de método: `+0x7B4` aparece en **82** sitios del binario según
`scripts/field_refs.py`, y `+0xBB8` en 27. El escaneo no distingue tipos (el mismo desplazamiento
se usa sobre el país y sobre el mundo), así que esos conteos son candidatos y **no** identifican
el campo.

### `0x0081F3B0` — cálculo numérico con doubles

Gate por `[country+0xAF8] != 0`. Trabaja con `fld qword [0xE45C68]`, `xorpd`/`movlpd` para
inicializar dos doubles locales en cero y llama dos veces a rutinas tomadas de registro
(`pe_0081F412`, `pe_0081F422`, convenciones no estándar). Después usa `[0xF096C8]` con
`add edx,0x0B; add edx,edx` (índice ×2 tras sumar 11). `inferred`: cálculo de una magnitud
temporal o de proporción; el `×2` sugiere tabla de pares.

### `0x0081FB00` y `0x00820760` — construcción de cadenas

Ambas arrancan con el mismo patrón de constructor de `std::string` en la pila
(`push 0x849E90; push 0x84A380; push 0x07; push 0x10; lea eax,[ebp-…]; push eax; call …`),
es decir, cadena vacía con capacidad inicial, y luego leen `[0x12588E8]` (el mundo) y
`[country+0xEC4]`.

- `0x0081FB00`: `mov eax,[0x12588E8]; mov eax,[eax+0xBCC]; add eax,0x280; push eax;
  lea ecx,[country+0xEC4]` — usa `world+0xBCC` y un desplazamiento de `+0x280`.
- `0x00820760`: llama `0x51F8C0` con `ecx = country`, compara un local contra
  `[0x12586DC]+0x60 → [+0x30]`, y vuelve a leer `[0x12588E8]`.

`inferred`: generan texto para la interfaz o el registro de mensajes de la IA. Las dos están bajo
el gate `byte [country+0xBB8] == 0` del job.

### Global de países: creación y destrucción

`0x012587E4` tiene **exactamente dos escrituras** en `.text` (`mov [imm32],reg`), y las dos están
identificadas ahora:

**Creación — `FUN_0055cdc0` (143 B, `0x0055CDC0..0x0055CE4F`), cierre de rango exacto:**

```
if ([0x12587E4] != 0) return            ; singleton
esi = alloc(0x424)                      ; 1060 bytes
[esi+0] = [esi+4] = [esi+8] = [esi+0xC] = 0
sub_AAEB25(&esi[0x14], 0x10, 0x40, 0x413490, 0xAA8540)   ; contenedor interno
[esi+0x414] = [esi+0x418] = [esi+0x41C] = 0
[0x12587E4] = esi
```

El vector de países vive en `+4`/`+8` (begin/end), que es lo que leen todos los bloques del job, y
el objeto mide **1060 bytes** con un contenedor asociado en `+0x14` (elemento de `0x10`, capacidad
`0x40`).

**Destrucción — función en `0x0055C750` que Ghidra no detectó** (cae en un hueco entre
`FUN_0055c6c0` y `FUN_0055c7e0`):

```
0x0055C750  ... vacía dos contenedores globales (0x125DD20 y 0x125DD98) con 0x55CF70 ...
0x0055C7AF  eax = [0x12587E4]
0x0055C7B4  [0x125DD9C] = 0
0x0055C7BC  if (eax == 0) goto 0x55C7CF
0x0055C7C1  call 0x55C7E0                ; destructor del gestor de países
0x0055C7C7  push esi; call 0xAAE91B      ; free
0x0055C7CF  mov [0x12587E4], edi         ; NULL
```

Es un teardown global: libera contenedores, destruye el gestor y anula el puntero. El `0x0055C7CF`
que aparecía como "hueco de Ghidra" en el control de direcciones queda explicado: **es una función
que el analizador no reconoció**, no una dirección inválida.

### `0x00820DF0` — 788 bytes, recorrido de `[country+0xCE4]`

```
country = ((Countries*)0x12587E4)->begin[[arg+0x34]]
list = country->[0xCE4]
if (!list) goto fin
for (n = list; n; n = n->[0x8]) {
    esi = n->[0];
    0x00911760(&local, 0);
    if (esi->vtable[27](esi) != 0) goto fin       // [vtable+0x6C]
    if (esi->[0x24] != 1)          goto fin
    ... cadena de llamadas a 0x0084xxxx ...
}
```

18 llamadas directas, casi todas a funciones de la zona `0x0084xxxx`, con un filtro explícito por
`[esi+0x24] == 1` y una llamada virtual al slot 27. `inferred`: es el recorrido de una colección
del país (unidades o grupos) y la cadena posterior decide acción por elemento; no identificado.

### `0x0081E280` — 812 bytes, milésimas y elección aleatoria

Comparte el esqueleto de `0x0081E5B0`: resuelve el país por `0x12587E4`, aplica el gate
`[country+0x67C]` y otro `[country+0x12D0]`, lee el vector `[country+0x9D8]..[country+0x9DC]` y
usa `[world+0xACC]` como tabla indexada. Repite la división en milésimas con `0x00AC9F20` /
`0x00AC02A0` y dos veces `0x00A513F0` (comprobación de `std::vector`: `cmp eax,0x3FFFFFFE`).

Al final elige un elemento al azar:

```
n = (end - begin) >> 2
if (n <= 0) goto fin
rand()                       // 0x00AB047B, thread-local
idx = rand() % n             // idiv
esi = begin[idx]
call [ [esi+0x38] -> vtable[9] ]     // [.. +0x24]
```

Es el mismo patrón de selección que `0x00876240`, pero aquí el elemento se toma del vector del
país, no de una lista de efectos.

## `FUN_00876240` (1793 bytes) — selección aleatoria sobre una lista de efectos

**551 instrucciones, 32 llamadas directas, 9 saltos hacia atrás** (verificado con Capstone;
Rizin daba cifras distintas porque se desincroniza). De esos 9 saltos, **8 apuntan al epílogo
compartido en `0x008767F0`** (`mov byte [esi+0x1C],0; lea esp,[ebp-0x1C]; pop…; ret 4`) y sólo
**uno es un bucle real**: `0x00876701`. El listado completo está en
`evidence/generated/ai-job/FUN_00876240.capstone.asm`. Ese bucle es:

```
loop:
    eax = *ecx                       ; nodo de la lista
    if ([eax+0x74] == 0)        skip ; filtro 1
    if ([eax+0xC4] == [ebx+0x12C]) skip ; filtro 2 (igualdad contra un campo del contexto)
    *(u32*)dst       = [eax+0xC0]    ; guarda un PAR de 8 bytes
    *(u32*)(dst+4)   = [eax+0xC4]
    dst += 8; count++                ; [ebp+0x08]
    ecx = [ecx+8]                    ; next
    if (ecx) goto loop

    call 0x009B7910                  ; LCG del CRT (dos pasos de imul 0x343FD / add 0x269EC3)
    cdq; idiv count                  ; índice = rand % count
    ecx = [tabla + idx*8]
    edx = [tabla + idx*8 + 4]
    [esi+8] = ecx
    [esi+0xC] = edx                  ; resultado = par elegido
```

Es el patrón de una **lista de opciones con selección aleatoria uniforme**: acumula pares
(peso/valor, id) de los nodos que pasan dos filtros y elige uno con `rand() % count`.

Otras piezas verificadas:

- `0x00504750` (110 bytes) copia cinco palabras (`[ecx+4..0x10] → [eax+4..0x10]`): es la copia de
  la estructura pequeña que el llamador usa como destino (`mov ecx,edi; mov eax,esi; call`).
- `0x009B7910` (48 bytes) son **dos** pasos del LCG del CRT seguidos.
- Prólogo: cuenta elementos del vector global de `0x12587E4` (`[ebx+8]-[ebx+4]`, máscara
  `0xFFFFFFFC`) y toma un camino corto si hay menos de cuatro.
- Ruta rápida: si `[arg+0x10C] != 0`, copia `[arg+0x108] → [esi+8]` y `[arg+0x10C] → [esi+0xC]`,
  pone `[esi+0x10] = 0` y hace `ret 4`.

Hipótesis de trabajo (`hypothesis`, no confirmada): el `arg+0x108`/`arg+0x10C` es el par
"seleccionado" ya resuelto y el `arg+0x10C != 0` significa "elección forzada"; en ese caso el
bucle con RNG sería el camino de elección libre. Falta contrastarlo con quien escribe ese par.

### Las 11 salidas por condición

La función no tiene un único `ret`: hay **11 saltos al epílogo compartido `0x008767F0`**
(`mov byte [esi+0x1C],0; lea esp,[ebp-0x1C]; pop edi/ebx; mov esp,ebp; pop ebp; ret 4`), cada uno
con su condición previa. Todas salen con el byte `[esi+0x1C]` puesto a cero:

| sitio | condición de salida |
| --- | --- |
| `0x008763E6` | `test al,al` tras un virtual `[vtable+0x20]` |
| `0x00876464` | `cmp dword [edi+0x18], 0` |
| `0x008766F8` | `test ecx,ecx` (lista vacía; antes pone `[ebp+8]=0`) |
| `0x00876741` | `cmp [ebp+8], ecx; jle` → contador de opciones ≤ 0 |
| `0x0087680D` | `mov edi,[edi+0x18]; test edi,edi` → recorre otra lista por `+0x18` |
| `0x00876826` | `[world+0xACC][idx] → [+0x188]` nulo |
| `0x0087682F` | `[objeto+0x288] == 0` |
| `0x00876878` | `[world+0xCF8] → [+0x8]` nulo |
| `0x00876892` | `[world+0xACC][idx] → [+0x188]` nulo (segunda rama) |
| `0x00876901` | `mov edi,[edi+0x10]; test edi,edi` → recorre una lista por `+0x10` |
| `0x0087691D` | `[0x125870C]+0x2238 → [eax+edi*4] → cmp [+0x188],0` |

Dos cosas que agrega esto:

- La función recorre **tres listas distintas por desplazamientos distintos** (`+0x18` y `+0x10`
  además del `+0x8` del bucle de selección), así que no es un único recorrido sino una cascada.
- **`world+0xACC` es la tabla de punteros a provincias**: el repositorio ya la tiene documentada en
  [PROVINCE-EVENT-SPAWN](contracts/PROVINCE-EVENT-SPAWN.md) como
  `[g_ProvinceManager + 0xACC]`, con `0x012588E8` = `g_ProvinceManager`. Es decir, las tres salidas
  que la consultan están mirando **provincias**, no países, y el campo `+0x188` del objeto
  obtenido es un campo de provincia (sin identificar por ahora).
- Del mismo modo, `[country+0x9D8]..[country+0x9DC]` es el **vector de provincias del país**, ya
  documentado en [COUNTRY-INFRASTRUCTURE-MODIFIER](contracts/COUNTRY-INFRASTRUCTURE-MODIFIER.md).
  Por tanto el índice que se usa para indexar `world+0xACC` en `0x0081E280` es un **id de
  provincia**, y la elección aleatoria de esa rutina elige **una provincia del país**.
- `0x125870C` **se inicializa en el subsistema de mapa**: su única escritura "de carga" está en
  `FUN_004963b0` (`0x004965E2`, `mov [0x125870C], ebx`), que maneja el literal
  `province_flag_sprites` junto a `map.cpp` y `/cache/map.bin`. Hay una segunda escritura en
  `FUN_00495bb0` (`0x00495C10`), cuya única cadena propia es `UNNAMED_SESSION`.
  Su tabla `+0x2238` se indexa con el mismo id de provincia y el objeto expone también `+0x188`,
  así que es otra tabla de provincias (hipótesis; falta identificar el tipo exacto).

### `g_ProvinceManager` confirmado por su constructor

`0x012588E8` se asigna con `push eax; call 0x67D9C0; mov [0x12588E8], eax` (`0x0067D996`) y se
pone a **NULL** al liberar (`xor eax,eax; mov [0x12588E8], eax` en `0x0067D9AE`). Es un singleton
con constructor propio, coherente con la lectura de `g_ProvinceManager` del repositorio.

`inferred`: el conjunto se comporta como una cadena de filtros (un AND de condiciones) donde
cualquier fallo sale sin resultado.

### El objeto destino: `esi` es un `CEventScope`

El destino que recibe `FUN_00876240` se construye antes con **`0x008A8650`** (215 bytes), y ese
constructor fija su identidad:

```
mov dword [esi + 4], 0x18D        ; 397
mov dword [esi],    0x00E2C904    ; vtable de CEventScope (confirmado por RTTI)
mov dword [esi + 8], 0x2D2D2D     ; el literal "---" (0x2D = '-')
mov dword [esi + 0xC], 0
mov dword [esi + 0x10], 0
mov word  [esi + 0x1C], cx        ; escribe los DOS bytes 0x1C y 0x1D de una vez
```

Es el **mismo descriptor `0x00E2C904` y el mismo valor `0x18D`** que escribe `0x008A88D0` desde
`AI_DecisionUpdate`. El inventario RTTI resuelve `0x00E2C904` como **`CEventScope`**
(locator `0x00E60C68`), así que el resultado de la selección aleatoria es un **ámbito de evento**.
El literal `Event_Election_Window` que está detrás de la tabla (`0x00E2C918`, apuntado desde
`0x004010C0`) es un campo del objeto, no su nombre de tipo: **corrección** sobre la lectura
anterior, que lo había tomado como la clase.

Sobre los dos bytes finales:

- `0x00876240` pone `byte [esi+0x1D] = 1` justo antes del epílogo (`0x008767EC`) y `byte
  [esi+0x1C] = 0` en el epílogo (`0x008767F0`).
- En todo `FUN_00876240` **no hay ninguna** `mov byte [reg+0x1C], 1` (verificado con un escaneo de
  `C6 /0` con `disp8=0x1C, imm8=1`: 30 sitios en el binario, ninguno dentro de la función).
- El constructor los escribe juntos con `mov word [esi+0x1C], cx`, y el valor de `cx` en ese punto
  no se puede determinar estáticamente (ecx cambia dentro de la función).

**Resuelto por estática** (no hizo falta traza dinámica). El constructor no recibe el valor de
`cx` de un argumento: lo fija él mismo cuatro instrucciones antes:

```
0x008A86D7  xor eax, eax
0x008A86D9  mov ecx, 1          ; <- cx = 0x0001
0x008A86DE  mov dword [ebp-0x14], 0x2D2D2D
0x008A86E8  mov dword [esi+0x30], eax
0x008A86EB  mov dword [esi+0x18], ebx      ; ebx = 0
0x008A86EE  mov word  [esi+0x1C], cx       ; +0x1C = 1, +0x1D = 0
```

Con eso, el contrato de los dos bytes queda:

| byte | valor inicial | qué lo cambia |
| --- | --- | --- |
| `+0x1C` | **1** (constructor) | las **11 salidas por filtro** (`0x008767F0`) y el epílogo de éxito lo ponen a 0 |
| `+0x1D` | 0 (constructor) | la ruta de éxito lo pone a **1** justo antes del epílogo (`0x008767EC`) |

Y el detalle que faltaba: la función tiene **21 `ret 4`**, no 11. Además del epílogo compartido hay
rutas de retorno tempranas (la ruta rápida `0x00876293..0x0087629B` y ~9 salidas por error) que
**no tocan ninguno de los dos bytes**, así que conservan el 1 inicial de `+0x1C`.

Lectura final: `+0x1C == 1` significa "la selección no descartó el objeto" (no pasó por ningún
filtro), y `+0x1D == 1` significa "se eligió una opción". El invocador `0x008B94B0` comprueba
`cmp byte [esp+0x2C], 0` — que cae en `+0x1C` — y abandona con `al=0` si es cero.

### Sus siete invocadores

Cada sitio cae en una función distinta, lo que encaja con "siete efectos que comparten la
selección aleatoria":

| sitio | función contenedora | tamaño |
| --- | --- | --- |
| `0x0087CB58` | `FUN_0087caf0` | 169 B |
| `0x0087CC02` | `FUN_0087cba0` | 483 B |
| `0x0087CED5` | `FUN_0087cd90` | 1133 B |
| `0x008B5F20` | `FUN_008b33e0` | 11402 B |
| `0x008B94D4` | `FUN_008b94b0` | 117 B |
| `0x008B957B` | `FUN_008b9530` | 3695 B |
| `0x008BA3C3` | `FUN_008ba3a0` | 76 B |

`FUN_008b94b0` (117 B, el que aparece en el perfil de muestreo) muestra el contrato de uso:

```
push 0; lea ecx,[esp+0x14]; call 0x8A8650     ; construye el contexto temporal
push [ebx+0x1C]
lea  esi,[esp+0x14]
call 0x00876240                                ; selección aleatoria → escribe en esi
if (byte [esp+0x2C] == 0) return false         ; no se eligió nada
n = ([ebx+0x0C] - [ebx+0x08]) >> 2             ; tamaño del vector del objeto
for (i = 0; i < n; i++) { elem = [ebx+0x08][i]; elem->vtable[6](&ctx); ... }
```

Es decir: primero **elige una opción** con RNG y después **evalúa** los elementos del vector con
ese contexto. `[ebx+0x1C]` viaja como segundo argumento de la selección.

- **Siete** sitios de llamada directa: `0x0087CB58`, `0x0087CC02`, `0x0087CED5`, `0x008B5F20`,
  `0x008B94D4`, `0x008B957B`, `0x008BA3C3`. `confirmed`. Los dos últimos caen en
  `FUN_008b94b0`, que es el caller que aparece en el perfil de muestreo.
- Prólogo: `mov ebx,[0x12587E4]; mov eax,[ebx+8]; sub eax,[ebx+4]; and eax,0xFFFFFFFC;
  cmp eax,4; jl 0x8767F4` — cuenta elementos de un vector de 4 bytes y toma un camino corto si
  hay menos de cuatro. Mismo global que en `FUN_0081e9e0`.
- Ruta rápida: si `[arg+0x10C] != 0`, `call 0x504750` y copia `[arg+0x108] → [esi+8]`,
  `[arg+0x10C] → [esi+0xC]`, `[esi+0x10] = 0`, `ret 4`.
- No hay evidencia todavía de que sea un switch de triggers: la hipótesis previa basada en las
  comparaciones `0x476/0x2F0/0x296` no está contrastada y queda como `hypothesis`.

## Por qué importa para el rendimiento

`AI_FrameUpdate` es el 30.5 % del tiempo de pared por día en el perfil de muestreo, y casi todo
pasa por `FUN_0081e9e0` por país. El bucle es secuencial sobre una lista enlazada (`+0x208`).

Consecuencias directas para cualquier intento de paralelizar:

1. La unidad natural es **un país**, no una provincia ni un POP: el bucle ya está agrupado así.
2. **No hay mutex en esta ruta**: el estado auxiliar vive en `[country+0x7B4]` y se reconstruye y
   libera en cada iteración. Eso quita un obstáculo, pero no demuestra que dos países no
   compartan escrituras: sigue sin auditar si un job escribe en otro país.
3. La lista es de punteros dispersos: repartirla entre hilos necesita primero materializarla en
   un array (lo que además arregla los misses del recorrido).
4. El acumulador `[country+0x8C]` se suma en cada pasada: si se paraleliza, debe quedar por país,
   nunca en una variable compartida.

## `0x00911760` — 1142 bytes, 333 instrucciones, 63 llamadas entrantes

Es un **método de condición** (`this` en `esi`, con vtable) al que `0x00820DF0` invoca como primer
filtro de cada nodo. Tiene 14 llamadas virtuales y 4 directas (`0x00416DB0`, `0x0047E4D0`,
`0x0051B810`, `0x00AAE91B`). Las lecturas verificadas:

```
cl = byte [world+0xD11]           ; 0x12588E8 → +0xD11
if (cl) { edi = [world+0xB24]; ... virtual [vtable+0x24] ... }
----------------------------------------------
virtual [esi->vtable + 0x70]
if (byte [0x125873E] == 0) {
    country = Countries->begin[[esi+0xC]];
    rel     = country->[0xBE8][[esi+0x14]];      // array de relaciones 683×683
    if ([world+0xB0C] > [rel+0x64])  goto salida; // fecha actual vs fecha de la relación
    if ([esi+0x24] != 0)             goto salida;
    if (byte [world+0xD11] == 0)     goto 0x911BC2;
}
if ([esi+0xC] == [esi+0x14])         goto 0x911BC2;
virtual [esi->vtable + 0x64]
if ((country = Countries->begin[[esi+0xC]])->[0x31] == 0) goto 0x911BC2;
virtual [esi->vtable + 0x64]                       // otra vez, con [esi+0x10]
```

Lo que queda establecido por bytes:

- Lee la **fecha del mundo** en `world+0xB0C` y la compara con una fecha guardada en el objeto de
  relación (`+0x64`). El mismo `+0xB0C` es el contador de días que se usó para medir el
  rendimiento, lo que confirma que es la fecha de simulación.
- Resuelve países por índice con el vector de `0x12587E4` y llega a la **matriz de relaciones**
  `country+0xBE8` (la misma que el proyecto ya tenía identificada como 683×683).
- Consulta tres banderas globales (`world+0xD11`, `0x125873E`) y un byte en la posición `+0x31`
  del país (muy al inicio de la estructura: `inferred`, bandera de civilizado/vivo/activo).
- Repite la virtual `[vtable+0x64]` (slot 25) en dos ramas distintas.

`hypothesis`: es un test de "relación conocida y vigente" (fecha de contacto, existencia del país
y visibilidad). No está confirmado y no debe citarse como contrato.

### `[country+0x7B4]`: head de lista, confirmado por el constructor

El constructor del país es `FUN_004f6a10` (6285 B) y en `0x004F6F84` hace:

```
0x004F6F60  lea esi, [ebx + 0x768]
0x004F6F6B  call 0x0044BC60              ; construye el subobjeto en ebx+0x768
0x004F6F70  mov dword [esi], 0x00DF9944  ; su vtable
0x004F6F76  mov dword [esi+0x44], 0xF
0x004F6F80  mov byte  [esi+0x30], 0
0x004F6F84  mov dword [ebx+0x7B4], edi   ; edi = 0  -> head = NULL
0x004F6F8A  mov dword [ebx+0x7B8], edi   ; tail = NULL
0x004F6F90  mov dword [ebx+0x7BC], edi   ; contador = 0
0x004F6F96  mov byte  [ebx+0x7C0], 0     ; byte de estado
```

Es decir `+0x7B4`/`+0x7B8`/`+0x7BC`/`+0x7C0` es la típica **lista con head, tail, contador y flag**,
y el `mov eax,[eax]` de `0x005DCAC0` está leyendo el head. Todo el recorrido del job encaja.

**Aviso de método**: existe otra función (`FUN_00860ed0`, `0x0086127C`) que escribe
`mov dword [esi+0x7B4], 0x00866B70` — la dirección de una función de 17 bytes
(`mov byte [ecx+0x749],1; mov dword [ecx+0x74C],0; ret`). Ese `esi` **no es el país**: es otro tipo
que usa el mismo desplazamiento. Es exactamente el límite que tiene el escaneo por offset, y por eso
la identificación se hizo por el constructor del país y no por la lista de escrituras.

## Campos que toca el job: conteo de accesos

Barrido con `scripts/field_refs.py` sobre todo el `.text` (datos en
`evidence/generated/ai-job/country-fields.csv`). **No distingue tipos**: el mismo desplazamiento
puede pertenecer a clases distintas, así que la tabla describe *cuánto se usa la posición*, no
*qué objeto la usa*.

| campo | tipo | total | lecturas | escrituras | `cmp` |
| --- | --- | --- | --- | --- | --- |
| `0x31` | byte | 256 | 24 | 19 | **213** |
| `0x67C` | byte | 70 | 15 | 3 | 52 |
| `0xBB8` | byte | 27 | 4 | **12** | 11 |
| `0xAF8` | byte | 6 | 4 | **0** | 2 |
| `0x12D0` | byte | 98 | 22 | 6 | 70 |
| `0xCE4` | dword | 27 | 18 | 9 | 0 |
| `0x7B4` | dword | 82 | **75** | 7 | 0 |
| `0x9D8` | dword | 128 | **126** | 2 | 0 |
| `0x9DC` | dword | 205 | **203** | 2 | 0 |

Lectura:

- `0x9D8`/`0x9DC` son casi sólo lecturas con dos escrituras cada uno: el par `begin`/`end` del
  vector que usan `0x00821510`, `0x0081E280` y `0x006874C0`.
- `0x7B4` tiene 75 lecturas y 7 escrituras: es el **head de una lista** del país. Su constructor lo
  confirma (ver más abajo): `+0x7B4` = head, `+0x7B8` = tail, `+0x7BC` = contador, `+0x7C0` =
  byte de estado.
- `0x31` y `0x12D0` se consultan con `cmp` (213 y 70 veces): son banderas de decisión.
- `0xBB8` es el único de los bytes con más escrituras (12) que lecturas (4): se asigna y se
  consulta, coherente con el gate `[country+0xBB8]==0` del job.
- `0xAF8` **no tiene ninguna escritura** con las formas cubiertas (`80/81/88/89/8A/8B/C6/C7/F6/F7`).
  Verificado por segunda vía: en `.text` aparecen 8 veces los bytes `f8 0a 00 00`; de esas, 6 son
  los accesos al campo, una es `mov dword [esp+0xAF8], eax` (slot de pila, `rm=4`) y otra son los
  bytes de un `rel32` de `call 0x6E0F90` (`0x006E0493`). Conclusión: no hay `mov` de byte a ese
  campo en el código; debe inicializarse en masa (`memset`/constructor). **No** es constante, pero
  tampoco se reasigna por instrucción aislada.

## Resuelto con hooks en ejecución (`v2probe`)

Plugin nuevo en `experiments/v2probe/` (`src/plugin.c` + `src/hooks.S`): cinco stubs
transparentes que registran y hacen `jmp` al original, sin tocar pila ni valor de retorno. En el
proceso, además, se resuelve el tipo de cualquier puntero con el RTTI de MSVC x86
(`vtable[-1] → CompleteObjectLocator`, `COL+0x0C → TypeDescriptor`, `+8 → nombre decorado`), que
funciona **en runtime** sobre los objetos vivos.

Medición sobre una partida real (España, enero–abril de 1836, velocidad alta):

| pregunta | respuesta medida |
| --- | --- |
| contenido de `[country+0x7B4]` | lista de **`CArmy`** (`.?AVCArmy@@` en el nodo y en su campo `+0xA0`) |
| `province+0x188` | puntero a **`CState`** (`.?AVCState@@`); mismo valor para las provincias del mismo estado, y `+0x18C = 0` |
| `country+0xE64` (el que compara `0x008E2A70`) | puntero a **`CCulture`** (`.?AVCCulture@@`) |
| `country+0xBCC` | **`CTechnologyStatus`** — coincide con lo que el repositorio ya documentaba como modificador tecnológico |
| `country+0xCE4` (lo que recorre `0x00820DF0`) | **nulo** en tiempo de paz: esa ruta no hace nada sin guerra/asedio |
| `country+0xA60` | no resuelve RTTI (puntero sin vtable válida) |

Detalles del nodo de la lista de ejércitos (`+0x7B4`), tal como salen del volcado:

```
lista7b4=43aa77e8 tail=43a9b508 cnt=26 flag=0
nodo0: elem=22e65730 (CArmy)  c38=00080004  c8c=0  c90=0  c94=0  c98=00080004
       cE8=0  cEC=0  cA0=22e658f0 (CArmy)
```

Los contadores `+0x38` y `+0x98` valen `0x00080004`, dos mitades de 16 bits (`4` y `8`) que no son
un puntero: no interpretarlos como dirección.

Contadores del job en esa corrida: `decision` superó las 10 000 llamadas y `throttle` se disparó
con `arg = 0x0000000F` al arrancar y luego con punteros.

## Qué queda abierto

Resueltas con `v2probe` en esta sesión: contenido de la lista `[country+0x7B4]` (**`CArmy`**),
`province+0x188` (**`CState`**), `country+0xE64` (**`CCulture`**), `country+0xBCC`
(**`CTechnologyStatus`**) y que `country+0xCE4` está nulo en paz.

Quedan cinco:

1. **Los dos bytes `+0x1C`/`+0x1D` del `CEventScope`**: el constructor deja `+0x1C = 1`, las 11
   salidas por filtro lo ponen a 0 y la ruta de éxito pone `+0x1D = 1`. Falta instrumentar el sitio
   `0x008B94D4` (`call 0x00876240`) para leer ambos bytes justo al volver; ese hook necesita un
   stub en ensamblador porque la llamada usa `eax`/`esi` como registros de contexto, no la pila.
2. **Rango real de `0x00820DF0` y `0x0081E280`**: Capstone no cierra el rango porque hay tablas de
   datos dentro de la extensión que declara Ghidra.
3. **Semántica de `0x00911760`**: prólogo y lecturas documentados; faltan las 14 ramas virtuales.
4. **Contenedor interno de `FUN_0055cdc0`** (`+0x14`, elemento de `0x10`, capacidad `0x40`) y quién
   llama al teardown `0x55C750`.
5. **Uso de `0x009B7910` frente a `0x00AB047B`**: se sabe que el segundo es `rand()` del CRT con
   estado por hilo; falta contar cuántas veces se usa cada uno por día (el plugin ya puede
   hookearlos).

`0x125870C` deja de estar abierta en lo esencial: el constructor de `CProvince` la usa como gestor
de definiciones (`[0x125870C]+0x2AA4`), así que su tabla `+0x2238` es de la misma familia.

## Control de consistencia de las direcciones citadas

Chequeo automático: se extraen todas las VA con formato `0x00XXXXXX` del documento y se comprueba
si caen dentro de alguna función de `evidence/generated/ghidra-corrected/functions.csv`.

Última ejecución: **129 VA citadas, 108 dentro de una función conocida, 21 fuera**, y las 21 están
explicadas una por una:

| grupo | VA | por qué queda fuera |
| --- | --- | --- |
| base | `0x00400000` | base preferida, no es código |
| límites superiores de rango | `0x0055CE4F`, `0x006875DA`, `0x0081E9D4`, `0x0081EAA4`, `0x00821505` | son `end_va` exclusivos |
| función no detectada por Ghidra | `0x0055C750`, `0x0055C7AF`, `0x0055C7B4`, `0x0055C7BC`, `0x0055C7C1`, `0x0055C7C7`, `0x0055C7CF` | el teardown del gestor de países, hueco entre `FUN_0055c6c0` y `FUN_0055c7e0` |
| función no detectada por Ghidra | `0x00866B70` | setter de 17 bytes en el hueco entre `FUN_00866a80` y `FUN_00866bc0` |
| literales / vtables / datos | `0x004010C0`, `0x00DF9944`, `0x00E2C904`, `0x00E2C918`, `0x00E38B28`, `0x00E455E8`, `0x00F20C18` | no son código |

No queda ninguna dirección sin explicación.

## Reproducir

```bash
cd research
python3 scripts/find_callers.py ../base-game/v2game.exe 0x0081e9e0   # 3 bucles sobre +0x208
python3 scripts/find_callers.py ../base-game/v2game.exe 0x00821190   # 1 llamador: 0x0081EA9B
python3 scripts/find_callers.py ../base-game/v2game.exe 0x00876240   # 7 sitios
tools/rizin/bin/rizin -q -e io.va=true -e scr.color=0 \
  -c "pd 55 @ 0x0081e9e0" ../base-game/v2game.exe
```

`find_callers.py` escanea `E8`/`E9 rel32` y punteros absolutos de 4 bytes; no analiza el binario
ni modifica nada.
