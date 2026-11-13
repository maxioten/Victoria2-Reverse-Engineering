# Contrato de `HighPerfWinClock` (`FUN_00A7B0F0` / `FUN_00A7B490`)

Perfil SHA-256: `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648` (`base-game/v2game.exe`). `[confirmed]`  
Base VA preferida `0x00400000` (`VA = RVA + 0x00400000`). `[confirmed]`

| VA | RVA | Tamaño (B) | Identidad | Estado | Evidencia / Ref |
| --- | --- | --- | --- | --- | --- |
| `0x00A38440..0x00A38494` | `0x638440..0x638494` | `85` | Factory / wrapper `new HighPerfWinClock` (`push 0x30`, `operator new`, `call 0x00A7B0F0`) | `[inferred]` | Único caller directo de `0x00A7B0F0` en `0x00A38472`; puntero en `.rdata:0x00E40754` |
| `0x00A7B0E0..0x00A7B0E8` | `0x67B0E0..0x67B0E8` | `9` | `HighPerfWinClock::IsRunning` (`[ecx+0x28] == 0`) | `[inferred]` | Vtable `.rdata:0x00E43A88[6]` (`0x00E43AA0`) |
| `0x00A7B0F0..0x00A7B48A` | `0x67B0F0..0x67B48A` | `923` | `HighPerfWinClock::HighPerfWinClock` (ctor) | `[inferred]` | Strings `"highprefwinclock.cpp"`, `"No clock found!"`, `"Clock rate is zero!"` en `.rdata:0x00E43A14..0x00E43A7F` |
| `0x00A7B490..0x00A7B4D5` | `0x67B490..0x67B4D5` | `70` | `HighPerfWinClock::~HighPerfWinClock` (`scalar deleting destructor`) | `[inferred]` | Vtable `.rdata:0x00E43A88[0]` (`0x00E43A88`) |
| `0x00A7B530` | `0x67B530` | — | `HighPerfWinClock::Start` (`[esi+0x28]=0`, `QPC(&[esi+8])`) | `[inferred]` | Vtable `.rdata:0x00E43A88[1]` (`0x00E43A8C`) |
| `0x00A7B790..0x00A7B79C` | `0x67B790..0x67B79C` | `13` | `HighPerfWinClock::Reset` (`[ecx+0x10]=0`, `[ecx+0x14]=0`, `[ecx+0x28]=1`) | `[inferred]` | Vtable `.rdata:0x00E43A88[2]` (`0x00E43A90`) |
| `0x00A7B7A0..0x00A7B7DC` | `0x67B7A0..0x67B7DC` | `61` | `HighPerfWinClock::Stop` (si `[esi+0x28]==0`, suma `QPC - start` a `[esi+0x10]` y marca `[esi+0x28]=1`) | `[inferred]` | Vtable `.rdata:0x00E43A88[3]` (`0x00E43A94`) |
| `0x00A7B7E0..0x00A7B7E6` | `0x67B7E0..0x67B7E6` | `7` | Tail-jump a `vtable[1]` (`0x00A7B530`, `Start`/`Restart`) | `[confirmed]` | Vtable `.rdata:0x00E43A88[4]` (`0x00E43A98`) |
| `0x00A7B7F0` | `0x67B7F0` | — | `HighPerfWinClock::GetElapsed` (`double`, usa `[esi+0x20]` si `[0x01258B6C]!=0`) | `[inferred]` | Vtable `.rdata:0x00E43A88[5]` (`0x00E43A9C`) |
| `0x00A7B850..0x00A7B891` | `0x67B850..0x67B891` | `66` | Limpieza `atexit` de la lista global de nodos de reloj | `[confirmed]` | Único destino de `jmp 0x00A7B850` en `0x00C88B90` |
| `0x00A7B8A0..0x00A7B908` | `0x67B8A0..0x67B908` | `105` | Helper de desenlace/borrado de nodo de lista global | `[confirmed]` | Único caller en `0x00A7B4B5` (dentro de `0x00A7B490`) |
| `0x00C88B90..0x00C88B94` | `0x888B90..0x888B94` | `5` | Thunk `jmp 0x00A7B850` registrado con `_atexit` (`0x00AAE904`) | `[confirmed]` | Registrado por `0x00C7DB60..0x00C7DB6B` |

---

## 1. Layout en memoria del objeto y globales `[confirmed]` / `[inferred]`

### Objeto `HighPerfWinClock` (`sizeof == 0x30` = 48 B en `0x00A38459 push 0x30`) `[confirmed]`

| Offset | Tipo / Tamaño | Campo observado | Lectores / Escritores verificados | Estado |
| --- | --- | --- | --- | --- |
| `+0x00` | `void**` (`4 B`) | Puntero vtable (`0x00E43A88` vivo; `0x00E388A8` base al finalizar dtor) | `0x00A7B119`, `0x00A7B496`, `0x00A7B4BE`, `0x00A7B7E0` | `[confirmed]` |
| `+0x08` | `int64` (`8 B`) | Marca QPC inicial (`start`) | `0x00A7B556` (`QPC(&[esi+8])`), `0x00A7B7C5..0x00A7B7CB` (`sub/sbb`) | `[confirmed]` |
| `+0x10` | `int64` (`8 B`) | Ticks acumulados | `0x00A7B13D..0x00A7B140` (`0`), `0x00A7B792..0x00A7B795` (`0`), `0x00A7B7CE..0x00A7B7D5` (`add/adc`) | `[confirmed]` |
| `+0x18` | `double` (`8 B`) | `1.0 / QueryPerformanceFrequency` | `0x00A7B427..0x00A7B430` (`fild; fld1; fdivrp; fstp qword ptr [esi+0x18]`) | `[confirmed]` |
| `+0x20` | `double` (`8 B`) | Valor congelado/cacheado devuelto cuando `byte [0x01258B6C] != 0` | `0x00A7B802` (`fld qword ptr [esi+0x20]`) | `[confirmed]` |
| `+0x28` | `uint8` (`1 B`) | Flag `paused/stopped` (`1` = detenido/inicial/reset, `0` = corriendo) | `0x00A7B143`, `0x00A7B55C`, `0x00A7B798`, `0x00A7B7A9`, `0x00A7B7D1`, `0x00A7B80A`, `0x00A7B0E2` | `[confirmed]` |

- **Vtable `.rdata:0x00E43A88`** (`[0x00E43A84] = 0x00000021`): slots `[0..6] = [0x00A7B490, 0x00A7B530, 0x00A7B790, 0x00A7B7A0, 0x00A7B7E0, 0x00A7B7F0, 0x00A7B0E0]`, terminada en `0x00000000` (`0x00E43AA4`). `[confirmed]`

### Nodo de lista global (`16 B`, asignado por `0x00A7B42A..0x00A7B439 push 0x10; call 0x00AAE9AF`) `[confirmed]`

| Offset | Tipo | Significado | Estado |
| --- | --- | --- | --- |
| `+0x00` | `HighPerfWinClock*` | Puntero `this` (`mov dword ptr [eax], esi` en `0x00A7B445`) | `[confirmed]` |
| `+0x04` | `ClockNode*` | `prev` (`mov dword ptr [eax+4], edi` en `0x00A7B447`) | `[confirmed]` |
| `+0x08` | `ClockNode*` | `next` (`mov dword ptr [eax+8], ebx` / `0` en `0x00A7B44A`) | `[confirmed]` |
| `+0x0C` | `uint8` | Flag tombstone diferido (`0` en `0x00A7B44D`; `1` en `0x00A7B8BB` solo si `[0x013F0764] != 0`) | `[confirmed]` |

### Globales `.bss` asociadas `[confirmed]`

Escaneo completo de `base-game/v2game.exe` buscando los 4 bytes little-endian de cada dirección:

- `0x01258B6C` (`uint8`): puesto a `0` en `0x00A7B11F`; consultado en `0x00A7B7F6` (`GetElapsed`). `[confirmed]`
- `0x01258B6D` (`uint8`): puesto a `(IsDebuggerPresent() != 0)` en `0x00A7B125..0x00A7B138`. `[confirmed]`
- `0x013F0758` (`ClockNode* head`): **6 únicas referencias en todo el binario**: `0x00A7B472` (ctor), `0x00A7B49D` (dtor), `0x00A7B851`, `0x00A7B875` (`atexit`), `0x00A7B8DB`, `0x00A7B8E2` (unlink). `[confirmed]`
- `0x013F075C` (`ClockNode* tail`): **5 únicas referencias**: `0x00A7B435`, `0x00A7B45E` (ctor), `0x00A7B87F` (`atexit`), `0x00A7B8E8`, `0x00A7B8F0` (unlink). `[confirmed]`
- `0x013F0760` (`uint32 count`): **4 únicas referencias**: `0x00A7B456`, `0x00A7B464` (ctor), `0x00A7B889` (`atexit`), `0x00A7B8FF` (unlink `dec`). `[confirmed]`
- `0x013F0764` (`uint8`): **1 única referencia en todo el binario**: `0x00A7B8B2` (`cmp byte ptr [0x013f0764], 0` en `0x00A7B8B0`). Nunca se escribe en ninguna parte de `base-game/v2game.exe`, por lo que permanece `0` en `.bss` durante toda la ejecución `[confirmed]`. Se trata de un guard muerto de eliminación diferida / reentrante (`node+0xC = 1`) cuyo lector/iterador externo fue eliminado en compilación o código muerto `[inferred]`.

---

## 2. Semántica exacta de las funciones verificadas

### A. Constructor `FUN_00A7B0F0` (`0x00A7B0F0..0x00A7B48A`, `923 B`) `[confirmed]`
- **ABI**: `__stdcall` (`[ebp+8] = this` -> `ESI`), devuelve `EAX = this`, `RET 4`, frame SEH `0x00B54052`. Único caller estático directo (`E8`): `0x00A38472` dentro de `FUN_00A38440` (`0` punteros/E9 en todo el binario). `[confirmed]`
- **Cuerpo principal (`0x00A7B0F0..0x00A7B432`)**:
  1. Inicializa `[esi] = 0x00E43A88`, `byte [0x01258B6C] = 0`, `byte [0x01258B6D] = (IsDebuggerPresent() != 0)`.
  2. Inicializa `[esi+0x10..0x17] = 0`, `[esi+0x28] = 1`.
  3. Llama a `QueryPerformanceFrequency` (`[0x00C8A254]`); si falla o `freq == 0`, construye excepción con `"No clock found!"` / `"Clock rate is zero!"` y llama a `_CxxThrowException` (`0x00AB111B`).
  4. Calcula `1.0 / (double)freq` y lo almacena en `qword [esi+0x18]` (`0x00A7B427..0x00A7B432`).
- **Bloque final de inserción en lista (`0x00A7B433..0x00A7B475`) + `0x00A7B42A`**:
  - MSVC intercaló `0x00A7B42A: 6a 10` (`push 0x10`, argumento para `operator new` en `0x00A7B439`) **antes** de `fld1; fdivrp st(1); fstp qword ptr [esi+0x18]` (`0x00A7B42C..0x00A7B432`). `[confirmed]`
  - Luego `0x00A7B433..0x00A7B475` lee `edi = [0x013F075C]`, llama a `0x00AAE9AF(0x10)` + `add esp, 4`, inicializa los 16 B del nodo (`this`, `edi`, `0`, `0`), incrementa `[0x013F0760]`, actualiza `[0x013F075C] = node` y enlaza `[edi+8] = node` o `[0x013F0758] = node`. `[confirmed]`
  - Ninguna línea entre `0x00A7B433` y `0x00A7B475` modifica campos de `HighPerfWinClock`, `0x01258B6C/D`, ni lanza excepciones de reloj (`0x00A7B476` pasa directo al epílogo devolviendo `EAX = esi`, `RET 4`). `[confirmed]`

### B. Destructor `FUN_00A7B490` (`0x00A7B490..0x00A7B4D5`, `70 B`) `[confirmed]`
- **ABI**: `__thiscall` (`ECX = this`), `[ebp+8] = flags`, devuelve `EAX = this`, `RET 4`. Única referencia estática: `.rdata:0x00E43A88` (`90 b4 a7 00`). `[confirmed]`
- **Flujo exacto**:
  1. `0x00A7B496`: `[esi] = 0x00E43A88`.
  2. `0x00A7B49C..0x00A7B4B5`: recorre `[0x013F0758]` (`cmp [eax], esi; mov eax, [eax+8]`) y pasa el nodo encontrado (o `NULL`) a `call 0x00A7B8A0` (`RET 4`).
  3. `0x00A7B4BA..0x00A7B4CC`: `test byte ptr [ebp+8], 1`, restaura `[esi] = 0x00E388A8` (vtable base cuyo slot 0 es `0x009A6D10`), y si `(flags & 1) != 0` llama a `operator delete(esi)` (`0x00AAE91B`).
  4. `0x00A7B4CF..0x00A7B4D5`: `mov eax, esi; pop esi; pop ebp; ret 4`.

### C. Helper de desenlace `FUN_00A7B8A0` (`0x00A7B8A0..0x00A7B908`, `105 B`) `[confirmed]`
- **ABI**: `__stdcall (ClockNode* node)`, `RET 4`, `AL` bool. Único caller en todo el binario: `0x00A7B4B5`. `[confirmed]`
- Si `node == NULL`: devuelve `AL = 0`. Si `byte [0x013F0764] != 0`: escribe `byte [node+0xC] = 1` y devuelve `AL = 1` sin liberar. En caso contrario (`[0x013F0764] == 0`): desenlaza `prev`/`next`, actualiza `head` (`0x013F0758`) y `tail` (`0x013F075C`) si coinciden con `node`, llama a `0x00AAE91B(node)`, decrementa `[0x013F0760]` y devuelve `AL = 1`. `[confirmed]`

### D. Limpieza `atexit` `FUN_00A7B850` (`0x00A7B850..0x00A7B891`, `66 B`) `[confirmed]`
- **Registro**: `0x00C7DB60` pasa `0x00C88B90` (`jmp 0x00A7B850`) a `_atexit` (`0x00AAE904`). `[confirmed]`
- **Flujo exacto**:
  - Lee `eax = [0x013F0758]`. Si `eax == 0`, salta (`0x00A7B857 je 0x00A7B873`) directo a poner `0x013F0758 = 0`, `0x013F075C = 0`, `0x013F0760 = 0` y ejecuta `ret`. `[confirmed]`
  - Si `eax != 0`, recorre `esi = [eax+8]` liberando cada nodo de `16 B` con `0x00AAE91B(eax)` y después pone los 3 dwords a `0`. **Nunca desreferencia `[eax+0]` (`node->clock`) ni destruye instancias `HighPerfWinClock`**. `[confirmed]`

---

## 3. Prueba de seguridad al elidir la lista global `[confirmed]`

1. **Elisión emparejada (ctor `0x00A7B0F0` + dtor `0x00A7B490`) -> 100% segura incluyendo `atexit`**:
   - Ninguna función fuera de `{0x00A7B0F0, 0x00A7B490, 0x00A7B8A0, 0x00A7B850}` lee ni escribe `[0x013F0758..0x013F0764]`. `[confirmed]`
   - Con inserción y desenlace neutralizados, `[0x013F0758]`, `[0x013F075C]` y `[0x013F0760]` permanecen `{0, 0, 0}` durante toda la partida (`0` asignaciones de `16 B` por reloj, `0` búsquedas `O(N)` al destruir). `[confirmed]`
   - Al salir el proceso (`atexit` -> `0x00C88B90` -> `0x00A7B850`), `test eax, eax` (`[0x013F0758] == 0`) toma `0x00A7B857 je 0x00A7B873`, escribe cero sobre los tres ceros y retorna sin liberar ni tocar ningún puntero. `[confirmed]`
2. **Por qué NO basta neutralizar solo el dtor `0x00A7B490` dejando vivo el append en `0x00A7B0F0`**:
   - Aunque `0x00A7B850` al cierre no desreferencia `[node+0]` (solo `[node+8]`) y liberaría los nodos al salir, cada creación de widget/reloj seguiría asignando `16 B` por nodo nunca desenlazado hasta el cierre del proceso (fuga progresiva durante sesiones largas). Por tanto, el contrato exige **elisión emparejada** de ctor+dtor `[confirmed]`.
   - Nota de invariante si existiera algún nodo residual por ruta no parcheada: `0x00A7B490` elidido que no llama a `0x00A7B8A0` ni deja nodos huérfanos nuevos evita el traversal, siempre que `0x00A7B0F0` tampoco inserte. `[confirmed]`

---

## 4. Puntos exactos de parcheo / hook y contrato ABI

### Destructor `0x00A7B490` (obligatorio preservar epílogo completo)

| Opción | Dirección / Tamaño | Bytes originales exactos | Contrato / Notas |
| --- | --- | --- | --- |
| A — Vtable slot `0` | `.rdata:0x00E43A88` (`4 B`) | `90 b4 a7 00` | Reemplazar puntero por stub `__thiscall` (`ECX = this`, `[esp+4] = flags`): poner `dword ptr [ecx] = 0x00E388A8`; si `(flags & 1) != 0` llamar `((void(__cdecl*)(void*))0x00AAE91B)(ecx)`; devolver `EAX = this`, `RET 4`. No requiere trampolín ni parchear `.text` si todos los callers usan vtable (única ref estática en `0x00E43A88`). |
| B — Entrada `0x00A7B490` | `.text:0x00A7B490..0x00A7B495` (`6 B`) | `55 8b ec 56 8b f1` | Límite limpio de `6 B` (`push ebp; mov ebp, esp; push esi; mov esi, ecx`) apto para `E9 rel32` (`5 B`) + `90` hacia stub con el mismo contrato de Opción A. |
| C — Salto medio inline | `.text:0x00A7B49C..0x00A7B4A0` (`5 B`) | `a1 58 07 3f 01` | Parche local `eb 1c 90 90 90` (`jmp short 0x00A7B4BA; nop; nop; nop`). Verificado: entre `0x00A7B49C` y `0x00A7B4BA` no hay desequilibrio neto de pila (`push ecx` + `call ret 4` se omiten juntos), `EAX` se sobreescribe en `0x00A7B4CF` y `0x00A7B4BA..0x00A7B4D5` conserva exactamente `test [ebp+8], 1`, `[esi] = 0x00E388A8`, `0x00AAE91B` y `EAX = esi; RET 4`. |

### Constructor `0x00A7B0F0` (obligatorio emparejar con el dtor)

| Opción | Dirección / Tamaño | Bytes originales exactos | Contrato / Notas |
| --- | --- | --- | --- |
| A — Entrada `0x00A7B0F0` o call site `0x00A38472` | `.text:0x00A7B0F0..0x00A7B0F4` (`5 B`) o `.text:0x00A38472..0x00A38476` (`5 B`) | `55 8b ec 6a ff` (`0x00A7B0F0`) / `e8 79 2c 04 00` (`0x00A38472`) | Hook `__stdcall (HighPerfWinClock* this)` devolviendo `EAX = this`, `RET 4`: debe ejecutar la inicialización `[0..0x28]`, `0x01258B6C/D`, `IsDebuggerPresent`, `QueryPerformanceFrequency` + excepciones, `[esi+0x18] = 1.0/freq`, y omitir la inserción en `0x013F0758..0x013F0760`. |
| B — Salto medio inline tras `fstp [esi+0x18]` | `.text:0x00A7B433..0x00A7B438` (`6 B`) | `8b 3d 5c 07 3f 01` | **Cuidado de pila**: `0x00A7B42A` ejecutó `6a 10` (`push 0x10`) antes de `fstp qword ptr [esi+0x18]`. Un `jmp short 0x00A7B476` sin limpiar ese dword corrompería `pop edi; pop esi; pop ebx` en `0x00A7B479..0x00A7B484`! Secuencia exacta segura de `6 B`: **`83 c4 04 eb 3e 90`** (`add esp, 4; jmp short 0x00A7B476; nop`: tras `eb 3e` en `0x00A7B436..0x00A7B437`, `0x00A7B438 + 0x3E = 0x00A7B476`), dejando `ESP` alineado para `pop edi / pop esi / pop ebx` y `EAX = esi; RET 4`. |

---

## Comandos de reproducción

```bash
sha256sum base-game/v2game.exe
source research/env.sh
python3 research/scripts/disasm_fn.py 0x00a7b0f0 --csv research/evidence/generated/ghidra-converged/functions.csv
python3 research/scripts/disasm_fn.py 0x00a7b490 --csv research/evidence/generated/ghidra-converged/functions.csv
python3 research/scripts/disasm_fn.py 0x00a7b850 --csv research/evidence/generated/ghidra-converged/functions.csv
python3 research/scripts/disasm_fn.py 0x00a7b8a0 --csv research/evidence/generated/ghidra-converged/functions.csv
python3 research/scripts/find_callers.py 0x00a7b0f0
python3 research/scripts/find_callers.py 0x00a7b490
```
