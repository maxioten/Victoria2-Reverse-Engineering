# P1 Triage: `CRT_alldiv` (`__alldiv` `0x00AC02A0` + callers calientes)

- **Target binary**: `base-game/v2game.exe` (SHA-256 `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`, ImageBase `0x00400000`, `VA = RVA + 0x00400000`) `[confirmed]`
- **Profile dataset**: `base-game/performance_patch_samples.tsv` (`1311` samples across `877` stacks, `100 ms` interval, `120` days, header reports `546.2 ms/day sampled`; `1311 * 100 / 120 = 1092.5 ms/day`) `[confirmed]`
- **Contrato base verificado**: `research/docs/contracts/INTEGER64.md` `[confirmed]`

---

## 1. Identidad, rango, callers y ABI

| Propiedad | Valor | Estado | Evidencia / Comando |
| --- | --- | --- | --- |
| Entry VA / RVA | `0x00AC02A0` / `0x6C02A0` | `[confirmed]` | `functions.csv`, `INTEGER64.md` |
| End VA / RVA (inclusivo) | `0x00AC0349` / `0x6C0349` (`c2 10 00` `ret 0x10` en `0x00AC0347..0x00AC0349`) | `[confirmed]` | Capstone `read_va(0x00AC02A0, 172)` |
| Tamaño | `170 B` inclusive (`functions.csv` `body_bytes = 170`) | `[confirmed]` | `0x00AC0349 - 0x00AC02A0 + 1 = 170` |
| Identidad | Rutina CRT MSVC de división entera de 64 bits con signo (`__alldiv`), truncamiento hacia cero | `[confirmed]` | `functions.csv`, `INTEGER64.md` |
| Calling convention | `__stdcall` CRT especial con limpieza de stack de 16 B (`ret 0x10`) | `[confirmed]` | `0x00AC0347 ret 0x10`, `INTEGER64.md` |
| Parámetros | `[esp+4..11]` (`DVND`: `int64_t` dividendo), `[esp+12..19]` (`DVSR`: `int64_t` divisor). Nota: muta los slots de argumentos en stack al negar operandos negativos | `[confirmed]` | `INTEGER64.md` |
| Valor de retorno | `EDX:EAX` = cociente `int64_t` (`DVND / DVSR`). Preserva `EBX, ESI, EDI, EBP`. `DVSR == 0` dispara `#DE` en `0x00AC02EB div ecx` | `[confirmed]` | `INTEGER64.md` |

### Callers estáticos y calientes (de `performance_patch_samples.tsv`)

- **Referencias estáticas** (`[confirmed]`): **`2084`** referencias en `.text` (`python3 research/scripts/find_callers.py 0x00ac02a0`).
- **Muestras totales en TSV** (`[confirmed]`): **`33 / 1311` muestras (`2.52%` own = `2.52%` incl; `13.75 ms/day` en escala TSV)** distribuidas a lo largo de **`24` return sites distintos en `19` funciones**:

| `ret_site` (TSV) | Muestras | Función (`functions.csv`) | Call site y patrón de divisor confirmado | Estado |
| --- | --- | --- | --- | --- |
| `0x00854815` | `5` | `FUN_00854620` | `0x00854810 call 0xac02a0`: divisor `int64` dinámico (`[ebp-0x20]:ecx`, producto `__allmul(..., 0x3e8)`) | `[confirmed]` |
| `0x005303C6` | `3` | `FUN_0052fcd0` | `0x005303C1 call 0xac02a0`: divisor constante `0x1f40000` (`32768000`); dividendo desplazado `0x1e` bits (`2x shld/shl 0xf`) | `[confirmed]` |
| `0x0044CB3D` | `3` | `FUN_0044cb00` | `0x0044CB38 call 0xac02a0`: bucle apretado (`cmp esi, ebx`), divisor constante `0x3e8` (`1000`), `imul [ebp+0xc]` | `[confirmed]` |
| `0x00485625` | `2` | `FUN_00485390` | `0x00485620 call 0xac02a0`: dividendo `[ebp-0x28]:ebx` (`shld/shl 0xf`), divisor global `.rdata` `[0x00F0ADE4:0x00F0ADE0] = 32768000 (0x1f40000)` | `[confirmed]` |
| `0x004855E4` | `1` | `FUN_00485390` | `0x004855DF call 0xac02a0`: divisor `[0x00F0ADE4:0x00F0ADE0] = 0x1f40000` (`shld/shl 0xf`) | `[confirmed]` |
| `0x00485643` | `1` | `FUN_00485390` | `0x0048563E call 0xac02a0`: dividendo `shld/shl 0xf`, divisor `int64` dinámico `[ebp-0x18]:[ebp-0x1c]` | `[confirmed]` |
| `0x0048548E` | `1` | `FUN_00485390` | `0x00485489 call 0xac02a0`: divisor global `.rdata` `[0x00F0AE0C:0x00F0AE08] = 491520 (0x78000)` | `[confirmed]` |
| `0x004EED1D` | `1` | `FUN_004ee990` | `0x004EED18 call 0xac02a0`: divisor constante `0x1f40000` (`shld/shl 0x1e`) | `[confirmed]` |
| `0x004EEC13` | `1` | `FUN_004ee990` | `0x004EEC0E call 0xac02a0`: divisor constante `0x1f40000` (`shld/shl 0x1e`) | `[confirmed]` |
| `0x004397D4` | `1` | `FUN_00439780` | `1` muestra (misma función que `0x004397AC`) | `[confirmed]` |
| `0x004397AC` | `1` | `FUN_00439780` | `1` muestra | `[confirmed]` |
| `0x00530FDE` | `1` | `FUN_00530e40` | `0x00530FD9 call 0xac02a0`: divisor constante `0x1f40000` (`2x shld/shl 0xf`) | `[confirmed]` |
| `0x0096BACB` | `1` | `FUN_0096ba50` | `0x0096BAC6 call 0xac02a0`: bucle acumulador (`shld/shl 0xf` dividendo y divisor) | `[confirmed]` |
| `0x004892DA` | `1` | `FUN_00488080` | `0x004892D5 call 0xac02a0`: `shld/shl 0xf` sobre dividendo | `[confirmed]` |
| `0x009810CF` | `1` | `FUN_009808e0` | `0x009810CD call eax` (llamada virtual `[edx+0x108]`): el método virtual salta por tail-call (`jmp __alldiv`) o tiene FPO/stack frame omitido antes de `0x00AC02ED` `[inferred]` | `[confirmed]` (sitio) / `[inferred]` (tail-call) |
| Otros 9 sitios (`1` c/u) | `9` | `0x004d1cd0`, `0x0082f430`, `0x00515490` (`0x0051630C`), `0x009019b0`, `0x0095eb00`, `0x00545be0`, `0x00534710`, `0x004ee300`, `0x0095a6a0` | `1` muestra cada uno | `[confirmed]` |

- **Total de `FUN_00485390`** sumando sus 4 sitios: **`5 / 33` muestras (`15.2%` de `__alldiv`)**.

---

## 2. Escrituras en memoria, side effects, x87/SSE, RNG y TBB

- **Escrituras en memoria**: únicamente locales sobre la pila propia y mutación temporal de los slots de argumentos `[esp+4..19]` cuando `DVND < 0` o `DVSR < 0`. Cero escrituras globales `[confirmed]`.
- **x87 / SSE**: `0` instrucciones x87 y `0` instrucciones SSE `[confirmed]`.
- **RNG**: `0` llamadas `[confirmed]`.
- **Seguridad TBB (`thread-safety`)**: **100% thread-safe / reentrante** (`pure` respecto a estado global; solo usa registros y pila) `[confirmed]`.

---

## 3. Instrucción dominante de stall y diagnóstico

- **Distribución de hojas en TSV (`33` muestras totales)** (`[confirmed]`):
  - `0x00AC02F5`: **`15 / 33` (`45.5%`)** — instrucción inmediatamente posterior a `0x00AC02F3: div ecx` (ruta rápida `hi32(DVSR) == 0`)
  - `0x00AC02ED`: **`9 / 33` (`27.3%`)** — instrucción inmediatamente posterior a `0x00AC02EB: div ecx` (ruta `hi32(DVSR) == 0`, caso `hi32(DVND) < DVSR` o alto cociente)
  - `0x00AC0315`: **`1 / 33` (`3.0%`)** — inmediatamente posterior a `0x00AC0313: div ecx` (ruta lenta `hi32(DVSR) != 0` con bucle de desplazamiento)
  - Resto (`0x00AC0344` [3], `0x00AC02A9` [2], `0x00AC02DD` [1], `0x00AC02C7` [1], `0x00AC02E1` [1]): **`8 / 33` (`24.2%`)** — manejo de signos y epílogo.
- **Diagnóstico (`[confirmed]`)**: **100% compute-bound (latencia de hardware `DIV r32`)**. **`25 / 33` (`75.8%`)** de las muestras caen en el siguiente IP exacto tras `div ecx` (`0x00AC02EB`, `0x00AC02F3`, `0x00AC0313`), porque en x86 `DIV r32` es no-segmentada de alta latencia (`~20–40` ciclos de ejecución) `[inferred]`.

---

## 4. Cota de Amdahl y análisis de overhead de hook

- **Cota superior de Amdahl**: **`2.52%`** del total (`33 / 1311` muestras; `13.75 ms/day` en escala TSV), pulverizado entre `>=19` funciones (`>=24` call sites) `[confirmed]`.
- **Análisis de overhead de hook**:
  - Un hook C estándar con trampolín + preservación completa de estado FPU/SSE (`FXSAVE`) destruiría el presupuesto: sería más lento que la propia rutina `__alldiv` (de solo `170 B`, ejecutando 1–2 `div ecx` cuando `hi32(DVSR)==0`) `[inferred]`.
  - Incluso un fast-path en ensamblador naked sin `FXSAVE` inyectado en `0x00AC02A0` (para hacer `idiv` de 32 bits cuando `hi32(DVND) == sign(lo32)` y `hi32(DVSR) == 0`) **falla en los callers más frecuentes del juego**:
    - En `0x005303C1`, `0x004EED18`, `0x004EEC0E`, `0x00530FD9` (`0x1f40000`) y `0x00485620`, `0x004855DF`, `0x00485489` (`shld/shl 0xf`), el dividendo se escala por `2^15` o `2^30` antes de llamar a `__alldiv`, por lo que `hi32(DVND)` es **no trivial** (`!= 0` y `!= -1`) `[confirmed]`! En el motor de punto fijo `Q16.15` / `Q30` de Victoria II, un fast-path de 32 bits no captura el caso común (`idiv ecx` 64/32 sigue teniendo riesgo de `#DE` por overflow si no se verifica `|hi32| < DVSR/2`) `[inferred]`.
  - Adicionalmente, los `2084` callers siguen pagando el costo de `call` + push de 16 B en stack.

---

## 5. Veredicto y prerrequisitos exactos

- **Veredicto**: **`descartar`** como objetivo de hook global en `0x00AC02A0`; aplicar **`micro-opt local`** (strength reduction de divisores constantes) **solo dentro de los callers calientes cuando esos callers sean recompilados**.
- **Por qué `micro-opt local` en los callers sí gana**:
  - En todos los callers con divisor constante en tiempo de compilación (`0x1f40000 = 32768000 = 125 * 2^18`, `0x78000 = 491520 = 15 * 2^15`, `0x3e8 = 1000 = 125 * 2^3`, `0x320000 = 3276800 = 25 * 2^17`), dividir un `int64_t` por una constante conocida se reduce en C/asm recompilado a un shift + multiplicación recíproca de 64 bits (`imul`/`mul` + corrección de signo hacia cero), eliminando **por completo** tanto el `call 0x00ac02a0` como la instrucción `div ecx` `[inferred]`.
  - Ejemplo concreto: en `0x005303C1` / `0x004EED18` (`(x << 30) / (125 << 18)`), algebraicamente equivale a `(x << 12) / 125` (con verificación de rango si `x` no excede `int32`), o `((int64_t)x << 30) / 32768000` compilado por GCC/Clang/MSVC moderno con recíproco `mul` de 0 divisiones hardware `[inferred]`.
- **Prerrequisitos exactos si se optimiza un caller**:
  1. Preservar exactamente la semántica de truncamiento hacia cero y saturación/overflow de `__alldiv` según `research/docs/contracts/INTEGER64.md` (ej., no usar `sar` sin corrección de signo para números negativos!).
  2. Verificar por test diferencial (Unicorn o test unitario PE32/ELF32) bit-a-bit contra `0x00AC02A0` sobre casos positivos, negativos y extremos antes de desplegar en cualquier caller recompilado.

---

## Comandos de reproducción

```bash
source research/env.sh
python3 research/scripts/disasm_fn.py 0x00ac02a0 --csv research/evidence/generated/ghidra-converged/functions.csv
python3 research/scripts/find_callers.py 0x00ac02a0 | head -n 40
```
