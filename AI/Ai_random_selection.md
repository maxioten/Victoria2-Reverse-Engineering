# Random selection over an effect list: `FUN_00876240`

How the engine picks one option out of a list with the CRT generator, and how the chosen result is
carried in a `CEventScope`.

Source: research of October 2026, static reading of `v2game.exe` 3.04 with Capstone, plus in-process
hooks (`tools/v2probe`) that resolve live object types through MSVC RTTI. Marks: **[C]** read in the
code, **[I]** inferred, **[M]** measured at runtime.

## Why this function matters

`0x00876240` is 1793 bytes, **551 instructions, 32 direct calls and 9 backward jumps** — of which
**8 are jumps to the shared epilogue at `0x008767F0`** and only **one is a real loop**
(`0x00876701`). Rizin's linear disassembly desynchronises inside this function and reports 26 calls
and 1 loop; the counts above come from Capstone.

It has seven direct callers, each in a different function:

| site | container |
| --- | --- |
| `0x0087CB58` | `FUN_0087caf0` |
| `0x0087CC02` | `FUN_0087cba0` |
| `0x0087CED5` | `FUN_0087cd90` |
| `0x008B5F20` | `FUN_008b33e0` |
| `0x008B94D4` | `FUN_008b94b0` |
| `0x008B957B` | `FUN_008b9530` |
| `0x008BA3C3` | `FUN_008ba3a0` |

## The selection loop **[C]**

`0x00876701..0x0087673C` collects pairs and `0x00876747..0x00876760` picks one:

```text
loop:
    eax = *ecx                       ; node
    if ([eax+0x74] == 0)          skip    ; filter 1
    if ([eax+0xC4] == [ebx+0x12C]) skip   ; filter 2
    *(u32*)dst       = [eax+0xC0]
    *(u32*)(dst+4)   = [eax+0xC4]
    dst += 8; count++                    ; [ebp+0x08]
    ecx = [ecx+8]                        ; next
    if (ecx) goto loop

    lea edx,[edi+0x40]
    call 0x009B7910                      ; two LCG steps
    cdq; idiv [ebp+0x08]                 ; index = rand % count
    eax = table
    ecx = [eax + index*8]
    edx = [eax + index*8 + 4]
    [esi+8] = ecx
    [esi+0xC] = edx                      ; result = the chosen pair
```

The destination is `esi`, and the caller sets it up with `0x008A8650` (215 bytes), which builds a
**`CEventScope`** (`[esi] = 0x00E2C904`, vtable confirmed by RTTI, locator `0x00E60C68`) with
`[esi+4] = 0x18D` and the literal `---` at `[esi+8]`.

The LCG state is **passed in the object**: `lea edx,[edi+0x40]; call 0x009B7910`. This is *not* the
CRT `rand()`; see below.

## The eleven filter exits **[C]**

All go to the shared epilogue `0x008767F0` (`mov byte [esi+0x1C],0` then `ret 4`):

| site | condition |
| --- | --- |
| `0x008763E6` | virtual `[vtable+0x20]` returns false |
| `0x00876464` | `[edi+0x18] == 0` |
| `0x008766F8` | empty list (`test ecx,ecx`) |
| `0x00876741` | option counter <= 0 |
| `0x0087680D` | `[edi+0x18]` null (walks another list through `+0x18`) |
| `0x00876826` | `[world+0xACC][idx] -> [+0x188]` null |
| `0x0087682F` | `[obj+0x288] == 0` |
| `0x00876878` | `[world+0xCF8] -> [+0x8]` null |
| `0x00876892` | `[world+0xACC][idx] -> [+0x188]` null (second branch) |
| `0x00876901` | `[edi+0x10]` null (third list) |
| `0x0087691D` | `[0x125870C]+0x2238 -> [eax+edi*4] -> [+0x188] == 0` |

`world+0xACC` is the province pointer array (`Symbols/structs.csv`: `World,0xACC,provinces`), so
three exits test `province+0x188`, which is `CState*` (`CMapProvince,0x188,state`).

## The two result bytes: `+0x1C` and `+0x1D` **[C][M]**

`0x008A8650` initialises both at once:

```text
0x008A86D7  xor eax,eax
0x008A86D9  mov ecx,1
0x008A86EE  mov word [esi+0x1C], cx     ; +0x1C = 1, +0x1D = 0
```

Then:

| byte | initial | change |
| --- | --- | --- |
| `+0x1C` | **1** | the 11 filter exits and the success epilogue set it to 0 |
| `+0x1D` | 0 | the success path sets it to **1** at `0x008767EC` |

The function has **21 `ret 4`**, not 11: besides the shared epilogue there are early returns (the
fast path `0x00876293..0x0087629B` and about nine error exits) that **do not touch either byte**, so
they keep the initial 1.

So `+0x1C == 1` means "the selection did not discard the object" and `+0x1D == 1` means "an option
was chosen". The caller `0x008B94B0` tests `cmp byte [esp+0x2C], 0` — which lands on `+0x1C` — and
returns false when it is zero.

## Two generators coexist

| function | state | shape |
| --- | --- | --- |
| `0x009B7910` | passed explicitly, `this+0x40` | two consecutive `imul 0x343FD / add 0x269EC3` steps |
| `0x00AB047B` | `__acrt_getptd()` + `ptd+0x14` | one step, returns `(seed>>16) & 0x7FFF` |

`0x00AB047B` is the CRT `rand()`: it starts with `call 0x00AB98AF`, which is MSVC `__acrt_getptd`
(`call 0x00AB9836`; on NULL, `push 0x10; call 0x00AB220B`), reads the seed from `ptd+0x14`, and
masks with `0x7FFF`. That makes it **thread-local**, which is the reason the daily AI loop cannot be
split across threads without changing the roll sequence. `0x00AB047B` has 38 references.

## Reproducing

```bash
# static
python3 tools/vic2_disasm.py 0x00876240        # or Capstone from the entry in functions.csv
# dynamic, in-process
# tools/v2probe hooks 0x0081EA9B and resolves live types through RTTI
```
