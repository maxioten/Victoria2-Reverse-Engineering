# P2 In-Process Hook Architecture & ENet Wait Static Audit

**Target binary**: `base-game/v2game.exe`  
**SHA-256**: `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648` (`confirmed`)  
**PE identity**: x86-32 (`Machine = 0x014C`), preferred `ImageBase = 0x00400000`, `SizeOfImage = 0x01092000`, `AddressOfEntryPoint = 0x006B0F91` (VA `0x00AB0F91`), `CheckSum = 0x00BC1E13` (`confirmed`).

**Evidence labels** (per `research/AGENTS.md`):
- `confirmed` — directly verified in binary bytes, disassembly, PE headers, logs, or source files read in this session.
- `inferred` — direct logical consequence of `confirmed` control flow or data structures without full end-to-end runtime trace.
- `hypothesis` — expected runtime behavior or unmeasured timing threshold requiring empirical measurement.

---

## 1. Existing In-Process Plugin & Hook Loading (Without x32dbg)

### 1.1 Dual Static-Import Startup Hooks in `v2game.exe`

- `confirmed`: `base-game/v2game.exe` statically imports both `DINPUT8.dll` and `lua51.dll` in its Import Address Table (`objdump -p base-game/v2game.exe | grep -iE "DLL Name|dinput8|lua51"`).
- `confirmed`: Replacing either DLL in the game directory causes Windows' PE loader to invoke its `DllMain(DLL_PROCESS_ATTACH)` synchronously **before** `v2game.exe` enters its original entry point (`0x00AB0F91`) and before any TBB or gameplay worker threads exist.

| Binary | SHA-256 | Role |
|---|---|---|
| `experiments/installed-patches/dinput8.dll` (identical to `base-game/dinput8.dll`) | `c6e25bdc119d01014064d18284ddb7116b6bcca8abfbd9159a31b3e39e8d746f` | **The Grand Loader (TGL) 1.0.0** — plugin host & `DirectInput8Create` forwarder (`confirmed`) |
| `experiments/installed-patches/performance_patch/performance_patch.dll` | `2681385e9314d204fb00f5244d9624162366d332b47474e834301afb3ddaf9da` | TGL plugin implementing `skip_network_wait`, `parallel_decisions`, `sample_profiler`, etc. (`confirmed`) |
| `experiments/installed-patches/lua51.dll` (identical to `base-game/lua51.dll`) | `1411b883e92f7ab3060a66b3a3d3365583428e8143962bba6478deeb23778a96` | **V2DLL 4.29** — `lua51.dll` proxy performing startup IAT/callsite patches from `v2dll_settings.ini` (`confirmed`) |

### 1.2 The Grand Loader (`dinput8.dll`) Load Sequence

- `confirmed`: `dinput8.dll` `DllMain` (`0x1000B2E0`) calls `0x100018C0` -> `0x1000F9F0` (`0x1000F010`), resolves `game_dir`, scans `<game_dir>\mod\*.ini` (`0x100120C0`), loads each matching `<game_dir>\mod\<name>\<name>.dll` via `LoadLibraryW`, resolves `__cdecl TGL_PluginInit(const Host *)`, and passes the 36-byte `Host` structure (`0x1000F66E..0x1000F699`, matching `experiments/v2opt/src/plugin.c:9-16`):

```c
typedef struct Host {
    uint32_t api_version;   // +0x00: 1
    uint32_t struct_size;   // +0x04: 0x24 (36)
    const char *plugin_name;// +0x08
    const wchar_t *game_dir;// +0x0c
    const wchar_t *config_file; // +0x10 (<game_dir>\mod\<name>.ini)
    const wchar_t *plugin_dir;  // +0x14 (<game_dir>\mod\<name>\)
    void *exe_base;         // +0x18 (GetModuleInformation lpBaseOfDll)
    size_t exe_size;        // +0x1c (SizeOfImage == 0x01092000)
    void (*log)(const struct Host *, const char *); // +0x20 (dinput8.dll+0xFEA0)
} Host;
```

- `confirmed`: `DirectInput8Create` (`0x10003ED1` -> `0x1000B440` -> `0x1000B330`) forwards cleanly to the real system `dinput8.dll`.
- `confirmed` (`base-game/the_grand_loader.log`): TGL loads plugins strictly in deterministic order at process attach and logs `TGL_PluginInit` return codes (`0` = success).
- `confirmed` (`experiments/installed-patches/performance_patch/performance_patch.dll` & `performance_patch.ini`): `TGL_PluginInit` (`0x10004273` -> `0x10014C30`) reads `performance_patch.ini` (`skip_network_wait`, `parallel_decisions`, `tick_profiler`, `sample_profiler`, `pin_fpu`, `fpu_precision`) and applies call-site `0xe8` patches via `0x1001DDA0` -> `0x1001DE70`. Note from `experiments/v2opt/PROFILING.md`: `tick_profiler=1` crashes (`lua51.dll+13C3E`) during `Adapting History` due to proxy return-thunk stack mismatch; `sample_profiler=1` avoids instrumentation thunks.
- `confirmed` (`lua51.dll`, `v2dll_settings.ini`, `base-game/logs/v2dll.log`): `V2DLL 4.29` initializes in `lua51.dll` `DllMain` (`0x100189C0`), hooks `WS2_32.dll!select` (ordinal `0x12`) via IAT patching (`0x10008F90` -> `0x1000D370`), hooks `CreateThread`/`_beginthreadex` for FPU pinning (`PATCH_THREAD_FPU_PIN`), and patches `Sleep(100)` -> `Sleep(1)` at RVAs `0x5DF2D5` and `0x5DF684`.

### 1.3 Audit of Existing Hook Prototypes (`v2opt` and `tick-country-hook-lab`)

1. **`experiments/v2opt/src/` (`entry.S`, `plugin.c`, `rows.h`)** (`confirmed`):
   - **Strengths to retain**:
     - PE identity verification (`plugin.c:127-131`): verifies `IMAGE_FILE_MACHINE_I386`, `SizeOfImage == 0x01092000`, `AddressOfEntryPoint == 0x006B0F91`, `CheckSum == 0x00BC1E13` before touching any code byte.
     - Targeted 5-byte `0xe8 rel32` call-site redirection (`redirect()` in `plugin.c:23-39`) with opcode byte check (`call_site[0] == 0xe8`), `VirtualProtect`, and `FlushInstructionCache`.
     - Full register & FPU/SSE preservation in `entry.S` (`pushal; pushfl; mov %esp,%ebx; subl $528,%esp; andl $-16,%esp; fxsave (%esp)` ... `fxrstor (%esp); popfl; popal`), restoring stack cleanly for `__thiscall` (`ret $4`) or jumping to original on fallback (`jmp *_v2_original_reset`).
     - `.ini` toggles via `GetPrivateProfileIntW(L"v2opt", ..., h->config_file)`.
   - **Critical gaps that P2 must fix**:
     - **Not TBB-safe**: `plugin.c:89` restricts execution with `if (GetCurrentThreadId() != owner_thread) return 0;` and mutates non-atomic shared globals (`calls`, `fast_calls`, `fallbacks`, `mismatches`, `reset_ticks`). Under `parallel_decisions=1`, worker threads either skip the optimization or data-race on counters. *(Note: `plugin.c:83` comments `"runs outside the loader lock"` — that applies to the runtime hook `v2_reset`, NOT `TGL_PluginInit`, which DOES execute inside `dinput8.dll`'s `DllMain` under the OS loader lock.)*
     - **Not a pure PIC/zero-import blob**: `v2opt.dll` links MinGW CRT/Win32 imports and `.reloc` (`-Wl,--dynamicbase`). While valid as a TGL host DLL, dynamically allocated hook trampolines/blobs cannot rely on relocation fixups or CRT state.
     - **Incomplete `shadow-compare` (`reset_mode=2`)**: `plugin.c:106` only calls `v2_original_reset(country)` and checks a structural invariant (`v2_equal_rows`), rather than executing both original and P2 implementations on identical inputs and comparing outputs + `FXSAVE` bit-for-bit.

2. **`experiments/tick-country-hook-lab/` (`hook.S`, `hook.c`, `build_hook.py`)** (`confirmed`):
   - Compiles freestanding `.text`-only PE (`-ffreestanding -fno-builtin -fno-stack-protector -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-ident -mno-sse -mno-mmx -msoft-float -nostdlib`), asserting **0 imports** and **0 base relocations** (`build_hook.py`), and extracts raw `hook.bin`.
   - Uses PC-relative addressing (`call .Lpc; .Lpc: popl %ebx; addl $(_hook_config-.Lpc), %ebx`) so the blob runs at any `VirtualAlloc` address without relocations.
   - Implements a true differential oracle (`hook.c`): snapshots `FX_BEFORE`, executes inline `hook_oracle` (stolen prologue bytes + `0xe8` rel32 fixups + tail jump), snapshots `FX_ORIGINAL`, restores inputs, executes `hook_compiled`, snapshots `FX_COMPILED`, and compares all 512 `FXSAVE` bytes plus GPRs/`EFLAGS`.

---

## 2. P2 Persistent In-Process Hook Architecture

### 2.1 Startup-Once Lifecycle & Loader-Lock Discipline

- **Single installation point**: All P2 hooks are installed **once** during `TGL_PluginInit(const Host *h)` inside `dinput8.dll`'s `DllMain(DLL_PROCESS_ATTACH)`, before `v2game.exe` reaches `0x00AB0F91` and before any TBB worker threads spawn (`confirmed`).
- **Zero runtime hot-patching**: Once `TGL_PluginInit` returns `0`, executable code pages and hook configuration records are **immutable** (`PAGE_EXECUTE_READ` for hook blobs, original `.text` permissions restored on patched call sites/vtables). No lazy patching on first call, no runtime toggling, no dynamic re-emission while worker threads are active.
- **Loader-lock constraints inside `TGL_PluginInit`**:
  - **Allowed**: PE fingerprint verification (`ImageBase` from `h->exe_base`, `SizeOfImage == 0x01092000`, `AddressOfEntryPoint == 0x006B0F91`, `CheckSum == 0x00BC1E13`); exact byte-signature verification at each patch target (`memcmp` of expected prologue/call bytes); `GetPrivateProfileIntW` / `GetPrivateProfileStringW` on `h->config_file`; `VirtualAlloc` (`PAGE_EXECUTE_READWRITE`) -> copy PIC blob + patch embedded `HookConfig` -> `VirtualProtect` (`PAGE_EXECUTE_READ`); `VirtualProtect` + patch target bytes + restore protection + `FlushInstructionCache(GetCurrentProcess(), target, len)`; `TlsAlloc()` (only if `shadow-compare` mode is enabled for at least one hook).
  - **Forbidden**: Spawning threads, `WaitFor*`, `LoadLibrary*` on complex DLLs, COM initialization, or CRT heap/stdio locks that risk loader-lock deadlock.

### 2.2 Zero Shared Mutable Global State (TBB-Safe Under `parallel_decisions=1`)

- **Hard rule (`prod` mode)**: Every P2 hook blob and production C replacement **must have zero shared mutable global or static state**.
  - Target addresses, original target pointers, `.ini` mode (`0`/`1`/`2`), and game read-only constants live in an immutable `HookConfig` block inside the blob's `.text` section, populated once before `VirtualProtect(..., PAGE_EXECUTE_READ)`.
  - All working storage lives strictly on the **thread's own stack** (16-byte aligned inside the wrapper frame) or in **caller-owned destination buffers**.
  - **Consequence**: Concurrent invocations across `ENGINE_WORKER_THREADS=6` TBB workers (e.g., AI/trigger evaluators such as `FUN_00876240` documented by `@triage-ai` in board `#7`) experience **zero data races, zero locks, and zero cross-core cache-line bouncing**.
- **Diagnostic counters / mismatch capture (`shadow-compare` mode only)**:
  - Never use shared `calls++` or shared scratch buffers. If per-thread mismatch recording or scratch memory is needed in `shadow-compare` (`mode = 2`), allocate a `DWORD tls_slot = TlsAlloc()` once in `TGL_PluginInit` and store `tls_slot` (plus an immutable callback pointer to a lock-free or thread-local logger if needed) inside `HookConfig`. Even simpler for `shadow-compare` on TBB-concurrent functions: run equivalence validation with `parallel_decisions = 0` in `performance_patch.ini` first so only the main thread executes the oracle, or store the 512-byte `FXSAVE` / shadow output buffers **strictly on the thread stack** (`subl $2048, %esp; andl $-16, %esp`). Stack-allocated shadow frames eliminate even `TlsAlloc` in the hot path.

### 2.3 Architectural State Preservation & PIC Blob Constraints

#### 2.3.1 Register, Flag, x87, and SSE (`FXSAVE`) Contract

Every P2 hook wrapper preserves the complete architectural state of x86-32:

```text
Caller stack at hook entry:
  [esp + 0x00] = caller return address
  [esp + 0x04] = arg0, arg1, ... (N bytes of callee-cleaned args, N=0 for cdecl)

PIC Assembly Entry (_p2_hook_entry):
  1. pushl $0                 ; reserves 4-byte tail/ret trampoline slot at [ebp + 0x24]
  2. pushal                   ; saves edi, esi, ebp, esp_pre, ebx, edx, ecx, eax (32 B)
  3. pushfl                   ; saves EFLAGS (4 B)
  4. cld                      ; guarantee DF=0 per x86 ABI before any C code
  5. movl %esp, %ebp          ; anchor pointer to SavedState:
                              ;   [ebp + 0x00] = EFLAGS
                              ;   [ebp + 0x04..0x20] = edi,esi,ebp,esp_pre,ebx,edx,ecx,eax
                              ;   [ebp + 0x24] = reserved trampoline slot (initially 0)
                              ;   [ebp + 0x28] = caller return address
                              ;   [ebp + 0x2C+] = stack arguments
  6. subl $528, %esp          ; 512 bytes FXSAVE + up to 15 bytes alignment slack
  7. andl $-16, %esp          ; mandatory 16-byte alignment for FXSAVE/FXRSTOR
  8. fxsave (%esp)            ; saves x87 FCW/FSW/FTW/FOP/FIP/FDP + st(0)..st(7), MXCSR, xmm0..xmm7
  9. call .Lpic_base
.Lpic_base:
     popl %ebx
     addl $(_hook_config - .Lpic_base), %ebx   ; EBX = &HookConfig (relocation-free)
 10. movl %esp, %eax          ; pass (SavedState *regs, void *fx_area, const HookConfig *cfg) (cdecl)
     pushl %ebx               ; cfg
     pushl %eax               ; fx_area (16-byte aligned 512 B FXSAVE buffer)
     pushl %ebp               ; regs (EFLAGS, GPRs, slot, retaddr, args)
     call _p2_dispatch
     addl $12, %esp
 11. testl %eax, %eax         ; 0 = fallback to original; 1 = handled (use ctx outputs)
     jz .Lfallback_to_original

.Lhandled:
 12. fxrstor (%esp)
 13. movl %ebp, %esp
 14. movl 0x28(%ebp), %eax    ; copy caller return address into reserved +0x24 slot
 15. movl %eax, 0x24(%ebp)    ; (movl does not alter EFLAGS; popal restores ctx->regs.eax)
 16. popfl
 17. popal                    ; esp now points to [ebp + 0x24] (caller return address)
 18. ret $(N + 4)             ; pops caller_retaddr from +0x24 and skips old +0x28 (4B) + N arg bytes
```

- **Handling Return Values & Custom LTCG `__usercall` ABIs**:
  - Standard `__thiscall` / `__cdecl` / `__stdcall` returning in `eax`/`al` (e.g., `bool` or `int`): `_p2_dispatch` writes the result into `ctx->regs.eax` (`[ebp + 0x20]`). On the `.Lhandled` path, `movl 0x28(%ebp), %eax; movl %eax, 0x24(%ebp)` happens *before* `popal` (so `popal` loads `ctx->regs.eax` into `EAX` and restores all other GPRs), `popfl` restores `EFLAGS`, `fxrstor` restores x87/SSE, and `ret $(N + 4)` pops the caller return address from `+0x24` while skipping the original return-address slot (`+0x28`, 4 B) plus `N` bytes of stack arguments (`ret $4` for `N=0` cdecl, `ret $8` for `N=4` 1-arg `__thiscall`/`__stdcall`).
  - **Custom LTCG `__usercall`** (specifically required for targets like `FUN_00876240` identified by `@triage-ai` in board `#7` and `research/docs/perf/FUN_00876240.md:16-18`: `eax = in_scope`, `esi = out_scope` unpreserved, `[esp+4] = target`, `void` return writing `out_scope` including status bytes `[esi+0x1C]`/`[esi+0x1D]`, `ret 4`): Because `P2Context` exposes **all 8 saved GPRs** (`edi..eax`) and `[ebp + 0x2C+]` stack args, the C handler reads `ctx->eax` (`in_scope`) and `ctx->esi` (`out_scope`), reads `ctx->args[0]` (`target`), writes `out_scope` in memory (including `[esi+0x1C]`/`[esi+0x1D]`), and leaves `ctx->eax` / `ctx->esi` updated as required by the ABI. Because `popal` loads every GPR from `ctx->regs` (except `esp`), arbitrary register-input / register-output ABIs work identically with `ret $(4 + 4)` (`ret $8`) on `.Lhandled`.
  - **x87 `st(0)` float/double returners**: `fxrstor` overwrites the entire x87 tag/register file (`st(0)..st(7)`). Therefore, if a hooked function returns a floating-point value in `st(0)` (like `0x009DF903`), the C replacement writes the result into `ctx->fxsave->st[0]` (80-bit extended / `fldl` before `fxsave` or manual 10-byte FPU slot update) OR the assembly epilogue runs `fxrstor` first and then `fldl`/`flds` from a scratch slot on stack before `movl %ebp,%esp; ...; popfl; popal; ret $(N + 4)`.
  - **FPU precision & rounding invariant**: Never alter `FCW` (`0x027F` / `0x007F`) or `MXCSR` inside a hook. Compiling hook blobs with `-mno-sse -mno-mmx -msoft-float` guarantees the compiler emits **zero** accidental x87/MMX/SSE instructions inside the trampoline/wrapper itself (`confirmed` from `experiments/tick-country-hook-lab/build_hook.py:51`).
  - **Clean fallback branch (`.Lfallback_to_original`)** (`inferred` from x86 stack semantics; interrupt-safe `ret`-slot tail-call pattern):
    ```asm
    .Lfallback_to_original:
        movl (%ebx), %eax         ; cfg->original_target (offset 0 of HookConfig)
        movl %eax, 0x24(%ebp)     ; write target EIP into reserved +0x24 slot
        fxrstor (%esp)
        movl %ebp, %esp
        popfl
        popal                     ; restores all 8 GPRs; esp = ebp + 0x24
        ret                       ; pops original_target into EIP; esp = ebp + 0x28 (caller retaddr + args untouched)
    ```
    Because `[ebp + 0x24]` is above `esp` (never below `esp` like a red-zone `[esp - 4]`), no OS APC/signal can clobber it, and `original_target` is entered with **all 8 GPRs, `EFLAGS`, x87, `MXCSR`/`XMM0..7`, and caller stack `[retaddr, args...]` 100% identical to hook entry**.

#### 2.3.2 Zero-Import, Zero-Relocation PIC Hook Blob Build Rules

Modeled on `experiments/tick-country-hook-lab/build_hook.py`:
- Compile each hook blob with:
  ```bash
  i686-w64-mingw32-gcc -m32 -O2 -ffreestanding -fno-builtin \
    -fno-stack-protector -fno-asynchronous-unwind-tables -fno-unwind-tables \
    -fno-ident -mno-sse -mno-mmx -msoft-float -nostdlib \
    -Wl,--image-base,0x10000000 -Wl,-e,_p2_hook_entry -o hook.exe hook.S hook.c
  ```
- **Automated build gate**: Extract `.text` bytes into `hook.bin` and assert:
  1. Only `.text` section is referenced (no `.data`, `.rdata`, `.bss`, `.idata`, `.reloc`).
  2. `IMAGE_DIRECTORY_ENTRY_IMPORT` is empty (`0` imports).
  3. `IMAGE_DIRECTORY_ENTRY_BASERELOC` is empty (`0` relocations).
- **Why this matters**: Any `hook.bin` passing those assertions can be `VirtualAlloc`'d at any 32-bit address in `v2game.exe`, patched with its `HookConfig` offsets at startup, and sealed `PAGE_EXECUTE_READ` with zero risk of rebase corruption or CRT/IAT dependency.

#### 2.3.3 Patch-Site Selection Rules

| Site Type | Mechanism | Pros | Cons / Guardrails |
|---|---|---|---|
| **Call-site `0xe8 rel32` redirect** (preferred when target has few direct callers) | Verify 5 bytes `e8 <expected_rel32>`, rewrite `rel32` to `hook_blob - (site + 5)` | Zero stolen prologue bytes; supports `HookConfig.original_target = site + 5 + expected_rel32` with zero relocation; per-callsite selectivity | Requires enumerating all direct call sites; misses indirect/vtable calls |
| **Vtable slot overwrite** (preferred for virtual methods with no direct non-vtable calls) | Verify 4-byte slot in `.rdata` equals `orig_fn`, overwrite slot with `hook_blob` | Zero code bytes modified; zero stolen instructions; trivial 4-byte atomic revert | Misses non-virtual direct calls (verify 0 `e8` callers statically first) |
| **Prologue 5-byte `0xe9 rel32` detour + relocated oracle** | Verify >=5 instruction-boundary prologue bytes, copy them into inline `hook_oracle` buffer, relocate any `0xe8`/`0xe9` relative offsets (`build_hook.py:62-75`), end with `jmp (fn + stolen_len)` | Catches all direct + indirect + vtable callers in one site | Must verify no branch target lands inside `[fn, fn + stolen_len)`; fails if function < 5 bytes or prologue contains jump-table / short backward branches |

### 2.4 Per-Function `.ini` Toggle (`off` / `shadow-compare` / `prod`) & Clean Fallback

Proposed `[hooks]` configuration format in `<game_dir>\mod\v2p2.ini`, parsed once in `TGL_PluginInit` via `GetPrivateProfileIntW` / `GetPrivateProfileStringW`:

```ini
[hooks]
; 0 / off    = do not patch (zero overhead, exact vanilla bytes)
; 1 / prod   = production P2 replacement (fast path + safe fallback on edge case)
; 2 / shadow = differential shadow-compare (runs original + P2, compares outputs/FXSAVE)
fn_00876240 = off
```

1. **`off` (`0`)**: Target bytes are verified (optional diagnostic log) and **not modified at all**. Zero runtime cost, zero trampoline allocated.
2. **`prod` (`1`)**: Executes P2 replacement. If P2 detects any unsupported state/edge case before mutating outputs, it returns `0` (`FALLBACK`), triggering `.Lfallback_to_original` (`fxrstor` + `popfl` + `popal` + tail-return to `original_target`), yielding identical behavior to unpatched execution.
3. **`shadow-compare` (`2`)**:
   - **Pre-condition check**: Functions that consume global `LCG`/`MT19937`/`rand()` (e.g., `FUN_00876240` ally/local_enemy branch, `FUN_0084b0f0` via `0x0084D1D0`) or mutate external global structures cannot be naively executed twice without restoring RNG/world state! Therefore:
     - **Pure / output-buffer-scoped functions**: Snapshot input structs & `FXSAVE_before` on stack -> run original -> snapshot `ret_orig`, `OUT_orig`, `FXSAVE_orig`, `GPR_orig`, `EFLAGS_orig` -> restore inputs & `FXSAVE_before` -> run P2 -> compare bit-for-bit (`ret`, `OUT`, callee-saved GPRs, `EFLAGS` status bits, 512-byte `FXSAVE`).
     - **RNG-using / mutating functions**: `shadow-compare` is ONLY enabled with `parallel_decisions=0` (single-threaded) AND must snapshot/restore the exact RNG state word(s) (or restrict `shadow-compare` to the non-RNG sub-paths / synthetic unit-test harness) so double execution never advances RNG twice!
   - **On mismatch**: Keep the **original** execution's outputs (`OUT_orig`, `FXSAVE_orig`, `ret_orig`), increment a thread-local or atomic diagnostic counter (or log mismatch address once via a rate-limited diagnostic hook), and return the original result cleanly so simulation state cannot diverge.

### 2.5 Empty-Hook Microbenchmark Protocol & P1 -> P3 Promotion Threshold

Before implementing any P3 replacement for a P1 candidate, measure the exact bare-hook overhead `C_hook` (`ns/call`) using the following protocol:

1. **Microbenchmark Harness (`experiments/v2opt/bench/` or standalone Win32 x86-32 binary)**:
   - Pin single thread to one core (`SetThreadAffinityMask(GetCurrentThread(), 1)`), elevate process priority (`HIGH_PRIORITY_CLASS`), and calibrate `RDTSCP` ticks against `QueryPerformanceCounter` over >= 100 ms.
   - Use **5 test configurations**, each executing `W = 1,000,000` warmup iterations followed by `M = 20` timed batches of `N = 10,000,000` calls, recording **median** and **p95** `cycles/call` and `ns/call`:
     - **(A) `baseline_direct`**: Direct `call` to a minimal `ret 4` target (matching `__thiscall`/`__usercall` `ret 4`). Prevent inlining/dead-code elimination via opaque volatile accumulator + `noinline`.
     - **(B) `pic_nop_trampoline`**: `0xe8` call-site patch -> `_p2_hook_entry` (`push $0; pushal; pushfl; cld; sub $528; and $-16; fxsave`) -> immediate `.Lfallback_to_original` (`fxrstor; popfl; popal; ret` to `orig`). Measures pure register/FPU save+restore + branch overhead (`C_fx`).
     - **(C) `pic_empty_c_handler`**: Full `_p2_hook_entry` -> `call _empty_c_handler(P2Context*, HookConfig*)` returning `0` (fallback) or `1` (noop return) -> full epilogue. Measures complete empty-hook round-trip (`C_hook`).
     - **(D) `vtable_empty_handler`**: Same as (C) dispatched via an indirect vtable call (`mov edx,[ecx]; call [edx+slot]`).
     - **(E) `tbb_contended_6thr`**: Spawn 6 worker threads (`ENGINE_WORKER_THREADS=6`) executing (C) concurrently for `10^7` calls/thread without shared globals. Confirms per-thread `ns/call` remains within `<= 1.10x` of single-thread (C).
2. **Hard Size / Frequency Threshold for P1 -> P3 Promotion**:
   - Let `C_hook` be the measured empty-hook cost from (C) in `ns/call` (`hypothesis`: ~15–40 ns/call due to `fxsave` + `fxrstor` + `pushal`/`popal`; exact bound must come from running the microbenchmark above).
   - Let `F` be the candidate's observed calls per game day (`calls/day`), `T_orig` its observed time per call (`ns/call`), and `T_p2` the projected replacement body time (`ns/call`).
   - A P1 candidate is **eligible for P3 promotion** only if it passes **all three gates**:
     1. **Amortization Gate**: `C_hook <= 0.10 * T_orig` (empty-hook overhead must be `<= 10%` of the original function's per-call time). *Example*: At `C_hook = 25 ns/call` (`hypothesis`), any leaf function with `T_orig < 250 ns/call` is **rejected** for direct hooking (consistent with `@triage-ai`'s `descartar` verdict in board `#7` for 48 B `FUN_008e2a70` and 67 B `FUN_008b8260` unless optimized upstream).
     2. **Net Savings Gate**: `(T_orig - (T_p2 + C_hook)) * F >= 0.25 ms/day` (at least `250,000 ns/day` saved end-to-end after paying `C_hook` on every call). Equivalently, for a hot loop saving `50%` of `T_orig`, `F * T_orig >= 0.5 ms/day` and `T_orig >= 10 * C_hook`.
     3. **Structural & Concurrency Gate**: Target supports clean 5-byte `0xe8` call-site, 4-byte vtable slot, or safe >=5-byte prologue detour (no mid-prologue jump targets), and if reachable under `parallel_decisions=1`, passes (E) `tbb_contended_6thr` scaling (`<= 10%` contention overhead) with zero shared mutable globals.

---

## 3. ENet Wait Static Audit (`NetSession_Service` -> `enet_host_service` -> `enet_socket_wait`)

### 3.1 Session Class Hierarchy & Single-Player Reachability

`confirmed` via `base-game/v2game.exe` disassembly (`pefile` + `capstone`, base `0x00400000`):

- `0x00A5FF00` (`NetSession` base constructor) initializes `[edi + 0x20] = 0x0F` (**15 ms** service timeout) at `0x00A5FFCB`.
- Session factories `0x009AE5F0` (check at `0x009AE856`) and `0x009AEB90` (check at `0x009AEDD4`) select one of four `CSession` subclasses depending on session mode:

| Mode | Subclass Ctor | Vtable | Service (`+0x1C`) | Calls `enet_host_service`? | Role |
|---|---|---|---|---|---|
| `mode == 2` | `0x00A682C0` | `0x00E42840` | `0x00A68450` | **No** (`confirmed`) | **Local / Single-Player / `InitialSession`** (callers at `0x00656725`, `0x00697BF9` pass `push 2` with `.rdata` strings `"NoAdress"` at `0x00E07678` and `"InitialSession"` at `0x00E07684`) |
| `mode == 1` | `0x00A60A10` / `0x00A60BD0` | `0x00E42728` | `0x00A61780` (**`NetSession_Service`**) | **Yes** (`0x00A618CC`) | **MP Client** (`confirmed`) |
| `mode == 0` | `0x00A635C0` / `0x00A63830` | `0x00E427C8` | `0x00A66D80` | **Yes** (`0x00A66EB3`) | **MP Host** (`confirmed`) |
| `mode == 3` | `0x00A68990` | `0x00E428B8` | `0x00A68C10` | **Yes** (`0x00A68C4B`, `0x00A69857`) | **LAN / Discovery** (port `0x2710` = `10000`) (`confirmed`) |

- `confirmed`: `CSession::Service(bool)` is invoked virtually via `[vtable + 0x1C]` (`0x009AFAE9`, `0x009AFB05`, `0x009AFBAC`).
- `confirmed`: In `mode == 2` (`0x00A68450`), the local session checks `[esi+0x80]` pointers (`0x00A68460..0x00A68482`), pops queued local commands via `0x00A6AB10` into `[esi+0x54]` in FIFO order (`0x00A6848C..0x00A68544`), increments `[[esi+0x1c]+0x54]` (`0x00A68549 mov esi, [esi+0x1c]; 0x00A6854C inc dword ptr [esi+0x54]`), and returns (`ret 4` at `0x00A68555`) **without calling ENet or Winsock**.

### 3.2 Exact Control Flow: `NetSession_Service` -> `enet_host_service` -> `enet_socket_wait`

1. **`NetSession_Service` (`0x00A61780..0x00A62E3C`, `ret 4`)** (`confirmed`):
   - `0x00A617A8..0x00A618B8`: Iterates `[ebx+0x9c]` (`0x00A6A1F0`, `0x00A6A210`, `0x00A6AD70`), serializing each queued outgoing command and appending it in strict FIFO order to `[ebx+0x54]`. Calls vfunc `+0x70` (`0x00A46A60` empty `ret 4` in base).
   - `0x00A618C0..0x00A618FE`: Loops `while (enet_host_service([ebx+0x18], &event, [ebx+0x20]) > 0)` via `0x00A618CC: call 0x00A89D00` (`e8 2f 84 02 00`), dispatching `event.type` `0..3` through jump table `0x00A62E40` (`case 0 -> 0x00A618C0`, `case 1 -> 0x00A618F1`, `case 2 -> 0x00A629C7`, `case 3 -> 0x00A61900`).
   - `0x00A62D6D..0x00A62DF5`: After `enet_host_service` returns `0` (`jle 0x00A62C80` -> `jne 0x00A62D6D`), calls `WINMM.dll!timeGetTime` (`0x00C8A328`), updates `[0x12586d0]`, flushes outgoing ENet packets (`0x00A899F0(host, 0)`), and if `[ebp+8] == 0` and `[ebx+0x98] == [ebx+0x94]`, sends a tick packet via vfunc `+0x14` and increments `[eax+0x54]` and `[ebx+0x98]`.

2. **`enet_host_service` (`0x00A89D00..0x00A89EA5`, `cdecl`)** (`confirmed`):
   - `0x00A89D20`: Calls `enet_host_dispatch_events` (`0x00A88400`); if a queued event is ready (`eax == 1`), returns `1` immediately.
   - `0x00A89D55..0x00A89DF2`: Computes `timeCurrent = timeGetTime() - [0x1258b70]`, sets `timeout_deadline = timeCurrent + timeout` (`[ebp+0x10]`), runs:
     - `0x00A8AE30` (bandwidth throttle via `timeGetTime`),
     - `0x00A899F0(host, 1)` (send outgoing commands),
     - `0x00A89250(event)` (receive incoming UDP commands via non-blocking Winsock),
     - `0x00A899F0(host, 1)` (send outgoing commands),
     - `0x00A88400(host, event)` (dispatch any newly assembled events).
   - `0x00A89E07..0x00A89E22`: Computes `remaining = deadline - timeCurrent`; if `timeout == 0` or deadline has elapsed (`cmp edx, 0x5265c00; jb 0x00A89E6F`), returns `0` **without calling `enet_socket_wait`**.
   - `0x00A89E43`: Otherwise calls `enet_socket_wait` (`0x00A8B400`).

3. **`enet_socket_wait` (`0x00A8B400..0x00A8B4BD`, custom register ABI: `edi=socket`, `ecx=remaining_ms`, `esi=&cond`)** (`confirmed`):
   - Converts `ecx` ms into `struct timeval { tv_sec, tv_usec }` and calls `WS2_32.dll!select` (`0x00C8A330`) at `0x00A8B477` (`ff 15 30 a3 c8 00`, return address `0x00A8B47D`, RVA `0x68B47D`).

### 3.3 How `performance_patch.dll` and `lua51.dll` Modify This Path

- **`performance_patch.dll` (`skip_network_wait`, `0x10037920..0x100379CE`)** (`confirmed`):
  - When `skip_network_wait != 0` in `performance_patch.ini`, patches **only** the single 5-byte `0xe8` call at `exe_base + 0x6618CC` (`0x00A618CC` inside `NetSession_Service`).
  - Thunk `0x100379A0` logs the first call's `[esp+0x0c]` (`"%u ms wait"`), overwrites `dword ptr [esp+0x0c] = 0`, and tail-jumps to original `enet_host_service` (`0x00A89D00`).
  - **Untouched sites**: Does **not** patch MP Host (`0x00A66EB3`) or LAN Browser (`0x00A68C4B`).
- **`lua51.dll` (`V2DLL 4.29`, `PATCH_MP_CLIENT_SLEEP`, `0x10008F90` -> `0x1000D370`)** (`confirmed`):
  - Hooks `WS2_32.dll!select` (ordinal `0x12`) in the IAT. If the caller's return RVA lies in `[0x689C00..0x68BFFF]` (which matches `0x68B47D` inside `enet_socket_wait`) and `tv_sec > 0 || tv_usec > 2000`, clamps the copied `timeval` to `{0, 1000}` (**1 ms**) rather than 0 ms (`base-game/logs/v2dll.log:12`).

### 3.4 Verdict: Can Skipping/Reducing the 15 ms `select()` Timeout in Single-Player Alter Command Ordering or RNG State?

1. **Standard Single-Player (`mode == 2`, `0x00E42840` / `0x00A68450`)**:
   - **Command Ordering**: **No effect** (`confirmed`). Standard single-player / `InitialSession` executes `0x00A68450`, which drains `[esi+0x7c] -> [esi+0x54]` locally and **never calls `NetSession_Service`, `enet_host_service`, or `ws2_32!select`**. `skip_network_wait=1` is never reached on this path.
   - **Even if `NetSession_Service` (`0x00A61780`) runs in a solo/loopback session with no remote peers**: `confirmed` — `NetSession_Service` transfers all local commands `[ebx+0x9c] -> [ebx+0x54]` in FIFO order **before** calling `enet_host_service` (`0x00A617BA..0x00A618B8`). Setting `timeout = 0` still executes `enet_host_dispatch_events`, `send_outgoing`, non-blocking `receive_incoming`, `send_outgoing`, and `dispatch_events`, skipping only the idle kernel sleep in `enet_socket_wait` (`select()`). With zero remote packets arriving, command order and tick counters (`0x00A62DD3..0x00A62DF5`) remain **identical**.
2. **RNG State**:
   - **Zero effect** (`confirmed`). Static call-graph inspection across `NetSession_Service` (`0x00A61780..0x00A62E3C`), `enet_host_service` (`0x00A89D00..0x00A89EA5`), `enet_socket_wait` (`0x00A8B400..0x00A8B4BD`), and ENet helpers (`0x00A88400`, `0x00A89250`, `0x00A899F0`, `0x00A8AE30`) confirms **zero direct or indirect calls** to game `LCG` (`0x009B7910`), `MT19937` (`0x009B7610`), or CRT `rand()`/`srand()` (`0x00AB047B`/`0x00AB046B`).
3. **Multiplayer / Lobby Caveat (`mode == 0` / `mode == 1` / `mode == 3`)**:
   - `inferred`: In active multiplayer client sessions (`0x00A61780`), `skip_network_wait=1` (`0 ms`) avoids blocking up to 15 ms inside `enet_host_service` when no UDP packet is already buffered, shifting packets that arrive mid-interval to the next `Service()` poll and increasing main-loop polling frequency (depending on `PATCH_MAIN_LOOP_SLEEP0` / `MAIN_LOOP_SLEEP_MS`). By contrast, `V2DLL`'s `PATCH_MP_CLIENT_SLEEP=1` (`1 ms` clamp in `ws2_32!select`) caps wait stalls at 1 ms across all ENet callers (`0x00A618CC`, `0x00A66EB3`, `0x00A68C4B`) without zero-sleep busy-polling.

---

## 4. Verification Commands Used

```bash
sha256sum base-game/v2game.exe \
  experiments/installed-patches/dinput8.dll \
  experiments/installed-patches/lua51.dll \
  experiments/installed-patches/performance_patch/performance_patch.dll

objdump -p base-game/v2game.exe | grep -iE "DLL Name|dinput8|lua51"

# Disassembly & cross-reference verification (via research/env.sh + pefile + capstone):
# - NetSession ctor 0x00A5FF00, NetSession_Service 0x00A61780..0x00A62E3C
# - CSession factories 0x009AE5F0, 0x009AEB90 and vtables 0x00E4271C, 0x00E42728, 0x00E427C8, 0x00E42840, 0x00E428B8
# - enet_host_service 0x00A89D00..0x00A89EA5, enet_socket_wait 0x00A8B400..0x00A8B4BD
# - lua51.dll IAT select hook installer 0x10008F90 & handler 0x1000D370
# - performance_patch.dll skip_network_wait installer 0x10037920 & thunk 0x100379A0
```
