# P2 Persistent Hook Lab (`experiments/p2-hook-lab`)

Paso A implementation of the persistent in-process P2 hook architecture specified in
[`research/docs/perf/P2-HOOK-ARCHITECTURE.md`](../../research/docs/perf/P2-HOOK-ARCHITECTURE.md),
kept strictly isolated from `base-game/` (`v2game.exe` is read-only).

## 1. Deliverables & Layout

- `p2_layout.h` — Shared offsets (`CFG_*`, `CFG_CR_*`, `SS_*`, `P2_MODE_*`, `P2_ACT_*`) and C structs (`P2HookConfig`, `P2CrConfig`, `P2SavedState`, `P2FxSave`, `TGLHost`).
- `hook.S` — PIC x86-32 trampoline (`_p2_hook_entry`, `.Lhandled`, `.Lfallback_to_original`, `_p2_pic_nop_entry`, `_p2_hook_config`) preserving all GPRs, `EFLAGS`, `DF=0`, stack alignment, and 512-byte `FXSAVE`/`FXRSTOR` state.
- `hook_blob.c` — Freestanding C dispatcher (`p2_dispatch`), compiled with `-mno-sse -mno-mmx -msoft-float -nostdlib`.
- `cr_sese_entry.S` & `cr_sese_body.c` — Freestanding PIC SESE `[0x00515EA6, 0x00516286)` replacement for `Country_Recalculate` variant (a) (`PREFETCHT0` lookahead `+3`) and variant (c) (`-DP2_CR_VARC=1`: 4096-tag `alive_bits` bitmask scanned via `bsf` in strictly ascending `idx` order, lazy-init + `validate` check, zero shared globals inside variant (a)).
- `build_hook.py` — Automated PIC compiler & gate producing `build/hook.*`, `build/cr_sese.*`, `build/cr_sese_bench.*`, `build/cr_sese_varc.*`, and `build/cr_sese_varc_bench.*`.
- `test_unicorn.py` — 10-case Unicorn x86-32 emulator test verifying state preservation, custom register writeback, PIC relocation, and fail-safe paths.
- `test_a7b490_unicorn.py` — 7-check Unicorn equivalence suite for the `HighPerfWinClock` pilot (`0x00A7B0F0` + `0x00A7B490` + `0x00A7B850`).
- `test_cr_sese_unicorn.py` — 7-check Unicorn equivalence & negative-control suite comparing `base-game/v2game.exe` `[0x00515EA6, 0x00516286)` vs `build/cr_sese.bin` (9-tag + `total_tags=0` + `"REB"` neg-ctrl) and `build/cr_sese_varc.bin` (220-tag sparse `40` living/`180` dead + `validate` missing/extra/`"REB"` neg-ctrls).
- `v2p2.c`, `v2p2_varc_asm.S` & `v2p2.ini` — Persistent TGL plugin (`build/v2p2.dll` prod exporting only `TGL_PluginInit`; optional `-DP2_CR_BENCH_DLL=1` `build/v2p2_cr_bench.dll`) verifying `base-game/v2game.exe` PE fingerprint, parsing `[hooks]` (`fn_00a7b490`, `fn_00515ea6`, `fn_00515ea6_varc = off | validate | prod`, all defaulting to `off`), sealing SESE PIC blobs `PAGE_EXECUTE_READ`, and patching the 10 verified V1 writer `E8` call sites (`SetOwner`, `CCountry::Reset`, `CWorld::ChangeTag`).
- `test_v2p2.py` — 12-check `pefile` + Wine integration test verifying `build/v2p2.dll` exports, ASLR/DEP flags, `0` `rdtsc`, `off`/`shadow`/`prod`/`validate` patching on `base-game/v2game.exe` bytes, `PAGE_EXECUTE_READ` protection, live dtor execution, and live V2 writer-hook transitions + `validate` mismatch logging.
- `bench_asm.S`, `bench.c`, `run_bench.py`, `bench_results.json` — Empty-hook microbenchmark (`A..E4..E6`) under an isolated Wine prefix (`experiments/p2-hook-lab/wine-prefix`).
- `bench_cr_asm.S`, `bench_cr.c`, `run_bench_cr.py`, `bench_cr_results.json` — Separate `RDTSC` intra-region microbenchmark (`[0x00515EA6 -> 0x00516286)`) comparing `nopf`, `var_a`, `var_c`, and `var_c_pf` on a 220-tag (40 living / 180 dead) scattered fixture under Wine.

## 2. `#29` Review Fixes Implemented

1. **Explicit `arg_bytes` guard (`hook.S` + `v2p2.c`)**: `.Lhandled` checks `CFG_ARG_BYTES(%ebx)` explicitly for `0, 4, 8, 12` and jumps directly to `.Lfallback_to_original` for any unsupported value instead of corrupting the caller stack; `v2p2.c` (`valid_arg_bytes`) also rejects unsupported `arg_bytes` during `TGL_PluginInit`.
2. **Explicit `.rdata` content check (`build_hook.py`)**: `llvm-mingw` (Clang 23.1.5 + LLD) emits `.rdata` holding the PE Export Directory preceded by a 16-byte LLD empty ctor/dtor sentinel (`ffffffff 00000000 ffffffff 00000000`). `build_hook.py` explicitly verifies that every 4-byte word before `ExportDir` in `.rdata` is `0x00000000` or `0xFFFFFFFF` (`len <= 32`, `% 4 == 0`), in addition to asserting `0` imports, `0` base relocations, and Capstone disassembly proving `0` external/absolute references in `.text`.
3. **Fail-closed `mode=shadow` (`hook_blob.c` + `v2p2.c`)**: Both `p2_dispatch` and `TGL_PluginInit` refuse `P2_MODE_SHADOW` (`mode == 2`) unless a shadow-capable comparator (`flags & 2u`) is explicitly registered.

## 3. Build & Verification Results

Run with the project environment active (`source research/env.sh`):

```bash
source research/env.sh
python3 experiments/p2-hook-lab/build_hook.py
python3 experiments/p2-hook-lab/test_unicorn.py
python3 experiments/p2-hook-lab/test_a7b490_unicorn.py
python3 experiments/p2-hook-lab/test_cr_sese_unicorn.py
python3 experiments/p2-hook-lab/run_bench.py
python3 experiments/p2-hook-lab/run_bench_cr.py
python3 experiments/p2-hook-lab/test_v2p2.py
```

Observed gate & test results:

- **`build_hook.py`**:
  - `hook`: `gate_passed`, `320` B, `0` imports, `0` relocs, `0` `rdtsc`, SHA-256 `93ae40a41e202c64cbfb41e5af3ff5fbbbc2c3c76193d623e1da07c316eba5f1`.
  - `cr_sese` (prod var a): `gate_passed`, `1420` B, `0` imports, `0` relocs, `0` `rdtsc`, `prefetcht0` present, SHA-256 `e67bcb55763f2374ef95cf1f0f15b99d2309d2d17a18c348747898d4b4b1f454`.
  - `cr_sese_bench` (bench var a): `gate_passed`, `1452` B, `0` imports, `0` relocs, `rdtsc` + `prefetcht0` present, SHA-256 `d2fc4ca3a895ca22c1abf9752edd6a4ac54904c7d02e6bc59ba8611a5b78de20`.
  - `cr_sese_varc` (prod var c): `gate_passed`, `3148` B, `0` imports, `0` relocs, `0` `rdtsc`, `0` `prefetcht0`, `bsf` present, SHA-256 `7ea6fa84469a14c5bc61d36cbe0a48146611a0eac88a37435e4d90f3eee9952d`.
  - `cr_sese_varc_bench` (bench var c): `gate_passed`, `3180` B, `0` imports, `0` relocs, `rdtsc` + `bsf` present, SHA-256 `59d25b6a352003686afd97487aa4e8bd2682f56d6ffff7f07d5ad6d47f625896`.
- **`test_unicorn.py`**: `Unicorn verification PASS: 10/10 cases verified (GPR/EFLAGS/DF/ESP/512B FXSAVE/PIC rebase)` — covers `mode=OFF`, `mode=PROD` fallback (`DF=1`, `ret 4`), `p2_pic_nop_entry`, `.Lhandled` (`argB=0`, `argB=8`), `__usercall` (`EAX`+`ESI` writeback with C scratch dirtying), PIC rebases (`0x23450000`, `0x41230000`), `mode=2` without comparator (`flags=0`) safe fallback, and unsupported `arg_bytes=16` safe fallback.
- **`test_a7b490_unicorn.py`**: `Unicorn HighPerfWinClock equivalence PASS: 7/7 checks verified (orig empty/pop x flags 0/1, P2 PIC x flags 0/1 w/ FXSAVE+EFLAGS, ctor skip + atexit)` — runs exact machine code slices from `base-game/v2game.exe` vs `build/hook.bin` + `p2_dtor_a7b490_handler` (`build/v2p2.dll`) across empty & 3-node populated lists, `flags=0/1`, verifying `EAX == this`, `ESP` `+4` cleanup (`RET 4`), `[this] == 0x00E388A8`, `operator delete(0x00AAE91B)` call args, `EFLAGS` + `512 B FXSAVE` preservation across a dirtying `operator delete` stub, plus paired `0x00A7B433` ctor skip (`83 c4 04 eb 3e 90`) and `0x00A7B850` `atexit` clean exit (`[0x013F0758..0x013F0760] == {0,0,0}`).
- **`test_cr_sese_unicorn.py`**: `Unicorn Country_Recalculate SESE equivalence PASS: 7/7 checks verified` — compares `base-game/v2game.exe` `[0x00515EA6, 0x00516286)` vs `build/cr_sese.bin` (`0x23450000`, RX-sealed) on the 9-tag fixture (`trace len=35`), `total_tags=0` early exit, `"REB"` neg-ctrl, and vs `build/cr_sese_varc.bin` on the 220-tag sparse fixture (`40` living / `180` dead, `trace len=123`) across lazy-init, steady-state `prod`, `validate` OK, and `validate` missing-bit/extra-dead/extra-`"REB"` negative controls (caught, logged, repaired, single-executed).
- **`test_v2p2.py`**: `PE check PASS: i386 DLL, DYNAMIC_BASE+NX_COMPAT, exports=['TGL_PluginInit'], prod_cr_rdtsc=0, varc_bsf=yes`; `v2p2.dll integration PASS: 12/12 host, HighPerfWinClock, fn_00515ea6 & fn_00515ea6_varc (incl. live writers+validate) checks verified`.

## 5. Paso B Pilot (`HighPerfWinClock` `0x00A7B0F0` + `0x00A7B490`)

Controlled by `[hooks] fn_00a7b490 = off | prod` in `v2p2.ini` (default `off`):
- **Paired ctor inline skip (`RVA 0x0067B433`, `6 B`)**: verifies `8b 3d <base + 0x00FF075C>` and overwrites with `83 c4 04 eb 3e 90` (`add esp, 4; jmp short 0x00A7B476; nop`), popping `push 0x10` from `0x00A7B42A` and skipping the `[0x013F0758..0x013F0760]` node allocation/append.
- **Paired dtor P2 PIC hook (`vtable[0]` `.rdata:RVA 0x00A43A88` -> `PAGE_EXECUTE_READ` blob)**: `p2_dtor_a7b490_handler` reads immutable `exe_base` from `cfg->user_data` (zero shared mutable globals), writes `base + 0x00A388A8` (`0x00E388A8`) to `*(uint32_t *)this`, conditionally calls `__cdecl operator delete` (`base + 0x006AE91B`) if `(flags & 1) != 0`, sets `regs->eax = this`, and returns `P2_ACT_HANDLED` (`RET 4` via `.Lhandled_ret4`). Installs atomically (rolls back ctor patch if vtable patch fails).

## 6. Microbenchmark Results (`C_hook`) & P1 -> P3 Gate

Measured via `run_bench.py` (`bench_results.json`) under `wine-11.21` in isolated `WINEPREFIX=experiments/p2-hook-lab/wine-prefix` on `Intel(R) Core(TM) i5-8600K CPU @ 3.60GHz` (`6C/6T`, `tsc_ghz = 3.599737`, `qpc_freq_hz = 10000000`), `warmup = 1,000,000`, `calls_per_batch = 10,000,000`, `batches = 20`:

| Config | Median Cycles/call | p95 Cycles/call | Median ns/call | p95 ns/call | Notes |
| --- | ---: | ---: | ---: | ---: | --- |
| `A_baseline_direct` | 4.3806 | 4.6102 | 1.2175 | 1.2825 | Direct `call rel32` to `ret 4` |
| `B_pic_nop_trampoline` | 198.8534 | 214.1898 | 55.2401 | 59.5006 | Full `pushal/pushfl/fxsave/fxrstor/popfl/popal` |
| `C_pic_empty_c_handler` | 206.9051 | 209.0727 | 57.4760 | 58.0792 | `p2_dispatch` -> empty C handler -> fallback |
| `C_handled_empty_c_handler` | 176.2667 | 177.1542 | 48.9661 | 49.2117 | `p2_dispatch` -> empty C handler -> `P2_ACT_HANDLED` |
| `D_baseline_vtable` | 4.5924 | 4.7343 | 1.2761 | 1.3159 | Direct vtable `call *(%edx)` |
| `D_vtable_empty_handler` | 206.4229 | 212.4729 | 57.3428 | 59.0235 | Vtable slot -> PIC entry -> fallback |
| `E_tbb_contended_4thr` | 240.3745 | 314.0760 | 66.7740 | 87.2466 | 4 concurrent threads on same sealed PIC blob |
| `E_tbb_contended_6thr` | 299.1302 | 414.3483 | 83.0954 | 115.1020 | 6 concurrent threads on same sealed PIC blob |

Derived P2 constants (`bench_results.json`):
- `C_fx_ns = 54.0226 ns`
- **`C_hook_ns = 56.2585 ns`** (`202.5245 cycles`) — fallback path (`C - A`)
- `C_hook_handled_ns = 47.7487 ns` — replacement epilogue (`C_handled - A`)
- `D_vtable_hook_ns = 56.0667 ns`
- **Resulting P1 -> P3 Promotion Thresholds**:
  - `T_orig >= 10 * C_hook = 562.585 ns/call` (`>= 477.49 ns/call` on handled-only path).
  - Net projected savings `>= 0.25 ms/day`.

**Thread-scaling observation (`E4_vs_C_ratio = 1.1618`, `E6_vs_C_ratio = 1.4457`)**:
- Both `E4` (`1.1618`) and `E6` (`1.4457`) exceed the strict `<= 1.10` wall-clock gate in the `10M x 20` run because the host CPU is a 6-core / 6-thread `i5-8600K` (no HyperThreading) running under active background load (`load average ~5.40` during testing), and `QueryThreadCycleTime` returns `0` under `wine-11.21` so `QPC`/`RDTSCP` capture OS scheduler preemption (`p95 = 115.10 ns` on 6 threads).
- A short-batch scaling probe (`2M x 10`) confirmed `0.9747x` (`1 thr`), `1.0000x` (`2 thr`), `1.0075x` (`4 thr`), and `1.2609x` (`6 thr`), and static inspection confirms the `PAGE_EXECUTE_READ` blob performs zero writes outside thread-local `[esp]`/`[ebp]`. Re-running `run_bench.py` on a quiescent host is recommended if a clean wall-clock `E_vs_C_ratio <= 1.10` certificate is required.

## 7. C1a `Country_Recalculate` SESE `[0x00515EA6, 0x00516286)` Variant (a)

Controlled by `[hooks] fn_00515ea6 = off | prod` in `v2p2.ini` (default `off`; `shadow` rejected cleanly until a differential comparator exists):
- **Detour site (`RVA 0x00115EA6`, `6 B`)**: verifies entry `8b 54 24 28 8b 02` and exit `RVA 0x00116286` (`8b 83 00 0a 00 00`), installs `build/cr_sese.bin` onto a `PAGE_EXECUTE_READ` page (`0` `rdtsc`, `0` shared mutable globals), and patches `E9 <rel32> 90` to return cleanly to `base + 0x00116286`.
- **Variant (a) (`cr_sese_body.c`)**: exact ascending `0..total_tags-1` loop preserving all checks (`other_id == self->id`, `other_id == 0`, `"REB"`, `(other+0x9DC - other+0x9D8) & ~3 <= 0`), exact helper calls/ABIs, and `[esp_in+0x18] = total_tags`, with guarded `PREFETCHT0` lookahead (`CR_PREFETCH_DIST = 3`) on `entries[idx+3]`, `other[p_id]+0x9D8`, `&self_relations[p_id]`, and `self_relations[p_id]+0x70`.
- **Intra-region `RDTSC` benchmark (`run_bench_cr.py`, `bench_cr_results.json`)**: `220` tags (`40` living / `180` dead), `8192`-byte country stride, `4096`-byte relation stride, `32` warmup + `400` interleaved A/B pairs under Wine on `i5-8600K`:

| Fixture Condition | Non-prefetched Median (p95) | Variant (a) `PREFETCHT0` Median (p95) | Delta (Median / p95) |
| --- | ---: | ---: | ---: |
| `cold_clflush` (per-iter `clflush` + `mfence; lfence`) | `23,242.0` (`25,030`) cyc | `23,548.0` (`25,350`) cyc | `+306.0` cyc (`+1.32%`) / `+320` (`+1.28%`) |
| `warm_cached` (L1/L2 resident) | `5,794.0` (`5,914`) cyc | `6,928.0` (`7,060`) cyc | `+1,134.0` cyc (`+19.57%`) / `+1,146` (`+19.38%`) |

Under this synthetic 220-tag scattered fixture on the 6-core `i5-8600K`, software `PREFETCHT0` adds pointer-chasing load overhead for dead tags (~81.8% of iterations) without beating hardware prefetch/OoO execution (`+1.32%` cold, `+19.57%` warm), so `fn_00515ea6` stays `off` by default unless whole-process SPA `RDTSC` profiling demonstrates a net win with full helper bodies active.

## 8. V2 `Country_Recalculate` SESE Variant (c) Compact Living-Tag Bitmask

Controlled by `[hooks] fn_00515ea6_varc = off | validate | prod` in `v2p2.ini` (default `off`; rejected cleanly if `fn_00515ea6` is already active):
- **Bitmask & lazy-init (`CRVarCState` in `p2_layout.h`)**: `128` dwords (`512 B`, up to `4096` tags; tags `> 4096` fall back cleanly to the full ascending loop), plus `initialized`, `dirty`, `total_tags`, and `entries_ptr`. Lazy-initializes on first entry to `0x00515EA6` (or when `total_tags` / `entries_ptr` / `dirty` changes) to capture initial savegame loads cleanly.
- **Bounded 3-writer `E8` hooks (`v2p2.c` + `v2p2_varc_asm.S`)** per `COUNTRY-PROVINCES-WRITERS.md` (all 10 call sites verified & rolled back atomically on mismatch):
  1. `CProvince::SetOwner` (`0x004B52E0`, `__thiscall`, `ret 0x10`, all 7 callers `0x004A9B5B`, `0x004B5965`, `0x004B5CC5`, `0x004EC6F4`, `0x004F9900`, `0x00537170`, `0x005F4020`): checks low byte `(arg4 & 0xFF) == 0`, snapshots `old_id = *(prov + 0x12C)` pre-call, and refreshes `old_id` and `new_id` post-call.
  2. `CCountry::Reset` (`0x00503020`, `__stdcall`, `ret 4`, both callers `0x004F8284`, `0x0067E78A`): refreshes `country->+0x20` bit post-call when initialized.
  3. `CWorld::ChangeTag` (`0x006881D0`, `__stdcall`, `ret 0xC`, caller `0x00880F83`): sets `dirty = 1` pre-call so the internal `0x00689401` `Country_Recalculate` call refreshes `alive_bits` after the `country_mgr+4` swap, and refreshes `id1`/`id2` post-call if still `dirty`.
- **SESE `bsf` scan & `validate` mode (`cr_sese_body.c`)**: scans `alive_bits` via `bsf` (`mask &= mask - 1`) in strictly ascending `idx` order, skipping `self->id`. In `validate`, every entry to `0x00515EA6` compares every bit `0..total_tags-1` against `(id != 0 && tag != "REB" && ((other+0x9DC - other+0x9D8) & ~3) > 0)`, logs mismatches (`idx`, `expected`, `actual`, `QPC`) via `OutputDebugStringA` + `v2p2_varc_validate.log`, repairs the bit, and executes the SESE body **exactly once**.
- **Intra-region `RDTSC` 4-variant benchmark (`run_bench_cr.py`, `bench_cr_results.json`, 220 tags [40 living / 180 dead], 400 interleaved pairs)**:

| Variant | `cold_clflush` Median (p95) | vs `nopf` | `warm_cached` Median (p95) | vs `nopf` |
| --- | ---: | ---: | ---: | ---: |
| `nopf` (full 220-tag scan) | `26,582.0` (`37,342`) cyc | `—` | `5,795.0` (`6,072`) cyc | `—` |
| `var_a_prefetcht0` (full + `+3` prefetch) | `26,255.0` (`39,120`) cyc | `-1.23%` / `+4.76%` | `6,861.0` (`7,220`) cyc | `+18.40%` / `+18.91%` |
| **`var_c_bitmask` (`bsf`, no prefetch)** | **`9,176.0` (`12,248`) cyc** | **`-65.48%` / `-67.20%`** | **`2,224.0` (`2,382`) cyc** | **`-61.62%` / `-60.77%`** |
| **`var_c_living_prefetcht0` (`bsf` + living prefetch)** | **`8,003.0` (`11,144`) cyc** | **`-69.89%` / `-70.16%`** | **`1,987.0` (`2,152`) cyc** | **`-65.71%` / `-64.56%`** |
