# Verification Report: P0 Baseline, P1 Triage, and P2 Hook Architecture

- **Target binary**: `base-game/v2game.exe` (SHA-256 `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`, preferred `ImageBase = 0x00400000`, `AddressOfEntryPoint = 0x006B0F91`, `SizeOfImage = 0x01092000`, `CheckSum = 0x00BC1E13`, statically imports `lua51.dll` and `DINPUT8.dll`) `[confirmed]`.
- **Reference binary integrity**: `base-game/v2game.exe` (`2022-08-10 20:30:33`), `base-game/performance_patch.ini` (`2026-10-22 13:53:18`), and `base-game/performance_patch_samples.tsv` (`2026-10-22 14:57:16`) remained unmodified `[confirmed]`.
- **Overall status**: **ALL DELIVERABLES PASS** (with 3 worker defects caught and fixed during verification: `FUN_00515490.md` caller inclusive count `#9/#10`, `P2-HOOK-ARCHITECTURE.md` `.Lhandled` stack/return contract & citations `#12/#13`, and `research/perf/README.md` `run-03` modal stall value `#21/#22`).

---

## 1. P0 Reproducible Performance Baseline (`@profiler`) — **PASS**

### 1.1 SHA-256 & Isolation Verification (`confirmed`)

| Artifact | Verified SHA-256 | Match vs Base / Spec |
|---|---|---|
| `base-game/v2game.exe` & `experiments/perf-baseline-lab/game/v2game.exe` | `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648` | Exact match |
| `base-game/dinput8.dll` & `experiments/perf-baseline-lab/game/dinput8.dll` | `c6e25bdc119d01014064d18284ddb7116b6bcca8abfbd9159a31b3e39e8d746f` | Exact match |
| `base-game/lua5.1.dll` & `experiments/perf-baseline-lab/game/lua51.dll` | `e50c69219a676587199fce1e27d9ef9f2924990f006b3f84cb37971f2e804215` | Exact match (vanilla Lua) |
| `base-game/performance_patch/performance_patch.dll` & `experiments/perf-baseline-lab/game/mod/performance_patch/performance_patch.dll` | `2681385e9314d204fb00f5244d9624162366d332b47474e834301afb3ddaf9da` | Exact match |

- *Note on `settings.txt`*: `experiments/perf-baseline-lab/lab-setup.json` and `research/perf/README.md` record initial staged `settings_sha256 = 73122d63f1d4a480203e697bac2f813a33959b32e8e06e92a3c8b2eb2377efe4`; the post-run file on disk (`experiments/perf-baseline-lab/game/settings.txt`) hashes to `1412609f4847b940b3ad328f26ce8fcb1434b474cec5960d0306ad6e33396918` after `v2game.exe` execution.

### 1.2 Factor-2 Audit of `base-game/performance_patch_samples.tsv` (`confirmed`)

- Independent parse of `base-game/performance_patch_samples.tsv`: `877` `stack` rows, `sum(count) = 1311`, `sum(ms/day) = 546.2732`, matching header `interval 100 ms, 120 days, 1311 samples, 546.2 ms/day sampled, 877 stacks, 0 dropped`.
- Independent Capstone disassembly of `experiments/installed-patches/performance_patch/performance_patch.dll`:
  - `0x100365D6..0x100365F4`: caps `sample_profiler` interval in `[0x10132080]` at `0x64` (`100` ms).
  - `0x1003745E: 6a 32` (`push 0x32` = `50`) / `0x10037469: 68 e8 03 00 00` (`push 0x3e8` = `1000`): computes `max_sample_qpc = (qpc_freq * 50) / 1000`.
  - `0x10037494`: calls `Sleep([0x10132080])` (`100` ms), then `0x100374CD..0x100374D9` clamps `delta_qpc` to `max_sample_qpc` (`50` ms).
  - Arithmetic confirmed: `1311 * 50 / 120 = 546.25` (formatted `546.2`) instead of `1311 * 100 / 120 = 1092.5`.

### 1.3 Raw Run Consistency, `n = 5` Stats & Gate Evaluation (`confirmed`)

Independent recomputation from `research/perf/raw/{run-01..run-05,ctrl-skipnet-1}/{run_metrics.json,performance_patch_samples.tsv,the_grand_loader.log}`:

| Tag | `skip_network_wait` (log) | Rows / Samples | Header `ms/day` (sum `pct`) | Raw Wall | Modal Stall | Active Wall | Per-Day Median |
|---|---|---|---|---:|---:|---:|---:|
| `run-01` | `0` (`disabled`) | `777` / `1080` | `599.8` (`599.84`) | `604.992` | `0.000` | `604.992` | `558.206` |
| `run-02` | `0` (`disabled`) | `737` / `1013` | `562.6` (`562.62`) | `571.452` | `0.000` | `571.452` | `547.774` |
| `run-03` | `0` (`disabled`) | `704` / `997` | `553.7` (`553.76`) | `624.820` | `7780.680` | `538.368` | `533.992` |
| `run-04` | `0` (`disabled`) | `689` / `967` | `537.0` (`537.07`) | `542.827` | `0.000` | `542.827` | `537.737` |
| `run-05` | `0` (`disabled`) | `702` / `966` | `536.5` (`536.55`) | `544.808` | `0.000` | `544.808` | `536.446` |
| `ctrl-skipnet-1` | `1` (`active, ... no longer blocks`) | `688` / `968` | `537.6` (`537.63`) | `547.637` | `0.000` | `547.637` | `540.213` |

- `n = 5` baseline statistics (`run-01..run-05`, matching `research/perf/baseline.json` exactly):
  - **Active Wall (`ms/day`)**: median `544.808`, mean `560.489`, stdev `28.053`, **CV `5.005%`**, IQR `28.625`, **IQR/median `5.254%`** -> **FAILS `< ~2%` gate** (under host `load1 = 7.19..12.17`).
  - **Raw Wall (`ms/day`)**: median `571.452`, mean `577.780`, stdev `36.408`, **CV `6.301%`**, IQR `60.184`, **IQR/median `10.532%`** -> **FAILS**.
  - **Per-Day Median (`ms/day`)**: median `537.737`, mean `542.831`, stdev `10.071`, **CV `1.855%`**, IQR `11.328`, **IQR/median `2.107%`** -> **BORDERLINE**.
  - **`sample_profiler` (`ms/day`)**: median `553.700`, mean `557.920`, stdev `25.933`, **CV `4.648%`**, IQR `25.600`, **IQR/median `4.623%`** -> **FAILS**.
- Aggregated `n = 5` samples: `5023` total (`v2game.exe` `2192` + unmapped `?` `2`, `ntdll.dll` `2145`, `win32u.dll` `528`, `wined3d.dll` `75`, `d3dx9_41.dll` `35`, `tbb.dll` `22`, `d3d9.dll` `10`, `ucrtbase.dll` `6`, `kernelbase.dll` `5`, `user32.dll` `3`).
- Control `ctrl-skipnet-1`: `547.637 ms/day` (`+0.52%` vs baseline median, inside host noise floor), properly isolated from baseline stats.
- Defect resolved (`#21 -> #22`): `research/perf/README.md:43` `run-03` Modal Stall updated from `7780.703` to `7780.680` to match `run_metrics.json` and `baseline.json`.

---

## 2. P1 Triage Fichas (`@triage-ai` & `@triage-econ`) — **PASS**

All 9 P1 fichas (plus `Country_PrePass` `0x00508590` cross-reference) were verified directly against `base-game/v2game.exe` (Capstone linear disassembly from entry VA), `find_callers.py`, `research/evidence/generated/ghidra-converged/functions.csv`, and `base-game/performance_patch_samples.tsv`.

| Deliverable | Entry..End VA (Bytes / Insns) | ABI & `ret` Verified | x87 / SSE / RNG | TBB Safe (`parallel_decisions=1`) | TSV Leaf / Incl & Dominant Stall | Verdict | Status |
|---|---|---|---|---|---|---|---|
| [FUN_00876240.md](FUN_00876240.md) | `0x00876240..0x00876941` (`1794 B` / `552`) | Custom LTCG `__usercall` (`eax=in_scope`, `esi=out_scope`, `[esp+4]=target`, `ret 4` x22); `7` direct callers | `0` x87, `0` SSE; LCG `0x009B7910` at `0x008764E6`, `0x00876747` | Runs on TBB workers (`performance_patch.dll`); stack scopes private, hook must be thread-safe | `124` (`9.46%`) / `131` (`9.99%`); `0x0087633E` (`103/124`, `83.1%`, memory-bound `[prov+0x128]`) | `cambio de patrón` (needs `@hook-arch` if directly hooked) | **PASS** |
| [FUN_008b8260.md](FUN_008b8260.md) | `0x008B8260..0x008B82A2` (`67 B` / `36`) | `__thiscall ret 4` (`2` exits); `0` direct calls, `.rdata` vtables `0x00DF99AC` / `0x00E2CE90` | `0` x87, `0` SSE, `0` direct RNG | Runs on TBB workers; read-only leaf | `52` (`3.97%`) / `457` (`34.86%`); `0x008B827F/7D/85` (`46/52`, `88.5%`, pointer-chase) | `descartar` (leaf hook/recomp) | **PASS** |
| [FUN_008e2a70.md](FUN_008e2a70.md) | `0x008E2A70..0x008E2A9F` (`48 B` / `16`) | `__thiscall ret 4`; `0` direct calls, vtable slot `0x00E31600`, `100%` TSV via `0x008B9512` | `0` x87, `0` SSE, `0` RNG | Runs on TBB workers; read-only leaf | `28` (`2.14%`) / `28` (`2.14%`); `0x008E2A94` (`22/28`, `78.6%`, `[country+0xE64]`) | `descartar` (cull upstream) | **PASS** |
| [FUN_0084b0f0.md](FUN_0084b0f0.md) | `0x0084B0F0..0x0084B59A` (`1195 B` / `346`) | `__thiscall ret`; `0` direct calls, vtable slot `0x00E2773C` | `0` x87/SSE inline (SSE in callees); `rand()` `0x00AB047B` (`0x0084B526`, `0x0084DE98`) + `MT19937` `0x009B7610` (`0x0084D856`) | Main-thread only (NOT TBB-safe) | `29` (`2.21%`) / `45` (`3.43%`); `0x0084B29D` (`19/29`, `65.5%`, `[rel+0x34]`) | `cambio de patrón` | **PASS** |
| [FUN_00515490.md](FUN_00515490.md) | `0x00515490..0x005163BA` (`3883 B` / `1093`) | `__stdcall ret 4`; `43` direct callers | `0` x87 inline, `11` SSE, `3`x `0x00401000`, `3`x `0x00B31C00`; depth-5 RNG (`0x515995->0x4b8870->0x96bb70->0x96bbf0->0x96be90->0x9b7500->0x9b7610`) | NOT TBB-safe (writes `[0x012588e8]+0xa7c/+0xa84`) | `56` (`4.27%`) / `76` (`5.80%`); `0x00515F24` (`16`) + `0x00515FCF` (`14`) | `cambio de patrón` | **PASS** *(after `#9/#10`)* |
| [FUN_0050ea30.md](FUN_0050ea30.md) | `0x0050EA30..0x00511104` (`9941 B` / `2874`) | `__stdcall ret 4`; `24` direct callers | `0` x87 inline, `18` SSE, `47`x `new`, `12`x `delete`; lazy RNG (`0x50edc5->0x9747a0->0x9740b0->0x9b7500->0x9b7610`) | NOT TBB-safe (writes `0x012586f0`, `0x01258a40`, `0x0125eadc`, `0x0125a69c`) | `21` (`1.60%`) / `27` (`2.06%`); fragmented stride-8 loops (`16/21`) | `descartar` | **PASS** |
| [FUN_00969760.md](FUN_00969760.md) | `0x00969760..0x00969BC9` (`1130 B` / `332`) | Custom LTCG (`EDI=CPop*`, `ESI=accum`, 3 stack args, `ret 0xc`); `2` direct callers | `0` x87, `0` SSE, `0` RNG (`1`x `__alldiv`, `9`x `__allmul`) | Runs inside TBB `0x0068F4C0->0x0068F710->0x00520150`; `0` global writes | `24` (`1.83%`) / `24` (`1.83%`); `0x00969889` (`13/24`, `54.2%`, `[pop+0xa4]`) | `descartar` standalone | **PASS** |
| [FUN_00a7b490.md](FUN_00a7b490.md) | `0x00A7B490..0x00A7B4D5` (`70 B` / `27`) | `__thiscall ret 4`; `1` `.rdata` ref (`0x00E43A88`) | `0` x87, `0` SSE, `0` RNG; `[0x013F0758..0x013F0764]` only in `0x00A7B435..0x00A7B8FF` | NOT TBB-safe (unprotected global list) | `23` (`1.75%`) / `23` (`1.75%`); `0x00A7B4AC` (`20/23`, `87.0%`, list walk) | `cambio de patrón` | **PASS** |
| [CRT_alldiv.md](CRT_alldiv.md) | `0x00AC02A0..0x00AC0349` (`170 B` / `70`) | `__stdcall ret 0x10` (stack arg mutation); `2084` static refs | `0` x87, `0` SSE, `0` RNG | Thread-safe / reentrant | `33` (`2.52%`) / `33` (`2.52%`) across `24` ret sites; `0x00AC02F5/ED/315` (`25/33`, `75.8%`, `div ecx`) | `descartar` global hook (`micro-opt local` in callers) | **PASS** |

- **Cross-references verified (`confirmed`)**:
  - `Country_PrePass` (`0x00508590..0x0050919D`, `3086 B`, `882` insns): `19` leaf (`1.45%`) / `116` inclusive (`8.85%`), dominant leaf `0x00508DEE` (`12/19` on `relation+0x2c`), untouched by `experiments/tick-country-prepare-lab` (which patches `0x00685AA9..0x00685AE4` only).
  - `__alldiv` `.rdata` constants: `0x00F0ADE0 = 0x1f40000` (`32768000`) and `0x00F0AE08 = 0x78000` (`491520`).
  - Defect resolved (`#9 -> #10`): `FUN_00515490.md:25` corrected caller `0x009068C9 + 0x00906872` inclusive count from `10` to `11` (`9 + 2`), reconciling total inclusive callers (`61 + 11 + 2 + 1 + 1 = 76`).

---

## 3. P2 Hook Architecture & ENet Wait Audit (`@hook-arch`) — **PASS**

Verified [P2-HOOK-ARCHITECTURE.md](P2-HOOK-ARCHITECTURE.md) against `experiments/v2opt/src/`, `experiments/tick-country-hook-lab/build_hook.py`, `experiments/installed-patches/`, and `base-game/v2game.exe`:

1. **Startup Load & PIC Rules (`confirmed`)**:
   - `dinput8.dll` (`c6e25bdc...`) and `lua51.dll` (`1411b883...`) are statically imported by `base-game/v2game.exe`, executing under loader lock before OEP `0x00AB0F91` and before worker threads spawn.
   - `experiments/tick-country-hook-lab/build_hook.py` confirms `-mno-sse -mno-mmx -msoft-float -nostdlib` (`line 51`), zero imports, and zero base relocations for PIC `hook.bin` blobs sealed `PAGE_EXECUTE_READ`.
2. **ABI / x87 / SSE Preservation & TBB Safety (`confirmed`)**:
   - Defect resolved (`#12 -> #13`): Section 2.3.1 unified `pushl $0` at `_p2_hook_entry` (`[ebp+0x24] = slot`, `[ebp+0x28] = caller_retaddr`, `[ebp+0x2C+] = args`), copies `0x28(%ebp)` -> `0x24(%ebp)` before `popfl; popal` on `.Lhandled` followed by `ret $(N + 4)` (preserving `EFLAGS` and all 8 GPRs), and copies `cfg->original_target` -> `0x24(%ebp)` before `fxrstor; popfl; popal; ret` on `.Lfallback_to_original`.
   - Supports standard `__thiscall`/`__cdecl`/`__stdcall` and custom LTCG `__usercall` (`FUN_00876240`, `void` return writing `out_scope` at `esi`).
   - Zero shared mutable global state in production mode; per-function `.ini` toggles (`off`/`prod`/`shadow-compare` with RNG/state guard) and 5-config microbenchmark + promotion gates (`C_hook <= 0.10 * T_orig`, net savings `>= 0.25 ms/day`, 6-thread scaling `<= 1.10x`).
3. **ENet `skip_network_wait` Static Audit (`confirmed`)**:
   - Vtable `+0x1C` service slots verified in `.rdata`: `mode == 2` (`0x00E42840 -> 0x00A68450`, `"NoAdress"` `0x00E07678`, `"InitialSession"` `0x00E07684`) drains `[esi+0x7c] -> [esi+0x54]`, increments `[[esi+0x1c]+0x54]` (`0x00A68549..0x00A6854C`), and never calls ENet or `select`.
   - `NetSession base` (`0x00A5FFCB`) sets `[edi+0x20] = 0x0F` (`15 ms`). `NetSession_Service` (`0x00A61780`, `mode == 1`) calls `enet_host_service` (`0x00A89D00`) at `0x00A618CC`; `enet_socket_wait` (`0x00A8B400`) calls `WS2_32!select` (`[0x00C8A330]`) at `0x00A8B477`.
   - `performance_patch.dll` (`0x10037920..0x100379CE`) patches only `exe_base + 0x6618CC` (`0x00A618CC`) to force `timeout = 0` (`[esp+0x0c] = 0`).
   - Independent 364-function BFS over `0x00A68450`, `0x00A61780`, `0x00A89D00`, and `0x00A8B400` found **0** direct or transitive calls to `0x009B7910`, `0x009B7610`, `0x009B7670`, `0x009B7700`, `0x00AB047B`, or `0x00AB046B`. Single-player command ordering and RNG state are unaffected.
