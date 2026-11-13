# P0 Reproducible Performance Baseline (`v2game.exe`)

## Target & Isolation Scope (`confirmed`)

- **Target binary**: `base-game/v2game.exe` (SHA-256 `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`, preferred image base `0x00400000`, `base-game/` unmodified).
- **Save**: `input-autosave.v2` (`SPA 1837.1.1`, SHA-256 `a3885cc5b64328e04b45b92c2329e5cfa7d2d931746110fb750e47475fd39e1b`).
- **Isolated lab**: `experiments/perf-baseline-lab/` staged by [prepare_lab.py](prepare_lab.py) (`lab-setup.json`):
  - `dinput8.dll`: SHA-256 `c6e25bdc119d01014064d18284ddb7116b6bcca8abfbd9159a31b3e39e8d746f`
  - `lua51.dll` (copied from `base-game/lua5.1.dll`, vanilla Lua without V2DLL): SHA-256 `e50c69219a676587199fce1e27d9ef9f2924990f006b3f84cb37971f2e804215`
  - `mod/performance_patch/performance_patch.dll` (identical to `base-game/performance_patch/performance_patch.dll` and `experiments/installed-patches/performance_patch/performance_patch.dll`, preferred base `0x10000000`): SHA-256 `2681385e9314d204fb00f5244d9624162366d332b47474e834301afb3ddaf9da`
  - DirectX system DLLs copied from `~/.wine/drive_c/windows/syswow64/`: `d3dx9_41.dll`, `d3dcompiler_41.dll`, `d3dcompiler_43.dll`
  - `settings.txt`: `1280x720` windowed, `autosave="NEVER"`, audio muted (`settings_sha256`: `73122d63f1d4a480203e697bac2f813a33959b32e8e06e92a3c8b2eb2377efe4`)
  - All `performance_patch.ini` optimization and bugfix toggles set to `0` (`background_sleep_ms = 100`, `sample_profiler = 50`; `skip_network_wait = 0` for baseline, `1` for control).
- **Session serialization & display isolation**: [run_baseline.py](run_baseline.py) verifies no `v2game.exe` is active before starting, launches one isolated `Xvfb` (`1280x800x24`, auto-selecting a free display `:95+` while leaving external `:99` untouched) + `xfwm4 --sm-client-disable --compositor=off --vblank=off`, tracks the simulation day clock directly in `/proc/<pid>/mem` (`INITIAL_CLOCK = 59892120`, `+24/day`), and tears down `v2game.exe`, `wineserver -k`, `xfwm4`, and `Xvfb` after every run.

---

## Task 1 Audit: Factor-2 Discrepancy in `performance_patch_samples.tsv` (`confirmed`)

Why `1311 samples * 100 ms / 120 days = 1092.5 ms/day`, yet `base-game/performance_patch_samples.tsv` header reports `546.2 ms/day sampled` (exactly half):

1. **Interval cap (`0x10036590`)**: Config parser reads `sample_profiler` into `[0x10132080]` and caps values `> 100` (`0x64`) at `100 ms` (`0x100365d6..0x100365f4`: `"sample_profiler: interval capped at 100 ms"`).
2. **50 ms QPC clamp (`0x10037420`)**: The sampler thread queries `QueryPerformanceFrequency()` via `0x1000272a` (`0x1001e310`) and at `0x10037457..0x1003747b` precomputes:
   - `max_sample_qpc = (qpc_freq * 50) / 1000` (`0x1003745e: push 0x32` = **50 ms**, `0x10037469: push 0x3e8` = 1000).
3. **Loop measurement clamping (`0x10037494..0x100374d9`)**: Each iteration calls `Sleep([0x10132080])` (`100 ms`), computes `delta_qpc = QPC() - prev_qpc`, and at `0x100374cd..0x100374d9` **clamps `delta_qpc` to `max_sample_qpc` (50 ms)**. Because `Sleep(100)` always takes `>= 100 ms > 50 ms`, every sample is credited with `50 ms` of QPC time instead of `~100 ms`.
4. **Idle skip (`0x1003758f`)**: Compares `(now - last_day_change_qpc) * 1000.0 / qpc_freq` against `[0x1010fe58] = 2000.0 ms`, skipping sampling while paused longer than 2 s.
5. **Accumulation & TSV writer (`0x10036c10`, `0x100360f0`, `0x10036e60`)**: Recording adds the clamped `delta_qpc` to `total_qpc` (`0x101377b0..b4`) and per-stack `[edi+0x18..0x1c]`; the report writer computes header `ms/day sampled` (`0x10036ece..0x10036f4d`) and per-stack `ms/day` (`0x10037077..0x100370b7`) as `(qpc * 1000.0 / qpc_freq) / days`.
6. **Arithmetic verification**:
   - `base-game/performance_patch_samples.tsv`: `877` stack rows, `sum(count) = 1311`, `sum(ms/day) = 546.2732`. `1311 * 50 / 120 = 546.25` (formatted `%.1f` -> `546.2`), and `1 * 50 / 120 = 0.4167`.
   - Same clamp explains `experiments/v2opt/PROFILING.md#L40` (`279 * 50 / 30 = 465.0 ms/day`, despite line 45 writing `count * 100 / 30`).
   - **Implication**: Relative stack percentages at `interval = 100` remain accurate (every sample hits the 50 ms clamp uniformly), while absolute `ms/day sampled` is halved. Setting `sample_profiler = 50` in P0 avoids the 50 ms clamp (`1080 * 50 / 90 = 600.0` vs `599.8` reported; `967 * 50 / 90 = 537.2` vs `537.0` reported).

---

## P0 Runs (`SPA 1837.1.1`, 90 days, speed 5, `sample_profiler = 50 ms`)

All runs serialized 1 at a time on `:95`. Raw outputs stored in `research/perf/raw/<tag>/` (`run_metrics.json`, `performance_patch_samples.tsv`, `the_grand_loader.log`, `game.log`) and aggregated in [baseline.json](baseline.json).

| Tag | Role | `skip_network_wait` | Days | Raw Wall (ms/day) | Modal Stall (ms) | Active Wall (ms/day) | Per-Day Median (ms) | `sample_profiler` (ms/day) | Samples | Modals | Host `load1` (before -> after) |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| `run-01` | Baseline | `0` (`disabled`) | 90 | 604.992 | 0.0 | 604.992 | 558.206 | 599.8 | 1080 | 0 | `7.19 -> 12.17` |
| `run-02` | Baseline | `0` (`disabled`) | 90 | 571.452 | 0.0 | 571.452 | 547.774 | 562.6 | 1013 | 0 | `11.27 -> 10.52` |
| `run-03` | Baseline | `0` (`disabled`) | 90 | 624.820 | 7780.680 | 538.368 | 533.992 | 553.7 | 997 | 1 | `9.68 -> 9.70` |
| `run-04` | Baseline | `0` (`disabled`) | 90 | 542.827 | 0.0 | 542.827 | 537.737 | 537.0 | 967 | 0 | `9.89 -> 11.55` |
| `run-05` | Baseline | `0` (`disabled`) | 90 | 544.808 | 0.0 | 544.808 | 536.446 | 536.5 | 966 | 0 | `10.79 -> 10.13` |
| `ctrl-skipnet-1` | **CONTROL ONLY** | `1` (`active`) | 90 | 547.637 | 0.0 | 547.637 | 540.213 | 537.6 | 968 | 0 | `9.72 -> 11.08` |

---

## Dispersion, Noise Floor & P0 Gate Evaluation (`confirmed`)

Computed across `n = 5` baseline runs (`run-01`..`run-05`, excluding `ctrl-skipnet-1`):

| Metric | Median | Mean | Stdev | CV (%) | IQR (`Q3 - Q1`) | IQR / Median (%) | Robust Sigma (`IQR / 1.349`) | Min .. Max | `< 2%` Gate |
|---|---:|---:|---:|---:|---:|---:|---:|---|---|
| **Active Wall (`ms/day`)** | **544.808** | 560.489 | 28.053 | **5.005%** | 28.625 | **5.254%** | 21.220 ms/day | `538.368 .. 604.992` | **FAIL** |
| Raw Wall (`ms/day`) | 571.452 | 577.780 | 36.408 | 6.301% | 60.184 | 10.532% | 44.614 ms/day | `542.827 .. 624.820` | **FAIL** |
| Per-Day Median (`ms/day`) | 537.737 | 542.831 | 10.071 | **1.855%** | 11.328 | **2.107%** | 8.397 ms/day | `533.992 .. 558.206` | **BORDERLINE (~2%)** |
| `sample_profiler` (`ms/day`) | 553.700 | 557.920 | 25.933 | 4.648% | 25.600 | 4.623% | 18.977 ms/day | `536.500 .. 599.800` | **FAIL** |

- **Gate assessment**:
  - Under current shared-host contention (`load1 = 7.19..12.17` on a 6-core desktop running GUI/swarm workloads) and software `wined3d` rendering inside `Xvfb`, total 90-day **Active Wall dispersion is 5.01% CV / 5.25% IQR**, which **FAILS the `< ~2%` P0 gate**.
  - Notice `run-03..run-05` clustered tightly at `538.368 .. 544.808 ms/day` (`1.20%` span), whereas `run-01` (`604.992 ms/day`, `load1` spiked `7.19 -> 12.17`) and `run-02` (`571.452 ms/day`, `load1 = 11.27`) elevated the mean and IQR.
  - **Noise floor**: Any patch benchmark on this loaded host cannot resolve `< ~5%` (`~21–28 ms/day` 1-sigma) active wall-clock deltas above host scheduling noise unless measured either on a quiet host (`load1 < ~3`), with paired `per_day_median_ms` (`CV = 1.855%`, `IQR = 2.107%`, noise floor `~8.4–10.1 ms/day`), or via targeted profiler sample shares.

---

## Control Measurement: `skip_network_wait = 1` vs `0` (`confirmed`)

- **`ctrl-skipnet-1`** (`the_grand_loader.log`: `[performance_patch] skip_network_wait: active, the per-frame network poll no longer blocks`):
  - Active Wall: `547.637 ms/day` vs baseline median `544.808 ms/day` -> **`+2.829 ms/day` (`+0.52%`)**, well inside the `±28.053 ms/day` (`±5.0%`) baseline noise floor.
  - Per-Day Median: `540.213 ms/day` vs baseline median `537.737 ms/day` -> **`+2.476 ms/day` (`+0.46%`)**.
  - `sample_profiler`: `537.6 ms/day` (`968` samples) vs baseline median `553.7 ms/day` (`997` samples).
- **Interpretation**: On this busy host (`load1 = 9.72 -> 11.08`), `skip_network_wait = 1` produces no measurable speedup above the noise floor because main-thread time is dominated by `ZwWaitForSingleObject` / `ZwDelayExecution` in rendering/UI (`FUN_006592f0`) and simulation ticks (`FUN_0057a690`), not the per-frame network wait.

---

## Aggregated `sample_profiler` Breakdown (`n = 5` baseline, 5023 samples / 450 days)

### Leaf Module Distribution (`confirmed`)

| Module | Samples | Share |
|---|---:|---:|
| `v2game.exe` | 2192 | 43.64% |
| `ntdll.dll` | 2145 | 42.70% |
| `win32u.dll` | 528 | 10.51% |
| `wined3d.dll` | 75 | 1.49% |
| `d3dx9_41.dll` | 35 | 0.70% |
| `tbb.dll` | 22 | 0.44% |
| `d3d9.dll` | 10 | 0.20% |
| `ucrtbase.dll` / `kernelbase.dll` / `user32.dll` / `?` | 16 | 0.32% |

### Top Leaf Frames & Dominant Call Chains (`confirmed`)

- **Top leaves**:
  1. `ntdll.dll:ZwWaitForSingleObject`: `1170` (`23.29%`) — predominantly `FUN_0099a520@0x0099A542 <- FUN_006592f0@0x00660F0C` (`879` samples, `17.50%` alone in exact top-10 stack prefix).
  2. `ntdll.dll:ZwDelayExecution`: `857` (`17.06%`) — predominantly `FUN_0099a200@0x0099A3D5 <- FUN_00a292a0@0x00A29313 <- FUN_00a20470@0x00A205E7 <- ... <- FUN_006592f0@0x006596B6` (`428` samples across top prefixes) and `FUN_007fa740@0x007FB844 <- FUN_007f75d0@0x007F7A7A <- FUN_00645460@0x0064547C <- FUN_006592f0@0x00659584` (`173` samples, `3.44%`).
  3. `win32u.dll:NtUserGetCursorPos`: `283` (`5.63%`) — called via `FUN_00a7a970@0x00A7A983 <- FUN_00657b60` (`FUN_00654d80`).
  4. `win32u.dll:NtUserCallOneParam`: `179` (`3.56%`) — called via `FUN_00a7a970@0x00A7A9AE`.
  5. `v2game.exe:FUN_00969760` (`0x00969760+0x129`): `63` (`1.25%`); `v2game.exe:__alldiv` (`0x00AC02A0+0x55`): `61` (`1.21%`); `ntdll.dll:ZwYieldExecution`: `37` (`0.74%`).
- **Simulation vs Render/Wait split across all `v2game.exe` stacks** (`confirmed` via stack-frame grep on all 6 TSVs):
  - Stacks containing `0x0057A732` (`FUN_0057a690`, daily simulation tick): `39.8%`–`41.0%` in `run-01..run-05` (`38.8%` in `ctrl-skipnet-1`).
  - Stacks containing `0x006592F0`/`0x00660F0C` (render/frame/wait loop): `44.8%`–`45.9%` in `run-01..run-05` (`47.4%` in `ctrl-skipnet-1`).
  - Leaf `ZwWaitForSingleObject + ZwDelayExecution`: `39.5%`–`41.4%` in `run-01..run-05` (`42.1%` in `ctrl-skipnet-1`).
  - *Note on CRT bottom frames (`inferred`)*: `functions.csv` maps stack-bottom return addresses (`0x00AB98AA`, `0x00AB7CD4`, `0x00AB8CE0`, `0x00AB04E7`) to CRT symbols (`__getptd_noexit`, `__whiteout`, `__input_l`, `_malloc`), reflecting `StackWalk64` unwinding past/through CRT/allocator trampolines; use `0x00654D80` (`47.58%`), `0x006592F0` (`45.29%`), `0x009AF9F0` (`40.99%`), and `0x0057A690` (`40.22%`) for game-logic attribution.

---

## Reproducing P0

```bash
python3 research/perf/prepare_lab.py
for i in 1 2 3 4 5; do
  python3 research/perf/run_baseline.py --tag "run-0$i" --days 90 --sample-interval 50 --skip-network-wait 0
done
python3 research/perf/run_baseline.py --tag ctrl-skipnet-1 --days 90 --sample-interval 50 --skip-network-wait 1
python3 research/perf/analyze_baseline.py
```

---

## Paso B Pilot: `HighPerfWinClock` (`0x00A7B0F0` + `0x00A7B490`) Pipeline & `atexit` Equivalence (`confirmed`)

> **Scope note**: Per `#30` and `#39`, `SPA 1837.1.1` has `0` leaf samples in `0x00A7B490..0x00A7B4D5` across the `n = 5` baseline (`5023` samples). This run validates **TGL plugin load, runtime patching, memory/list invariance, W^X sealing, 90-day stability, and clean `atexit` (`0x00A7B850`) exit** — **NOT** a SPA speedup claim.

- **Runner**: [run_pilot_a7b490.py](run_pilot_a7b490.py) (temporarily staged `experiments/p2-hook-lab/build/v2p2.dll` SHA-256 `ebfa16fd447a4d71e2fbf58ae99f1b0ebdfb76056bad19f47b78712d383abf2c` + `mod/v2p2.ini` with `fn_00a7b490 = prod` in `experiments/perf-baseline-lab/game/mod/`, then unstaged cleanly after teardown; `base-game/` untouched).
- **Results JSON**: [pilot_a7b490.json](pilot_a7b490.json) and raw artifacts in `research/perf/raw/pilot-a7b490/`.
- **Verification checks**:
  - **TGL plugin load (`the_grand_loader.log`)**: `[loader] 2 plugin(s) loaded`; `v2p2: fn_00a7b490 paired HighPerfWinClock pilot installed (ctor skip + P2 PIC dtor).`; `v2p2: TGL_PluginInit ready (PE verified, 1 hooks installed, W^X sealed).`
  - **Live `/proc/<pid>/mem` & `/proc/<pid>/maps` (`post_load` and `post_90d`)**:
    - `0x00A7B433` ctor skip bytes: `83 c4 04 eb 3e 90` (`matches_expected: true`)
    - `.rdata:0x00E43A88` (`vtable[0]`): patched to `0x01d30050` inside an `r-xp` (`PAGE_EXECUTE_READ`) mapping (`dtor_vtable_hooked: true`)
    - `[0x013F0758..0x013F0764]`: `head = 0`, `tail = 0`, `count = 0`, `tombstone_flag = 0` (`clock_list_zero: true`) both right after load and after 90 simulated days.
  - **90-day run & clean `atexit` shutdown**: `elapsed_days = 90`, `0` crashes, `1` modal pause (`7521.19 ms`), clean exit via `in_game_menu_quit_return` with `exit_returncode = 0` (`clean_exit: true`, triggering CRT `_atexit` `0x00A7B850`).
  - **Pipeline / equivalence telemetry (NOT a perf claim)**: `per_day_median_ms = 530.24 ms/day`, `active_wall_ms_per_day = 520.037 ms/day`, `sample_profiler = 534.8 ms/day sampled` (`963` samples, `0` dropped, `0` hits in `0x00A7B4xx`/`0x00A7B0xx`, `load1 = 2.91 -> 8.85`).

---

## C1b (Runtime): Gate 2 Determinism Check on `SPA 1837.1.1` (90 Days) (`confirmed`)

- **Runner**: [run_determinism.py](run_determinism.py)
- **Results JSON**: [determinism_spa90.json](determinism_spa90.json) and raw artifacts (`day90.v2`, `game.log`, `the_grand_loader.log`, `performance_patch_samples.tsv`) in `research/perf/raw/det-run-1/` and `research/perf/raw/det-run-2/`.
- **Setup**: Two identical serialized baseline runs (`fn_00515ea6 = off` / vanilla `performance_patch.ini` with all fixes `0`, `input-autosave.v2`), slowed down at day 86 and paused on exact day `90` (`clock_day90_offset = 90`, `date="1837.4.1"`), capturing live `/proc/<pid>/mem` RNG state (`0x00F0ECF0..+0x9C4` = `2500 B`, `0x00F20C14..+0xC` = `12 B`) both post-load and at day 90, plus UI-saved `day90.v2`.

| Check | `det-run-1` | `det-run-2` | Match? |
|---|---|---|---|
| **Post-load RNG** (`0x00F0ECF0` 2500 B + `0x00F20C14` 12 B) | `d9ee5dc7...`, `idx=6`, `cnt=6` | `d9ee5dc7...`, `idx=6`, `cnt=6` | **YES (`100%` exact)** |
| **Day 90 Clock** | `90` (`date="1837.4.1"`) | `90` (`date="1837.4.1"`) | **YES** |
| **Modal pauses during 90d** | `1` | `0` | **NO** |
| **Day 90 RNG state (`0x00F0ECF0`, 2500 B)** | `7cc618f3...`, `idx=397` | `af623d73...`, `idx=300` | **NO** |
| **Day 90 RNG counter (`0x00F20C14`)** | `445,933` | `447,084` (`+1,151` draws) | **NO** |
| **Day 90 Savegame (`day90.v2`)** | `23,114,202 B` (`1,813,151` lines), SHA-256 `ddff1970...` | `23,140,749 B` (`1,813,730` lines), SHA-256 `0e6467f2...` | **NO (`21,998,729` diff bytes at same offset)** |

- **Observed world-state divergence**: Both runs start from identical post-load RNG (`d9ee5dc7...`) and stop on identical `date="1837.4.1"`, yet diverge during the 90-day vanilla baseline (`unit=2068, state=1197` vs `unit=2066, state=1198`; `ENGRoyalHouseAnglified=yes` triggered only in `det-run-2`; `worldmarket_pool.ammunition=43.50702` vs `42.85858`; `+1,151` RNG draws).
- **Gate 2 verdict (`confirmed`)**: **`deterministic_for_gate2 = false`** under unpatched vanilla baseline settings (`sync_world_rng=0`, `pin_fpu=0`, default TBB worker threads). Therefore, **naive across-run byte-for-byte `.v2` save or end-of-90d RNG equality cannot serve as a pass/fail gate for `off` vs `prod` runs** unless non-determinism sources are controlled separately; Gate 2 equivalence for SESE patches like `Country_Recalculate` should rely on **in-process SESE differential shadow-compare** (comparing exact state/globals before returning to `0x00516286` on identical inputs) alongside **Unicorn bit-exact tests**.

---

## V3 Live `validate` & Paired A/B (`Country_Recalculate` Variant `(c)` `fn_00515ea6_varc`)

- **Runner & artifacts**: [run_varc_v3.py](run_varc_v3.py), [varc_ab.json](varc_ab.json).
- **Staged plugin**: `experiments/p2-hook-lab/build/v2p2.dll` (SHA-256 `7ecaa803f055b90b4c160dd9e6a9c34d535bebff2bd296373ff5944cc986af35`), staged temporarily into `experiments/perf-baseline-lab/game/mod/v2p2/` with `fn_00515ea6_varc = validate | off | prod` (all other hooks `off`) and cleanly unstaged after the suite (`experiments/perf-baseline-lab/game/mod/` verified clean).
- **`analyze_baseline.py` isolation**: Updated to skip non-`run-*`/`ctrl-*` folders before loading `run_metrics.json`; re-running `python3 research/perf/analyze_baseline.py` confirms pure P0 baseline remains `n = 5` (`544.808 ms/day` active wall median, `537.737 ms/day` per-day median).

### 1. Live 90-Day `validate` Run (`varc-validate-90d`)

- **Protocol**: `SPA 1837.1.1`, `90` days (`start_day_offset = 2`, `end_day_offset = 92`), `sample_profiler = 50 ms`, display `:95`, `fn_00515ea6_varc = validate`.
- **Observations (`confirmed`)**:
  - `the_grand_loader.log` confirms `v2p2: fn_00515ea6_varc Country_Recalculate SESE variant(c) installed (mode=validate, W^X sealed).` and `TGL_PluginInit ready (PE verified, 1 hooks installed, W^X sealed).`
  - Post-90d `/proc/<pid>/mem` check confirms `0x00515EA6` patched (`e9 55 ad 81 01 90`), blob `0x01d30000..0x01d30c4c` mapped `r-xp` (entry `0x01d30c00`), `varc_mode = 1`, `initialized = 1`, `validate_mode = 1`, `total_tags = 272`, `living_tags_bitcount = 130`, and **`mismatch_count = 0`**.
  - **`v2p2_varc_validate.log` was never created (`validate_log_exists = false`, `0` lines)**, `0` crashes, `0` dropped profiler samples (`1,477` samples; `dead_check = 0`; `sese_total_incl_blob = 10` / `0.677%` via `7` `?;0x00A7B825` + `3` dropped-`0x005089E0` `.text` helpers; `cr_total_incl = 17` / `1.151%`).

### 2. Paired Alternating A/B (`n = 3` Pairs: `off` vs `prod`, 90 Days)

- **Profiler attribution note (`confirmed`)**: `performance_patch.dll` only symbolizes `v2game.exe` `.text` (`0x...`) and loaded PE DLLs (`mN:sym`), so samples inside the `VirtualAlloc`'d `cr_sese_varc` blob (`0x01d30000..0x01d30c4c`) appear as **`?`** (`blob_mapped_incl = 0` by construction). Additionally, because `cr_sese_varc.bin` (`-O2`) uses `EBP` as a GPR outside `.text`, the profiler's walker drops frame `0x005089E0` on both blob samples (`?;0x00A7B825;...`) and its `.text` helpers (`0x00511140`, `0x004A8300`, `0x009692C0`, etc. directly above `0x00A7B825;0x00685701`). `run_varc_v3.py` (`analyze_tsv_cr`) explicitly attributes both `blob_proxy_q_a7b825` (`0` in all 3 `off` runs) and `helpers_dropped_5089e0` (`0` in all 3 `off` runs) to `sese_total_incl_blob` and `country_recalculate_total`.

| Pair | Mode | `per_day_median_ms` | `active_wall_ms_per_day` | `load1` (before -> after) | Total Samples | `0x00515EC0..0x00515F35` dead-check (incl) | SESE `.text` / `?`+helper / total (incl) | `Country_Recalculate` total (leaf / incl) |
|---|---|---|---|---|---|---|---|---|
| 1 | `ab-01-off` | `586.730` | `673.191` | `9.98 -> 10.54` | `1,184` | `2` (`0.169%`) | `11 / 0+0 / 11` (`0.929%`) | `13 / 23` (`1.943%`) |
| 1 | `ab-01-prod` | `557.234` (`-29.496`) | `627.565` (`-45.626`) | `10.09 -> 10.33` | `1,113` | `0` (`0.000%`) | `0 / 6+1 / 7` (`0.629%`) | `9 / 18` (`1.617%`) |
| 2 | `ab-02-off` | `819.139` | `884.182` | `9.82 -> 10.12` | `1,543` | `1` (`0.065%`) | `13 / 0+0 / 13` (`0.843%`) | `18 / 25` (`1.620%`) |
| 2 | `ab-02-prod` | `750.257` (`-68.882`) | `785.591` (`-98.591`) | `10.19 -> 13.03` | `1,376` | `0` (`0.000%`) | `0 / 7+7 / 14` (`1.017%`) | `10 / 27` (`1.962%`) |
| 3 | `ab-03-off` | `533.302` | `566.184` | `13.03 -> 9.45` | `1,008` | `2` (`0.198%`) | `14 / 0+0 / 14` (`1.389%`) | `15 / 23` (`2.282%`) |
| 3 | `ab-03-prod` | `517.826` (`-15.476`) | `518.452` (`-47.732`) | `9.18 -> 9.60` | `928` | `0` (`0.000%`) | `0 / 7+1 / 8` (`0.862%`) | `8 / 18` (`1.940%`) |
| **Agg (`n=3`)** | **`off` -> `prod`** | **`586.730 -> 557.234`** | **`673.191 -> 627.565`** | noisy (`~9.2..13.0`) | `3,735 -> 3,417` | `5 (0.134%) -> 0 (0.000%)` | `38 (1.017%) -> 29 (0.849%)` (`0` `.text` + `20` `?` + `9` helper) | `46 / 71 (1.901%) -> 27 / 63 (1.844%)` |

- **Verdict (`confirmed`)**: Zero mismatches across all 90 days in `validate` (`mismatch_count = 0`); in all 3 `prod` runs `0x00515EA6` stayed patched (`site_bytes = e9 55 ad 81 01 90`, `living_tags_bitcount = 129`, `mismatch_count = 0`). Under `prod`, vanilla `.text` SESE (`0x00515EA6..0x00516285`) + dead-tag-check hits dropped to `0`, while total SESE execution in the `VirtualAlloc` blob (`20` `?;0x00A7B825` + `9` dropped-`0x005089E0` helper hits) accounted for **`29 / 3,417` (`0.849%`)** vs `38 / 3,735` (`1.017%`) in `off` (and `Country_Recalculate` total `71 / 3,735 = 1.901%` vs `63 / 3,417 = 1.844%`). All 3 pairs showed lower `per_day_median_ms` (`-15.476` to `-68.882 ms/day`) and `active_wall_ms_per_day` (`-45.626` to `-98.591 ms/day`) with **no regression** (end-to-end wall deltas remain dominated by host load variation `load1 = 9.18..13.03` relative to a ~`0.17%` / ~`1 ms/day` `Country_Recalculate` SESE share saving).

