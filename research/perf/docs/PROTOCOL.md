# Benchmark protocol

## Goal

Measure the cost of a fixed number of game days on the original executable and
on an experimental build/patch, with the same save, mod and machine.

The primary metric is **wall time per game day**. CPU time and peak RSS are
secondary; they help distinguish a real win from a scheduling artifact.

## Fixed inputs

Record these once per campaign:

| Field | Example |
|---|---|
| Executable SHA-256 | `62d48c…d6648` (original) |
| Save SHA-256 | hash of the exact `.v2` save |
| Game version | 3.04 |
| Mod and version | vanilla / GFM / TGC, exact commit |
| Settings | max speed, no pause, same resolution, same audio |
| Machine | CPU, RAM, OS, Wine/Windows version |
| Renderer | D3D9 / Wine D3D9 / DXVK, exact version |

Do not change mod, save, resolution or background load between baseline and
experiment.

## Run procedure

1. Start the game and load the fixed save.
2. Pause on **day 1** at max speed.
3. Start the timer:

   ```bash
   python research/perf/tools/run_benchmark.py \
     --label baseline \
     --save-hash <sha256> \
     --notes "vanilla 1836, 30 days"
   ```

4. Unpause and let exactly **30 game days** pass.
5. Pause on day 31 and press Enter in the timer.
6. Save the game and record the save hash.
7. Repeat at least **5 times** per label; discard the first warm-up run if the
   first day includes loading or shader compilation.

`run_benchmark.py` records wall time, process CPU time, peak RSS and sample
count. It does not read the game date; the operator is responsible for starting
and stopping on the same day boundary.

## Metrics

| Metric | Formula |
|---|---|
| wall ms/day | `wall_s * 1000 / 30` |
| CPU ms/day | `cpu_s * 1000 / 30` |
| peak RSS | max sampled RSS |
| save hash | after the run, must equal the baseline for the same actions |

Report median and p95 across runs, not a single sample.

## Acceptance

A performance change is accepted only if:

- median wall ms/day is lower than baseline by a margin larger than run-to-run
  noise;
- p95 does not regress;
- save hash, RNG sequence, POP counts and country totals match the baseline;
- multiplayer still connects and services packets (for network changes);
- no new crash or hang appears in a 1-year run.

## Caveats

- Wine and D3D9 add noise. Pin the Wine/DXVK version and close other apps.
- Rendering is part of the frame budget. A change that only affects the tick
  should be measured with the same camera position and map view.
- The timer is manual. For automated date detection, add a process-memory
  reader for the calendar and mark it as a separate experiment.
- The first run after loading a save is a warm-up; do not use it for the
  baseline median.
