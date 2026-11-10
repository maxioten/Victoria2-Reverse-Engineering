# Benchmark tools

## `run_benchmark.py`

Manual start/stop timer for a fixed save. It samples the game process CPU and
RSS while the run is active.

```bash
python -m pip install psutil
python research/perf/tools/run_benchmark.py \
  --label baseline \
  --process v2game.exe \
  --save-hash <sha256> \
  --days 30 \
  --runs 1 \
  --notes "vanilla 1836, max speed, 1280x720"
```

The operator:

1. loads the fixed save;
2. pauses on day 1;
3. presses Enter to start;
4. unpauses and lets 30 game days pass;
5. pauses on day 31 and presses Enter to stop.

The script appends one JSON line per run to
`research/perf/benchmarks/runs.jsonl`.

On Linux/Wine the process name may not be `v2game.exe`; pass `--process wine` or
`--pid <pid>` if needed.

## `parse_results.py`

```bash
python research/perf/tools/parse_results.py \
  --input research/perf/benchmarks/runs.jsonl \
  --baseline baseline \
  --experiment enet-timeout-zero \
  --csv research/perf/benchmarks/summary.csv
```

It reports count, median and p95 for wall ms/day, CPU ms/day and peak RSS, plus
the delta of the experiment against the baseline.

```bash
python research/perf/tools/parse_results.py --selftest
```

runs a synthetic check without a game.

## Data format

See [`../schema/benchmark.schema.json`](../schema/benchmark.schema.json). The
run file is JSONL; a JSON list is also accepted.

## Limitations

- The timer does not read the game calendar. The operator must stop on the same
  day boundary for every run.
- CPU time includes Wine and rendering; keep the environment fixed.
- A single run is not evidence. Use at least five runs and report median/p95.
