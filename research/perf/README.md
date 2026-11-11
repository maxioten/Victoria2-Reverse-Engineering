# Performance baseline and experiments

This directory contains the measurement protocol and the first two performance
experiments for Victoria II:

1. **ENet poll in single player**: the game spends ~46–51 ms per game day
   blocked in `select()` even when no network peer exists.
2. **Contiguous relations / SoA**: ~466,000 separately allocated relation
   objects cause cache misses in several daily loops.

The starting point is the measured profile in
[`Engine/performance-profile.md`](../../Engine/performance-profile.md) and
[`Engine/network.md`](../../Engine/network.md).

## Contents

| Path | Purpose |
|---|---|
| [`docs/PROTOCOL.md`](docs/PROTOCOL.md) | fixed-save benchmark protocol |
| [`tools/run_benchmark.py`](tools/run_benchmark.py) | manual start/stop timer with CPU/RSS sampling |
| [`tools/parse_results.py`](tools/parse_results.py) | aggregate runs, median/p95, baseline vs experiment |
| [`schema/benchmark.schema.json`](schema/benchmark.schema.json) | JSON schema for a run |
| [`experiments/enet-timeout-zero/`](experiments/enet-timeout-zero/) | binary-patch experiment for the ENet wait |
| [`experiments/relations-soa/`](experiments/relations-soa/) | layout design, microbenchmark and native 683 × 683 fixture |
| [`experiments/enet-wait-sample/`](experiments/enet-wait-sample/) | direct EIP-sampling measurement of the ENet socket wait |

## Rules

- The game executable, saves and assets stay local. This directory publishes
  scripts, protocol and aggregate results only.
- No optimization is accepted without a before/after measurement on the same
  machine and save.
- A faster build that changes save hash, RNG sequence, POP counts or country
  totals is rejected.
- Binary patches are experimental and always applied to a copy with a
  hash-checked original.

## Quick start

```bash
# One run: load the fixed save, pause at day 1, then run:
python research/perf/tools/run_benchmark.py \
  --label baseline --save-hash <sha256> --runs 1

# Aggregate five runs per label:
python research/perf/tools/parse_results.py \
  --input research/perf/benchmarks/runs.jsonl \
  --baseline baseline --experiment enet-timeout-zero
```
