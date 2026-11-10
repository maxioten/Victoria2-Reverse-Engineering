# Performance plan

The engine already has a measured profile in
[`Engine/performance-profile.md`](../../../Engine/performance-profile.md).
This document turns those measurements into an implementation order.

The goal is not “decompile 100 % and then optimize”. The goal is:

1. get a buildable executable;
2. make the measured hot paths editable;
3. optimize them with deterministic, benchmarked changes;
4. keep matching decompilation as a parallel track for functions that need it.

## Measured budget

Vanilla 1836, max speed, ~196 ms per game day:

| Block | ms/day | Share |
|---|---:|---:|
| Frame outside the tick | ~90 | 45 % |
| — ENet poll in `select` | ~46–51 | 25 % |
| — `AI_FrameUpdate` | ~24–26 | 12 % |
| — `Render_MapFrame` | ~14.5 | 7 % |
| `WorldMarketUpdate` | ~23 | 11 % |
| `Country_PrePass` | ~27 | 13 % |
| `Country_DailyUpdate` own | ~20 | 10 % |
| Market/goods distribution | ~8.7 | 4 % |
| AI casus belli scans | ~11 | 5 % |
| Events | ~4 | 2 % |

The profile also identifies the data layouts behind the cache misses:

- **Relations**: `country+0xBE8` is an array of 683 pointers to separately
  allocated objects; ~466,000 relations. Several daily loops read one or two
  fields from each.
- **POPs**: linked lists, objects at least `0x280` bytes, next at `+0x27C`.
- **Living countries**: a `vector<CCountry*>` at `world+0xADC`.
- **Allocator**: ~1.7 ms/day; the cache misses come from access patterns, not
  from `_malloc`.

## Order of work

### 1. Benchmark harness first

Before touching code:

- fixed save, fixed game version, fixed mod;
- measure 30 game days at max speed;
- record wall time, CPU time, instructions, cache misses;
- repeat 5 times and report median/p95;
- keep the original executable as the baseline.

No optimization is accepted without a before/after measurement.

### 2. ENet poll

The profile attributes ~46–51 ms/day to the ENet `select` poll, even in single
player. The first experiment is to detect single-player and skip or shorten the
poll.

Acceptance:

- same save, same 30 days;
- multiplayer still works;
- no change in save hash or RNG state;
- measured reduction in day time.

### 3. Relations layout

The largest data-layout target:

- replace 683 separately allocated relation objects per country with a
  contiguous array or a structure-of-arrays;
- or precompute the fields read by each daily loop into a compact per-country
  summary;
- keep the original object identity where pointers escape.

Start with the loops that only read `+0x2C`, `+0x30`, `+0x34`, `+0x50`,
`+0xA8`. Measure cache misses before/after.

### 4. Living-country list

`AI_TargetScan` and `Country_PrePass` walk tags, including dead ones. Use the
living-country vector and verify that dead tags with set relation fields still
produce the same result.

### 5. POP iteration

POPs are linked lists. Replace the hot traversals with:

- contiguous storage per type, or
- an intrusive vector plus a stable index;

while preserving the original order used by RNG and daily updates. This is
where determinism matters most: do not reorder POP processing.

### 6. Market batching

`WorldMarketUpdate` and `ProcessMarketAndGoodsDistribution` repeatedly walk
countries and POPs. Batch by good/type, avoid repeated virtual calls and keep
the arithmetic order identical.

### 7. AI budget

`AI_FrameUpdate` already has a per-frame budget. Profile the decision loop,
cache target scans, and avoid rescanning casus belli that did not change.

### 8. Render

`Render_MapFrame` is ~7 % of the day. Lower priority:

- batch D3D9 state changes;
- texture atlases;
- fewer draw calls;
- avoid redundant map updates.

### 9. Compiler-level wins

A separate `perf` build can use:

- Visual Studio 2022;
- `/O2 /GL /LTCG`;
- PGO with a fixed save;
- `/arch:SSE2` where the original already requires it.

This build intentionally does not match the original bytes. Keep it separate
from the `match` build.

## Two build modes

| Mode | Purpose | Compiler/flags | Gate |
|---|---|---|---|
| `match` | source reconstruction and regression | original MSVC/VC10 flags | `reccmp`/`objdiff` |
| `perf` | performance experiments | modern MSVC, LTCG, PGO | correctness + benchmark |

The `match` build is the reference. The `perf` build is where optimizations
land. A change that alters game state is rejected even if it is faster.

## Correctness gates

Every performance change must preserve:

- save hash after N days;
- RNG sequence and draw count;
- POP counts by type and province;
- country totals (money, goods, manpower);
- event/decision order;
- multiplayer compatibility where applicable.

Use the existing contracts in `research/docs/contracts/` as oracles.

## Matching/decomp strategy

For performance, a full matching decompilation is not a prerequisite. Use a
hybrid:

- matching source for the hot modules you will edit;
- lifted C from pcrecomp for cold functions;
- replace lifted functions incrementally as they become hot or necessary.

The matching track uses:

- `rebrew` with an `msvc-10.0` profile if the compiler is confirmed as VC10;
- `reccmp` annotations for functions, vtables and data;
- `objdiff` for object-level progress.

## Milestones

| Milestone | Deliverable |
|---|---|
| M0 | benchmark harness and baseline |
| M1 | ENet poll experiment with measurement |
| M2 | relations layout prototype |
| M3 | living-country list |
| M4 | POP iteration prototype |
| M5 | market batching |
| M6 | full build with `perf` mode |
| M7 | 30-day and 1-year determinism runs |

Each milestone is a separate PR with its own before/after JSON. No “it feels
faster” claims.
