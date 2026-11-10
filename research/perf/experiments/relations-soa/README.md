# Experiment: contiguous relations / SoA

## Problem

`country+0xBE8` is an array of 683 pointers, one per country tag. Each pointer
targets a separately allocated relation object, so a full matrix is about
**683 × 683 = 466,489** allocations. Several daily loops read one or two fields
from every pair; the pointer chase is the cache-miss source measured in
[`Engine/performance-profile.md`](../../../../Engine/performance-profile.md).

Hot loops and fields:

| Function | Address | Fields read |
|---|---|---|
| `Country_Recalculate` | `0x00515490` | `+0x08 +0x0C +0x20 +0x24 +0x28 +0x34 +0x38 +0x70` |
| `FUN_00522CF0` (market capacity) | — | `+0x34` |
| `CountryRelation_DailyPurge` | `0x0092E290` | `+0x50 +0xA8 +0x2C +0x30 +0x28 +0x20` |
| `Country_PrePass` | `0x00508590` | `+0x2C +0x30` |
| `AI_TargetScan` | `0x0084B0F0` | `+0x34 +0x3C` |

The loops also write other countries (`Country_PrePass` moves money into
`other+0xE78`), so a read-only summary is not enough for every caller.

## Layout options

### A. Contiguous backing store, keep the pointer array

Allocate one block of 466,489 relation objects and make each
`country+0xBE8[tag]` point into it:

```text
Relation *block = malloc(683 * 683 * sizeof(Relation));
country[i]->relations[j] = &block[i * 683 + j];
```

Advantages:

- the pointer array and every existing dereference stay valid;
- no loop needs to change;
- one allocation instead of 466,489;
- adjacent tags become adjacent in memory.

Risks:

- the block must never be reallocated while pointers escape;
- constructors/destructors and copy paths must be updated;
- relation objects may be created lazily; the backing store needs a lifetime
  rule.

This is the first prototype because it changes allocation, not semantics.

### B. Hot-field SoA summary

Keep the original relation objects for writes, and add a read-only SoA cache:

```text
int32_t rel_f2c[683 * 683];
int32_t rel_f30[683 * 683];
int32_t rel_f34[683 * 683];
int32_t rel_f50[683 * 683];
...
```

Populate after load and after any write that changes a cached field. Use it only
in loops that read the field and do not mutate the relation.

Advantages:

- no pointer chase in the hot loop;
- smaller cache footprint if only a few fields are read;
- can be introduced loop by loop.

Risks:

- cache invalidation must be exact; a missed write produces stale values;
- duplicated state increases save/load and copy complexity;
- field semantics must be confirmed before caching.

### C. Full SoA migration

Move the relation storage itself to SoA and rewrite every access. Highest
potential, highest risk; only after A and B are measured.

## Microbenchmark

[`microbench.c`](microbench.c) simulates 466,489 records and reads five fields
with a shuffled country order. It compares:

- `ptrs`: separately allocated objects + pointer array;
- `aos`: one contiguous array of structs;
- `soa`: eight contiguous arrays, one per field.

Build and run:

```bash
./run_microbench.sh
```

Results on the development machine (synthetic, not the game):

| Layout | ns/pair (range across repeated runs) |
|---|---:|
| `ptrs` | 9.8–13.3 |
| `aos` | 5.6–9.7 |
| `soa` | 4.0–7.9 |

This is a **layout upper-bound probe**, not a game benchmark. The synthetic
runs are noisy and the SoA result was not consistently better than AoS; the
range only shows that pointer chasing can be more expensive. The engine may
have different field widths, aliasing and write patterns.

## Native 683 × 683 fixture

[`fixture.c`](fixture.c) builds the full matrix in four layouts and runs the
same deterministic daily pass on each:

| Layout | Storage |
|---|---|
| `ptrs` | 466,489 separately allocated objects + pointer array (baseline) |
| `aos` | one contiguous block, indexed directly |
| `aos_ptr` | the same block reached through the original pointer array (layout A) |
| `soa` | eight contiguous arrays, one per field |

The pass reads five hot fields, writes one field on the current pair and one on
a neighbouring country, and uses a shuffled country order. It checks:

- identical field values after the pass (full comparison and FNV-1a digests);
- pointer arrays are byte-identical before and after (no invalidation);
- layout A keeps `relations[i] == &block[i]` and adjacency;
- canaries before and after every allocation survive, including the 466,489
  guarded per-pair allocations of the baseline.

Build and run:

```bash
./run_fixture.sh
```

The script first runs an ASan/UBSan build with `--correctness-only`, then an
optimized build with `--json`; the JSON is written to `fixture-results.json`
(ignored by git). Timing is ns per pair, median and p95 over rounds, with the
layout order rotated every round.

Results on the development machine (synthetic, not the game; the host was
loaded, so absolute values are only indicative):

| Layout | ns/pair median (range of 3 runs) |
|---|---:|
| `ptrs` | 28.0 (26.4–40.5) |
| `aos` | 10.5 (10.5–12.6) |
| `aos_ptr` | 12.6 (12.2–17.6) |
| `soa` | 7.0 (6.9–10.0) |

The ordering is stable across runs: the pointer chase is ~2.1–2.7× slower than
the contiguous block, and the SoA pass is ~1.5× faster than AoS. The `aos_ptr`
result shows the cost of keeping the original pointer array. This fixture
validates layout mechanics and gives an upper bound; it does not prove a game
speedup.

## Prototype plan

1. Native fixture: done in [`fixture.c`](fixture.c); it checks values, pointer
   identity, pointer stability and canaries for all four layouts.
2. Implement layout A (contiguous backing store) behind a compile-time switch.
3. Run the existing relation loops against A and compare:
   - return values;
   - memory writes;
   - relation pointer identity;
   - iteration order.
4. Measure with the fixed-save protocol.
5. Only then prototype B for `Country_PrePass`, `AI_TargetScan` and
   `Country_Recalculate`.

## Acceptance

- Same 30-day save hash and RNG sequence.
- Same relation values after load, daily update and save.
- No pointer invalidation or use-after-free in the native fixture.
- Lower median wall ms/day than baseline, with p95 not worse.
- No change in multiplayer state exchange.

## Open questions

- Are relation objects ever reallocated or replaced after `country+0xBE8` is
  populated?
- Are relation pointers stored anywhere else (vtables, caches, save code)?
- Are the hot fields written by the same loops that read them?
- What is the exact lifetime of the 683 × 683 matrix across save/load?

These must be answered before changing allocation.
