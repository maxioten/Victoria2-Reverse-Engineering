# Experiment: contiguous relations / SoA

## Storage correction (2026-11-11, static)

`country+0xBE8` is not a fixed array: it is a **`std::vector<Relation*>`**
with begin/end/capacity at `+0xBE8/+0xBEC/+0xBF0`. It grows to 683 entries
via `push_back` (reallocation through the shared grow helper `0x00A513F0`,
which copies pointers, never objects). All examined readers reload
`[country+0xBE8]` per access, so the moving pointer array is safe; the
pointed-to objects never move. The "466,489 allocations" figure stands
(count getter returns `0x2AB` = 683), but the container finding below
replaces "fixed array" wherever it appears in this document.

## Problem

Each of the ~683 country slots targets a separately allocated 0xAC-byte
relation object (vtable `0x00E34C3C`, type tag `0x18D` at `+0x04`), so a full
matrix is about **683 × 683 = 466,489** allocations. Several daily loops read
one or two fields from every pair; the pointer chase is the cache-miss source
measured in
[`Engine/performance-profile.md`](../../../../Engine/performance-profile.md).

Hot loops and fields:

| Function | Address | Fields read |
|---|---|---|
| `Country_Recalculate` | `0x00515490` | `+0x08 +0x0C +0x20 +0x24 +0x28 +0x34 +0x38 +0x70` (confirmed; also writes `+0x38 +0x71`) |
| `FUN_00522CF0` (date guard, ex-market capacity) | — | no relation contact (see correction below) |
| `CountryRelation_DailyPurge` | `0x0092E290` | `+0x50 +0xA8 +0x2C +0x30 +0x28 +0x20` (reads; frees subordinate list nodes, no relation stores) |
| `Country_PrePass` | `0x00508590` | `+0x2C +0x30` (reads; also writes `+0x40 +0x44 +0x48 +0x4C`) |
| `AI_TargetScan` | `0x0084B0F0` | `+0x34 +0x3C` (reads; no writes) |

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

## Open questions — answered 2026-11-11 (static, v2game.exe 3.04)

All addresses are VAs (base `0x00400000`). Verified by disassembly and by
full-`.text` scans (E8-target scan, immediate scan, proximity scan).

### 1. Reallocated or replaced after population? No (objects); yes (pointer array)

- Single construction path: `operator new(0xAC)` + constructor `0x0092D490`
  (vtable `0x00E34C3C`, `[+0x04]=0x18D`) at `0x005047F2`, inside creator
  `0x005047C0`, itself called once from a pair loop at `0x0055C21D`. The
  constructor is called from exactly one site; the creator from exactly one
  site (full-`.text` E8 scans).
- Each object is appended via `push_back` into the `+0xBE8` vector. Growth
  reallocates the **pointer array** (`0x00A513F0`, pointer copy
  `mov edx,[ecx+esi*4]` / `mov [eax],edx`); objects never move.
- No vector erase/pop exists: zero `sub [X+0xBEC],4` in `.text`.
- No individual delete of array elements: zero `operator delete`
  (`0x00AAE91B`) calls within 200 bytes of any `+0xBE8/BEC/BF0` reference in
  `.text` (33,734 delete sites checked by proximity scan).
- The country member-destructor (`0x004F8340`) never touches `+0xBE8/BEC`.

So: objects are created once, never freed individually, never replaced in
their slots. The pointer array may move during growth; every examined reader
reloads `[country+0xBE8]` per access, so that is safe.

### 2. Pointers stored anywhere else? No aliasing owners found

- `CountryRelation_DailyPurge` (`0x0092E290`) is called per relation
  (`0x0050AC3A`: `array[idx]` → push → call) and frees **subordinate list
  nodes** from intrusive lists rooted at `[rel+0x50/0xA8/0x2C/0x30/0x28]`
  (unlink + `operator delete` + count--). It never frees the relation object
  and never writes array slots: no dangling slots are created here.
- The 0xAC copy helper (`0x00504700`) is a *partial* copy (lists at
  `+0x0C/+0x54` deep-copied, plain fields `+0x04/+0x08/+0x9C/+0xA0/+0xA4`;
  vtable and most data fields untouched): it is not a relation duplicate.
  Its two callers copy into a stack temporary (`0x00519F80`, PrePass path)
  and into the inline container at `country+0xBF8` (`0x00503020`, a separate
  vector 8 bytes past the relations vector). Neither aliases relation
  objects.
- Purged nodes carry vtables and `next/prev` at `+0x08/+0x04`; the purge
  passes relations only transiently (thiscall `ECX`).

Residual risk (stated, not blocking layout A): a full copy of a country
object graph was not audited; if one exists it would duplicate the vector
shallowly by construction. No such path was found.

### 3. Hot fields written by the same loops? Deferred — SoA-only

Layout A keeps the same objects and the same code, so write patterns are
irrelevant to it. This question stays open for layout B (SoA cache
invalidation) and must be answered per loop before B.

### 4. Lifetime across save/load: rebuilt at load, values runtime-only

- The matrix is populated by the single fill path above during scenario
  setup/load (pair loop `0x0055C216` → creator per element).
- The save file carries no per-pair relation matrix: `diplomacy=` holds only
  `vassal`/`alliance` entries, per-country `influence=` blocks hold sphere
  influence, and the keyword `relation` is absent. Pair-field values are
  runtime state, rebuilt to loader defaults on every load.
- Teardown of individual relations was not found (see 1); the backing store
  for layout A must therefore outlive the scenario and needs no per-object
  free path — but this must be confirmed behaviorally.

### Layout-A verdict

Feasible with the facts above: back all 0xAC objects contiguously at fill
time, keep the `std::vector<Relation*>` mechanics (including growth
reallocation of the pointer array) intact, construct in place with
`0x0092D490`, never free individually. Acceptance stays behavioral
(unchanged 30-day save hash, same relation values after load/daily/save,
fixed-save protocol) because save-key coverage of pair fields is unmapped
statically.

## Write sets — static, 2026-11-11 (for SoA invalidation)

Direct stores to relation objects per hot loop (register-attributed;
instruction addresses given so every claim is checkable). Everything else
found in these functions targets stack, other objects, fresh allocations, or
subordinate list nodes.

| Loop | Relation writes | Relation reads (confirmed) |
|---|---|---|
| `Country_PrePass` `0x00508590` | `+0x40`, `+0x44` (timestamp pair at `0x50874B/0x50874E`); `+0x48`, `+0x4C` (thiscall `0x0092F570`, clamped accumulator) | `+0x2C`, `+0x30`, `+0x40`, `+0x08`, `+0x0C` (list walks) |
| `Country_Recalculate` `0x00515490` | `+0x38` (`=0` at `0x5161B3`, after deleting the owned `+0x38` child via its vtable dtor at `0x5161BC`); `+0x71` (`=1` at `0x5161AF`) | `+0x08`, `+0x0C`, `+0x20`, `+0x24`, `+0x28`, `+0x34` (via `ECX` at `0x51615B`), `+0x38`, `+0x70` |
| `AI_TargetScan` `0x0084B0F0` | none (two relation loads, both read-only) | `+0x34` (`0x84B299`), `+0x3C` (`0x84B3BD`) |
| `CountryRelation_DailyPurge` `0x0092E290` | none to the relation (frees subordinate list nodes only) | `+0x50`, `+0xA8`, `+0x2C`, `+0x30`, `+0x28` (+0x20 in tail) |
| `FUN_00522CF0` | none — **correction**: this function is a 29-instruction date-guard helper (`[esi+0xE9C]` vs world clock, zeroes `[eax]/[eax+4]`), with no relation contact. The `+0x34` market-capacity read attributed to it was not found here or at its sampled caller `0x00831CF9` (FP market code); that attribution needs re-verification. Its 6 callers: `0x487483 0x5FE67E 0x6025BB 0x60C695 0x60CA7B 0x831CF9`. |
| `+0x34` writer map | reset-only: constructor tail (`0x0092D590` → reset `0x0092D620`, zeroes `+0x20/+0x24/+0x28/+0x34/+0x3C/+0x2C/+0xA8/+0x38/+0x30`), country-wide reset loop (`0x00504340`), reset callers `0x00517250`/`0x00518620` (war/peace-transition shape). No nonzero writer in: 5 hot loops, ctor, reset, fill loop, purge, all 6 vtable methods, `0x0092F570`. Dynamic: [`values_watch.py`](values_watch.py) read `+0x34` of 8 sampled relations at every calendar tick for 30 live SP days (Carlist war active): 240/240 zero, 0 transitions |

SoA consequences:

- Cacheable for reads with invalidation: `+0x40/+0x44/+0x48/+0x4C`
  (PrePass, every pass), `+0x38/+0x71` (Recalculate).
- Never cached: `+0x38` is an owned-child pointer (deleted + nulled in
  Recalculate); caching it would dangle.
- Read-mostly, safe to cache with no invalidation found: `+0x08`, `+0x0C`,
  `+0x20`, `+0x24`, `+0x28`, `+0x2C`, `+0x30`, `+0x34`, `+0x3C`, `+0x50`,
  `+0x70`, `+0xA8` — none of the five loops stores to them. (Callee-side
  effects through vtables were scoped out except `0x0092F570`; a full
  callee audit is still open.)
- `+0x34` is written nowhere in these five loops; live watch
  ([`values_watch.py`](values_watch.py), needs `client.py` from
  `../enet-wait-count/` alongside it; bridge token stays local) shows it
  constant 0 across 30 SP days — cache as reset-dominated, refresh on the
  reset paths above.

## Open questions (remaining)

- Exact teardown path of the matrix at scenario exit (bulk free vs leak).
- A full country deep-copy path, if one exists, and what it copies.
- True owner of the `+0x34` market-capacity read (mis-attributed to
  `0x00522CF0`); the field itself is reset-dominated per the watch above.
