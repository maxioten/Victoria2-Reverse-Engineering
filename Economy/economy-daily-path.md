# Economy: the daily path

What the economy does every day, how its per-pop loops walk memory, and three corrections to earlier
notes.

Source: research of October 2026, static reading plus a sampling profiler on TGC 1836
and 1848–1855. Builds on [economy-market.md](economy-market.md). Marks: **[C]** read in the code,
**[I]** inferred, **[M]** measured.

## Corrections to earlier notes

1. **`FUN_006859C0` is `DayTick`, the daily tick, not `Economy_ProcessMonthlyTick`.** It runs once per
   game day (`Update_World_and_Advance_Time` adds 24 hours and calls it at `0x00683AB1`). **[C]** See
   [../Engine/daily-tick.md](../Engine/daily-tick.md).
2. **`EconomyManager_UpdateFull` (`0x0068BF00`) is not the daily update.** Its only caller is
   `Game_FinalizeLoadAndEnterGameplay` (`0x0066321D`): it is the full rebuild done once after loading,
   which is where its five `Economy_Update(..., 0..4)` passes come from. The daily path is
   `DayTick` (`0x00685F7E`) -> `Economy_Update` (`0x00489990`). **[C]**
3. **The price bounds are 2^15 fixed point.** The clamp loads `kPriceMinFactor` with
   `FLD qword [0x00E45C30]` at `0x00482C46`. **[C]**

   | constant | VA | stored value | meaning |
   |---|---|---|---|
   | `kPriceMinFactor` | `0x00E45C30` | 6554.1 | 0.2 × 32768 + 0.5 |
   | `kPriceMaxFactor` | `0x00E45C28` | 163840.5 | 5.0 × 32768 + 0.5 |

   A change to 0.1 / 10.0 must write 3277.3 / 327680.5; writing 0.1 / 10.0 directly makes the bounds
   32768 times too small.

## Daily path **[C]**

```text
DayTick
  Economy_Update (0x00489990)                        1 call/day
    WorldMarketUpdate (0x00484060)                   ~23 ms/day inclusive, 0.2 ms own [M]
      for country: for state: for factory: Factory_MarketUpdate (0x00482FF0)
      per country: Market_AddRealDemand (0x00487410), then
                   Market_UpdateCountryPops (0x00485E40)        CALL at 0x0048468F, ~15 ms/day [M]
      0x00484309: CALL UpdateTimeThrottle            (can render a frame mid-market)
    ProcessMarketAndGoodsDistribution (0x004808D0)   ~8.7 ms/day
    Market_PostProcess (0x00488080)                  ~3.3 ms/day
```

`Economy_CalculateDistribution` (`0x00520150`) has 24 callers (load, UI, diplomacy, events); during play
it runs daily inside the TBB `parallel_for` `ProcessPopStatisticsFunctor` (`FUN_0068F4C0`, see
[../Engine/threads.md](../Engine/threads.md)).

## How the per-pop loops walk memory **[C]**

Traversal position and descriptive POP dimensions are not unique identities. See
[Entity identity](../Engine/entity-identity.md) for current IDs and cross-transition limits.

`Market_UpdateCountryPops(market, country, ...)` (four stack arguments; `market` = `EDI`, `country` = `EBX`
at the call):

```text
for each province id in country+0x9D8 .. +0x9DC:
    province = world+0xACC[id]
    for each pop type id t in market+0x804 .. +0x808:
        for pop = *(province+0x194 + t*16); pop; pop = pop+0x27C:     ; linked list per (province, type)
            reads pop+0x58 (size), +0x68 (type), +0x1B0/+0x1B4, +0x1D4 -> [+0xB0, +0xE8], ... +0x27C
            FUN_004DD3C0 (artisans/needs), FUN_00485390 (needs purchase, x3: life/everyday/luxury) ...
```

The same `province+0x194[type]` / `pop+0x27C` walk appears inline in `ProcessMarketAndGoodsDistribution`
(per pop: `CALL FUN_0095EB00` at `0x00481860`, pop in `ESI`, next in `EAX`) and in `DayTick`'s per-province
pass (`FUN_004B9C60`, province in `ESI`, called at `0x00685B09`).

Every pop is a separate allocation and the next one is only known once the current one has been read,
so these loops are **one dependent cache miss per pop**: the hottest sampled instructions sit right after
the first read of each pop (`0x004853D7`, `0x004869F6`, `0x00486A1C`, `0x004B9C9B`, `0x0095EB63`). **[M]**

## Shared state in the market loops **[C]**

- `WorldMarketUpdate` and `Market_UpdateCountryPops` rewrite static scratch buffers per country and per
  pop (`0x013F24F4`…`0x013F25A8`, e.g. a `memset` of `0x013F24B0` per pop).
- The per-state work draws from the Mersenne Twister: `FUN_004A46E0` -> `FUN_004A5170` ->
  `FUN_009B7950` -> `Rng_Next`.
- Accumulations clamp at 99 999 (`Goods_MultiplyClamp99999`, `Clamp(…, 0xC34F8000)`), so their order
  matters.

## Fixed-point arithmetic cost

The economy's 2^15 fixed-point math goes through the CRT helpers `__alldiv` (`0x00AC02A0`) and
`__allmul` (`0x00AC9F20`): ~4 and ~2 ms/day of own time in 1848–1855, about **630 k 64-bit divisions a
day**. 61 % of `__alldiv`'s samples sit right after its two `DIV`s on the 32-bit-divisor path; the
slow path is negligible. Each division costs ~6.7 ns on a current CPU (micro-benchmark of the same
routine), so the cost is the number of divisions, not a slow helper. **[M]**

## Stockpiles **[C]**

`Stockpile_SubtractArtisanFactory` (`0x0047DCA0`): a byte per good at `holder+0x08+good` says whether the
good is present; the amounts are a vector of int64 at `holder+0x48/+0x4C`; the good count is
`g_goodsCount` (`0x012587F4`). Missing entries are created with the negated amount. `ScaledDotProduct`
(`0x0047E3E0`, ~58 callers) and `Buffer_ScaleValuesInRange` (`0x0047DE60`, ~53 callers) are generic, not
market-specific.
