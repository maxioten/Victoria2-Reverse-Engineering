# Production identity and clearing

This note separates producer identity and inventory from market clearing. It is
for readers interpreting native economy fields, not a complete settlement model.

## Target and evidence

Supported executable: **Victoria II: Heart of Darkness 3.04, English, x86**,
SHA-256 `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
VAs use preferred image base `0x00400000`: **VA = RVA + 0x00400000**;
runtime address = loaded module base + RVA. Neither is a file offset.

Sources are Smedley commit **`a87832e6196168b6b6ac82701dc3f1dd95732848`**:
[telemetry evidence][telemetry] and [mapping catalog][catalog]. Runtime/UI/save
correlations below are historical, narrow observations retained in that source,
not fresh live tests or acceptance of a current telemetry implementation.
The historical runtime evidence lacks exact-built-commit provenance.
Local read-only binary checks confirm the static anchors; they do not verify
runtime transfer outcomes or promote complete object layouts.

## RGO capacity and owner modifier

`CProvince` (called `CMapProvince` in the existing CSV) `+0x1AC` is **RGO
employment capacity**, not a copy of total population. `+0x1A8` remains the
population field. Historical Berlin fruit capacity is 195625 and Görlitz coal
capacity 60000; employed farmers/labourers are respectively 110896 and 54730.

The owner-modifier UI calculation at **RVA `0x00340F8D` / VA `0x00740F8D`**
uses this chain:

| Input | Native path |
| --- | --- |
| State | `province+0x188 -> CState` |
| Owner POP type index | `CProductionType+0xF0 -> owner type+0x28` |
| Owner population | `*(state+0x118)[type_index]`, 32-bit entries |
| Denominator | Total state RGO capacity at `state+0xC8` |

For positive capacity, the 2^15 fixed-point ratio is
`(owner_population * 32768) / state_RGO_capacity`, with native integer rounding.
The code guards zero capacity. Historical ratios `4275/457875` and `848/60000`
give raw 305 and 463, matching the narrow UI correlations. VA `0x00740F39`
loads the recipe's owner-type pointer; VAs `0x00740F93`–`0x00740FA8` load the
state, denominator and indexed population. RGO output helper **RVA
`0x000DE350` / VA `0x004DE350`** multiplies efficiency, throughput, recipe base
output and record size, shifting 15 bits after each multiplication.

## Factory identity under ownership transfer

Historical paused transfers establish two limited topology outcomes:

| Case | Observed contract |
| --- | --- |
| No duplicate factory type | Transferring SAX provinces 558/559/560 to PRU preserves recipient state 757, removes source state 907 and moves the unchanged level-1 fabric node immediately, **without a daily tick**. Region key `SAX_558` is unchanged. |
| Equal-level duplicate fabric nodes | The recipient node survives with its subsidy flag and budget 1000.00; the source node, budget 931.91, is removed. |

This is not a general merge rule: unequal levels and merges above eight distinct
types remain unresolved. A node pointer is an in-process identity, not a durable
cross-load identifier; region identity alone does not identify an owner-specific
state portion. Factory budget is `CStateBuilding+0x150` (/32768000), subsidy
flag `+0x180`; neither should be inferred from the province owner alone.

## Clearing values are not bounded sales fractions

| Object | Field | Interpretation |
| --- | --- | --- |
| Artisan economy at `CPop+0x1D4` | `+0xD0 / +0xD8` | Domestic/export clearing values, /32768; **not bounded fractions**. Historical export raws 32931–118028 exceed 32768. |
| `CWorldMarket` at `CGameState+0xBCC` | `+0x60` | Save-correlated `last_supply_pool`, goods quantities /32768, indexed by zero-based mod-load goods ordinals. Not producer sales. |

Sequential domestic/export clearing does **not** establish a producer-attributed
sales split. Global sold pools likewise do not establish country or producer
attribution. Realized sold quantity requires `opening unsold + produced - closing
unsold`; proceeds are independent, and output × price is not a substitute.
RGO/artisan opening stock needs a prior closing boundary with continuous
producer/province/country/output identity; artisan recipe switches break that
chain. Missing settlement or shutdown phases are not complete intervals.

Physical inventory and consumption can support narrow offline value-added
accounts, not a complete GDP or a verified current `country.economy` interval.
**Precious-metal RGO income is not cash creation**: valuation needs gross output
and the active mod's cash rate (vanilla 0.5, GFM 1.0), not market price or RGO
income. These limits also apply when capacity and owner modifiers are known.

See [Economy & Market](economy-market.md) and
[Economy Daily Path](economy-daily-path.md) for surrounding call paths.

[telemetry]: https://github.com/adrunkhuman/smedley_kernel/blob/a87832e6196168b6b6ac82701dc3f1dd95732848/mappings/evidence/telemetry.md#rgo-production
[catalog]: https://github.com/adrunkhuman/smedley_kernel/blob/a87832e6196168b6b6ac82701dc3f1dd95732848/mappings/v2game-3.04.toml
