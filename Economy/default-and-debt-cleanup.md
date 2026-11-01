# Default and debt cleanup

Interest-shortfall handling and creditor removal are **separate native paths**.
This note is for readers interpreting default observations and country debt;
it does not define a general bankruptcy lifecycle.

## Target and evidence

Supported executable: **Victoria II: Heart of Darkness 3.04, English, x86**,
SHA-256 `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
VAs use preferred image base `0x00400000`: **VA = RVA + 0x00400000**;
runtime address = loaded module base + RVA. Neither is a file offset.
Treasury, bank and creditor principal use signed 48.15 fixed point (/32768).

Sources are Smedley commit **`a87832e6196168b6b6ac82701dc3f1dd95732848`**:
[fiscal evidence][fiscal] and [mapping catalog][catalog]. The handler invocation
has historical runtime correlation; its body, refund and debt-removal callers
are static contracts. Historical runtime evidence lacks exact-built-commit
provenance. Read-only checks of the supported binary confirm selected
signatures and instructions, not fresh live tests, current-worktree acceptance
or complete default outcomes.

## Interest shortfall handler

`CCountry::PayDailyInterest` at RVA `0x00123C30` / VA `0x00523C30` accumulates
insufficient payments. A positive shortfall above its threshold invokes the
handler at **RVA `0x001241F0` / VA `0x005241F0`**, via VA `0x005241CD`.

The reviewed handler body applies `bad_debtor` or `in_bankrupcy` modifiers,
emits creditor notifications, and cleans construction/factory state. The source
label `bad_debtor` corresponds to the binary's literal **`bad_debter`** at VA
`0x00DF985C`; `in_bankrupcy` is the literal at VA `0x00DF9898`. Calls at VAs
`0x00524294` and `0x005242DC` lead to modifier helper VA `0x005114D0`.
These static paths do not establish every runtime modifier outcome.

The construction refund is conditional, not a universal bankruptcy refund:

| Static anchor (VA) | Mechanism |
| --- | --- |
| `0x005246BE`–`0x005246D1` | A virtual predicate and a non-null construction pointer gate the refund branch. |
| `0x005246EB`–`0x00524701` | Reads canceled construction `+0xB8/+0xBC` and credits country treasury `+0xE78/+0xE7C`; low-word add at **`0x005246F7`** (RVA `0x001246F7`). |
| `0x00524715 / 0x00524718` | Adds the same amount to daily accounting ledger **`+0x40/+0x44`**, relative to the resolved ledger, not the country. |

The reviewed body (`VA 0x005241F0`–`0x0052571B`) **does not call
`CCountry::RemoveDebts`** or directly establish a principal write-off.
An invocation need not synchronously change treasury, creditor count/principal
or own-bank lent principal. Later treasury recovery remains unattributed.

## Separate debt-removal path

`CCountry::RemoveDebts` is **RVA `0x00111340` / VA `0x00511340`**.
It walks country creditors `+0xE8C..+0xE90`. For eligible nonzero-ordinal
creditors it subtracts principal from the lender bank's `money_lent` (`+0x18`)
and `money` (`+0x10`), clamping each at zero (VAs `0x005113A2`–`0x005113D1`).
With the boolean argument true, paid creditors skip these bank reductions.
Creditor objects are destroyed and the vector end is reset; skipping a bank
reduction does not preserve the creditor. This is not normal principal repayment.

| Direct caller | RVA / VA | Static guard or argument |
| --- | --- | --- |
| Conditional country daily cleanup | `0x00108ACE / 0x00508ACE` | Calls `RemoveDebts(true)` only if absent from **both** preceding membership searches. |
| `CCountry::Annex` | `0x00118EE6 / 0x00518EE6` | Calls `RemoveDebts(false)`. |

The daily searches walk country `+0x4D8` and `+0x4E8` at VAs
`0x00508A95`–`0x00508AC9`; a match in either skips removal. **Their membership
semantics are unresolved.** Do not name these sets or treat this guard as an
automatic bankruptcy/default write-off boundary. Static cleanup mechanics do
not establish bankruptcy timing, prestige effects, modifier outcomes, or the
cause of delayed negative-treasury recovery.

See [Economy & Market](economy-market.md) and
[Country Daily Update](../Engine/Country_Daily_Update.md) for surrounding paths.

[fiscal]: https://github.com/adrunkhuman/smedley_kernel/blob/a87832e6196168b6b6ac82701dc3f1dd95732848/mappings/evidence/fiscal-credit-boundaries.md#interest-shortfall-and-default
[catalog]: https://github.com/adrunkhuman/smedley_kernel/blob/a87832e6196168b6b6ac82701dc3f1dd95732848/mappings/v2game-3.04.toml
