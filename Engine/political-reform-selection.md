# Political reform selection

Political selection is a country-owned **array of option pointers**, indexed by
an issue group's index. `CCountry+0x860` holds the array **pointer**, not an inline
array. This note establishes the static category-2 mechanism and a narrow GFM
current-selection correlation. It does not establish live reform transitions or
safe arbitrary writes.

## Executable and evidence

Target: Victoria II: Heart of Darkness 3.04, executable SHA-256
`62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`
(12,294,656 bytes), pinned by the Smedley
[mapping catalog](https://github.com/adrunkhuman/smedley_kernel/blob/a87832e6196168b6b6ac82701dc3f1dd95732848/mappings/v2game-3.04.toml).

All code/global addresses here and in the CSVs are **preferred VAs**. Source
RVAs were converted explicitly as `VA = RVA + 0x00400000`; under ASLR use
`loaded_base + (VA - 0x00400000)`. Object offsets are not addresses.

Sources at Smedley commit `a87832e6196168b6b6ac82701dc3f1dd95732848`:

- [Political selection evidence](https://github.com/adrunkhuman/smedley_kernel/blob/a87832e6196168b6b6ac82701dc3f1dd95732848/mappings/evidence/province-reconciliation.md#political-reform-selection).
- [Immutable GFM/save inputs](https://github.com/adrunkhuman/smedley_kernel/blob/a87832e6196168b6b6ac82701dc3f1dd95732848/mappings/evidence/gfm-workload.md#immutable-inputs).
- [Current bounded reader](https://github.com/adrunkhuman/smedley_kernel/blob/a87832e6196168b6b6ac82701dc3f1dd95732848/kernel/game_state/src/services/province_modifier_reconciliation.cpp)
  (`ResolveQuery`, `ResolveOwner`, `OwnerOptionSelected`). This code does not
  supply exact-built-commit provenance for historical runtime observations.

The catalog's `verified-static-callsites` means reviewed native data flow;
`verified-runtime` applies only to the correlations described below. CSV `C`
means confirmed code/field interpretation, not a general runtime safety claim.

## Static mechanism

| Preferred VA | Boundary | Contract |
| --- | --- | --- |
| `0x008C4A70` | `CIssueGroupTrigger` parser | Loads the issue-option registry from `0x01258A48`; passes it in `EAX` and an MSVC-string pointer on the stack to lookup `0x00975ED0`. Requires returned option `+0x54` to equal trigger group `this+0x20`; stores accepted option at `this+0x24`. |
| `0x008C4DA0` | `CIssueGroupTrigger::Evaluate` | x86 `__thiscall`, scope on stack, `ret 4`. Reads group index `+0x50` and category `+0x5C`; category **2** compares the indexed country selection pointer with expected option `this+0x24`. |
| `0x008950B0` | `CSetPoliticalReformEffect::Execute` | x86 `__thiscall`, two stack arguments, `ret 8`. Resolves the scope country, follows target option `this+0x20` → group `+0x54` → index `+0x50`, loads the pointer at country `+0x860`, and writes the option at that index. Static corroboration, not a write API. |

For a country scope, the evaluator uses its country reference. For a province
scope it reads current-owner key/index at province `+0x128` / `+0x12C` (the POP
fallback also reaches a province). The country database pointer at preferred VA
`0x012587E4` supplies its `+0x4` country-pointer array. An owner index of zero
returns false on the province path; the evaluator also rejects the `REB` tag.

The category-2 comparison is equivalent to:

```text
group    = trigger.group                       // this+0x20
country  = country_database.countries[owner_index]
options  = *(CIssueOption***)(country + 0x860)   // pointer load
selected = options[group.index]                // group+0x50; 4-byte entries
return selected == trigger.expected_option     // this+0x24
```

This is explanatory data flow, not a callable interface. The category-2 branch
contains no array-length check; the bounded Smedley reader's `group_index < 64`
is a defensive limit, **not** proof of native array length or write safety.
Other issue categories are outside this note.

| Object | Offset | Narrow meaning |
| --- | --- | --- |
| `CIssueGroupTrigger` | `+0x20` / `+0x24` | Group / expected option pointers |
| `CIssueGroup` | `+0x50` / `+0x5C` | Index / category (2 selects political reforms) |
| `CIssueOption` | `+0x54` | Owning group pointer |
| `CCountry` | `+0x860` | Pointer to selected political option pointers |
| `CSetPoliticalReformEffect` | `+0x20` | Target option pointer |

**Registry:** preferred VA `0x01258A48` is the issue-option registry pointer.
The parser load at `0x008C4AD4` and call at `0x008C4ADA` establish this role.

## Narrow runtime correlation and limits

Pinned GFM v3.0 commit `ee1486e251d3bb4dc5c355f5c2ec34abaea1078d` defines
political issue `slavery` and option `no_slavery`. Historical active-campaign
lookup resolved that option to a group with index **1**, category **2**;
bounded indexing correlated the current owner's selected option. This is
lookup/current-selection evidence, not a live reform-transition observation.

Separate historical reconciliation observations removed a stage for an owner
selecting `no_slavery` and preserved it otherwise. Those observations used a
locally changed implementation without exact-built-commit provenance; they do
not establish current-build behavior or general modifier-removal safety.

No live reform transition was observed. Registry lifetime across loads, pointer
ownership across transitions, safe threads/phases, arbitrary indices/options,
and complete country/group/option layouts remain unverified. The native effect's
store is evidence of representation, not authorization to reproduce the write.

## Byte checks and local references

The catalog's relocation-free entry signatures match the pinned executable:

| Preferred VA | Entry bytes |
| --- | --- |
| `0x008C4DA0` | `55 8b ec 83 e4 f8 51 53 56 8b 75 08 8b 46 0c` |
| `0x008950B0` | `55 8b ec 83 ec 08 8b 45 08 8b 50 08 89 55 f8` |
| `0x00975ED0` | `55 8b ec 51 8b 4d 08 53 56 8b f0 8b 41 14 57` |

The parser additionally begins `55 8b ec 83 e4 f8 6a ff` (checked directly;
not a separate catalog signature). Later exception-handler/global absolute
operands are relocated and must not be matched literally under ASLR. Byte
matches alone do not prove semantics or lifecycle safety.

See [Triggers & scopes](triggers-and-scopes.md) and the
[symbol conventions](../Symbols/README.md); corresponding rows are in
[functions](../Symbols/functions.csv), [globals](../Symbols/globals.csv), and
[structs](../Symbols/structs.csv).
