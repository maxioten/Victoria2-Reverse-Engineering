# Script execution boundaries

Selected-event-option actions and region iterators are **different boundaries**.
The former has limited country-event runtime correlation; the latter has a
static mechanism but no verified runtime attribution contract. Neither is a
universal event/trigger/effect profiler or stable script-source identifier.

## Executable and evidence

Target: Victoria II: Heart of Darkness 3.04, executable SHA-256
`62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`
(12,294,656 bytes), pinned by the Smedley
[mapping catalog](https://github.com/adrunkhuman/smedley_kernel/blob/a87832e6196168b6b6ac82701dc3f1dd95732848/mappings/v2game-3.04.toml).
All code/global addresses here and in the CSVs are **preferred VAs**: source RVAs
were converted explicitly as `VA = RVA + 0x00400000`; under ASLR use
`loaded_base + (VA - 0x00400000)`. Object offsets are not addresses.

Source at Smedley commit `a87832e6196168b6b6ac82701dc3f1dd95732848`:
[GFM workload boundary evidence](https://github.com/adrunkhuman/smedley_kernel/blob/a87832e6196168b6b6ac82701dc3f1dd95732848/mappings/evidence/gfm-workload.md#region-scope-iteration-boundary)
and its [selected-option section](https://github.com/adrunkhuman/smedley_kernel/blob/a87832e6196168b6b6ac82701dc3f1dd95732848/mappings/evidence/gfm-workload.md#selected-event-option-boundary).
`verified-static-callsites` means reviewed native data flow; `verified-runtime`
below is restricted to the stated observations. CSV `C` does not imply universal
runtime coverage or hook safety.

## Selected-event-option execution

At preferred VA **`0x00907E00`**, x86 MSVC `__thiscall` receives the action in
`ECX`. It resolves the event through action `+0x40` / `+0x44` and synchronously
calls option executor **`0x008A61F0`**. The reviewed call at `0x009089CC` passes
selected index in `ESI`, resolved event in `EDI`, and scope on the stack;
the option executor returns `ret 4`. Do not apply the action's `__thiscall`
convention to that register-based helper.

| Action offset | Interpretation | Evidence limit |
| --- | --- | --- |
| `+0x64` | Selected option index | Correlated for **two country-event actions** only. |
| `+0x68` | Embedded event snapshot | Not a general ownership, extent, or lifetime guarantee. |
| `+0x40` / `+0x44` | Resolver words | Second word matched the country-event ID in those two actions; other scopes unverified. |
| `+0x70` / `+0x74` | Opaque source words | Source-key semantics unresolved; do not label these as the event resolver or stable script-site identity. |

The helper indexes the event's options and invokes the chosen option's effect
block. Its negative-index branch executes the immediate block instead; this
static branch does not broaden the two observed selected-option correlations.

The catalog labels the action `verified-runtime` **only in this selected-option
role**. The observations are bounded by the pinned GFM/PRU
[immutable inputs](https://github.com/adrunkhuman/smedley_kernel/blob/a87832e6196168b6b6ac82701dc3f1dd95732848/mappings/evidence/gfm-workload.md#immutable-inputs);
the save and traces are not committed. Historical implementations lack
exact-built-commit provenance. Observed thread/lifetime does not establish
ownership; broader scopes, pointer lifetime,
source-site identity, nested reentrancy, and active-callback overhead remain
unresolved. Measurements with no calls cannot bound active overhead. There is
no reusable, production script-attribution contract here.

### Not `Event_Fire`

Preferred VA **`0x008A8120`** (`Event_Fire`) is a distinct delivery/setup path:
the existing [event-system analysis](Event_System.md#33-firing-an-event)
identifies AI option selection and command queueing, human-window delivery, and
immediate effects. Selected-option execution, including observed nested
country-event execution, did **not** call it. That observation excludes it as
the selected-option boundary, **not** as a possible accepted-event-delivery
boundary. Its delivery semantics have not been independently runtime-correlated
by this work; the static delivery analysis is not invalidated.

## Region scope iteration (static only)

| Preferred VA | ABI | Mechanism |
| --- | --- | --- |
| **`0x00888BA0`**, `CRegionScopeEffect::Execute` | `ECX` = this, two stack arguments, `ret 8` | `this+0x3C` points to a region. Traverse its `+0x8` province list, build province scopes, evaluate the embedded `this+0x20` filter, execute the `this+0x8` child effect chain for matches. |
| **`0x008C5DA0`**, `CRegionScopeTrigger::Evaluate` | `ECX` = this, one stack argument, `ret 4` | `this+0x1C` points to a region. Evaluate the nested trigger sequence per province; return true at the first matching province, false after exhaustion. |

Both are catalog `verified-static-callsites`, **not** `verified-runtime`.
Trigger execution remains unobserved; effect execution lacks source-site
correlation. Region cardinality is not the short-circuited trigger visit count.
Effect-inclusive timing includes traversal, filtering, and child effects, not
just iterator overhead. Stable sites, actual visit counts, and active overhead
are not established.

In pinned GFM v3.0 commit `ee1486e251d3bb4dc5c355f5c2ec34abaea1078d`,
`any_land_province` is a **custom region** defined in `map/region.txt`
(3,385 unique province IDs, range 1–3,986), not a built-in engine operator.
Its uses compile to these generic region-scope objects. That mod definition
neither establishes a special native operator nor proves runtime visit counts.
No GFM policy inventory or campaign-cost attribution is implied.

## Entry signatures

These catalog signatures match the pinned executable and stop before relocated
exception-handler operands where present:

| Preferred VA | Relocation-free entry bytes |
| --- | --- |
| `0x00907E00` | `55 8b ec 83 e4 f8 6a ff` |
| `0x00888BA0` | `55 8b ec 83 e4 f8 83 ec 54 53 56 8b f1 8b 4d 08` |
| `0x008C5DA0` | `55 8b ec 83 e4 f8 6a ff` |

The option helper additionally begins `55 8b ec 53 8b 5d 08 85 f6` (checked
directly, not a separate catalog signature). Byte agreement is not semantic or
hook-safety proof; later relocated absolute operands cannot be matched literally
under ASLR.

See [Triggers & scopes](triggers-and-scopes.md), [Event system](Event_System.md),
and [symbol conventions](../Symbols/README.md). Boundary rows are in
[functions](../Symbols/functions.csv) and [structs](../Symbols/structs.csv).
