# Configurable message dispatch

Configurable notifications have a presentation policy distinct from message
production, scripted effects, and AI option choices. Nine duplicated dispatch
paths contain a popup/pause block followed by further notification handling.
Skipping that block is not equivalent to suppressing the underlying event.

## Scope and evidence

Source: Smedley commit `a87832e6196168b6b6ac82701dc3f1dd95732848`:
[signature catalog][catalog], [historical campaign evidence][evidence], and
[current address/register use][code]. This note describes engine instruction
sites, not Smedley patch machinery or service APIs.

| Target property | Value |
| --- | --- |
| Executable | English Windows Victoria II: Heart of Darkness 3.04, **x86** |
| SHA-256 | `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648` |
| File size | `12294656` bytes |
| Preferred image base | `0x00400000` |

All code addresses here are preferred **VAs**, converted from catalog RVAs by
adding `0x00400000`. At runtime, use loaded module base + RVA. Policy offsets
below are relative to the policy object, not to the dispatching function.

## Presentation boundary

| Policy byte | Interpretation |
| --- | --- |
| `+0x0E` | `popup` |
| `+0x10` | `pausepopup` |

At each listed branch, the code tests `popup`; a nonzero value enters the popup
path. The next check tests `pausepopup` and can enter the same block. These are
not a complete policy layout or a description of every other presentation gate.

The listed no-popup continuations are **after popup and `CPauseGame`
construction**, not function returns. Reaching them skips that presentation
block but proceeds to later notifications, including map notices/logs or icons
as applicable. It does not skip message production, scripted effects, or AI
choices. The identified notification families include technology, invention,
upper-house, bankruptcy, and diplomatic/Great War messages; path 3 has a static
Great War discovery/status association. This is **not coverage of all popups**,
all mods, or every window created by [Event_Fire](Event_System.md).

## Instruction sites

These are branch/continuation labels **inside dispatch paths, not function
entries**. Path numbers are local catalog labels, not engine message-type IDs.

| Path | Popup-policy branch VA | Policy register | No-popup continuation VA | Evidence for path |
| --- | --- | --- | --- | --- |
| 1 | `0x0042BC68` | EDI | `0x0042BE42` | Historical runtime-correlated branch; static continuation. |
| 2 | `0x004934F8` | EBX | `0x00493663` | Static callsites; continuation begins icon handling. |
| 3 | `0x004E9678` | EDI | `0x004E9852` | Static callsites. |
| 4 | `0x00549C68` | EDI | `0x00549E42` | Static callsites. |
| 5 | `0x005ABAA8` | EBX | `0x005ABC13` | Static callsites; continuation begins icon handling. |
| 6 | `0x0072DFB8` | EDI | `0x0072E192` | Static callsites. |
| 7 | `0x00907038` | EDI | `0x00907212` | Static callsites. |
| 8 | `0x00909168` | EDI | `0x00909342` | Static callsites. |
| 9 | `0x0093D818` | EDI | `0x0093D9F2` | Static callsites. |

The catalog marks the first branch `verified-runtime`, the other eight branches
`verified-static-callsites`, and **all nine continuations**
`verified-static-callsites`. Exact signatures are kept in the [catalog][catalog];
the [Symbols rows](../Symbols/README.md) export only these 18 instruction sites.
A byte match establishes code presence, not full runtime coverage or a callable
function boundary.

The runtime evidence is **historical and lacks exact-built-commit provenance**.
It supports the exercised boundary, not acceptance of subsequent Smedley builds,
API extraction, every message family, or all nine paths at runtime. No game was
run for this documentation export, and static review must not be presented as
new runtime validation.

[catalog]: https://github.com/adrunkhuman/smedley_kernel/blob/a87832e6196168b6b6ac82701dc3f1dd95732848/mappings/v2game-3.04.toml#L203-L345
[evidence]: https://github.com/adrunkhuman/smedley_kernel/blob/a87832e6196168b6b6ac82701dc3f1dd95732848/mappings/evidence/campaign-automation.md#observer-ownership-and-view
[code]: https://github.com/adrunkhuman/smedley_kernel/blob/a87832e6196168b6b6ac82701dc3f1dd95732848/kernel/game_state/src/runtime.cpp#L2262-L2290
