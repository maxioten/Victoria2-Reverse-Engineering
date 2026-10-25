# Entity identity: states, regions, and POPs

A live state, its region definition, and an individual POP have different identities.
Region keys describe geography; POP dimensions describe a cohort. Neither is a
unique replacement for the corresponding object ID.

## Scope and evidence

This note exports narrow claims from Smedley commit
`a87832e6196168b6b6ac82701dc3f1dd95732848`, not its APIs or historical whole-object layouts.
The target is the English Windows **x86** Victoria II: Heart of Darkness 3.04 executable:

| Property | Value |
| --- | --- |
| SHA-256 | `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648` |
| File size | `12294656` bytes |
| Preferred image base | `0x00400000` |

Code addresses below are preferred **VAs**: source catalog RVA + `0x00400000`.
With relocation, use loaded module base + RVA. Object offsets are not code addresses.
Static extent evidence and historical runtime/save correlations apply only to the
stated claims. The source does not establish the full `CState` or `CPop` layout,
permanent identity, or acceptance of later builds. No game was run for this export.

## States and shared regions

| Boundary | Meaning | Evidence / limit |
| --- | --- | --- |
| `CState+0x0C` | Persistent, serialized state ID; Brandenburg observed as `750`. | Historical runtime/save correlation; not a promise of survival through every ownership, merge, or reload transition. |
| `CState+0x08` | Object-type discriminator, observed value `47`. | Not a state ID or region ID. |
| `CState+0x250` | Pointer to `CRegion`. | Owner-specific state instances can share the same region pointer and key. Region identity therefore does not uniquely identify a state. |
| `CRegion+0x18` | ASCII definition key, e.g. `PRU_549`. | Distinct from the current owner and from localized presentation. |
| `CRegion+0x34` | Display name, e.g. `Brandenburg`. | A name is not an identity key. RTTI and contiguous runtime instances give an observed region extent of `0x108`, not a complete layout. |

Constructor VA `0x004CDC60` and allocation callsites at VAs `0x004FC0CB`,
`0x00521785`, and `0x005218FB` establish a **`0x290` state extent**
(`verified-static-callsites`). Size alone does not verify the intervening fields.
The [catalog][catalog] records the constructor signature and allocation evidence;
the [state/region correlations][states] distinguish serialized state identity
from shared region identity. The [current readers][readers] read the state ID and
region key separately; their defensive checks are not additional runtime proof.

## POP IDs versus descriptive dimensions

`CPop+0x0C` is the current in-process ID, correlated with serialized POP IDs.
The repository's `Pop` symbol rows refer to this engine class. The following
fields are narrow descriptive/scope observations, not a complete POP layout:

| Dimension | Source | Evidence / limit |
| --- | --- | --- |
| Province | Pointer at `CPop+0x64`; referenced province ID at `+0x58`. | Candidate scope dimension in current readers. |
| POP type | Pointer at `CPop+0x68`; referenced type ID at `+0x28`. | Candidate type dimension in current readers. |
| Culture | Pointer at `CPop+0x6C`; referenced key at `+0x18`. | Narrow static/save correlation. |
| Religion | Pointer at `CPop+0x70`; referenced key at `+0x10`. | Narrow static/save correlation; not the extra serialized string at `+0x2C`. |
| Artisan recipe | Active production type, read separately from the POP dimensions. | Can change across dates; adding it still does not make the descriptive tuple unique. |

The [historical POP evidence][pops] reports **23,429 unique serialized IDs** but
only **22,610 province+type+culture+religion keys**, with **329 duplicate keys**
(all artisans). Adding recipe still leaves **126 duplicate keys**. Do not merge
individual POPs solely because their descriptions match.

### Narrow counterexample to durable cohort identity

A size-65 French/Catholic craftsmen cohort (type candidate `7`) was matched as follows:

| Raw date | Province | POP ID | Observation |
| --- | --- | --- | --- |
| Through `59883744` | `412` | `27606` | Original ID present. |
| `59883768` | `420` | `28227` | Original ID absent; same dimensions and size at a new ID. |
| `59883792` | `458` | `28266` | Prior ID absent; same dimensions and size at another new ID. |

This constrains any claim that one ID permanently tracks such a cohort. It does
**not prove migration or individual continuity**: the native migration boundary
was not established. Promotion, demotion, splitting, merging, deletion, save/reload,
and ID reuse semantics also remain unresolved. Consecutive surviving IDs support
observed scope changes; matching descriptions alone cannot assign a cause.

These are historical correlations, not newly repeated runtime probes. Pinning the
source preserves the evidence record; it does not supply exact-built-commit
provenance for every historical observation or certify a later implementation.

See also [engine structure](engine-structure.md),
[economy traversal](../Economy/economy-daily-path.md), and
[Symbols](../Symbols/README.md) for the narrow exported rows.

[catalog]: https://github.com/adrunkhuman/smedley_kernel/blob/a87832e6196168b6b6ac82701dc3f1dd95732848/mappings/v2game-3.04.toml
[states]: https://github.com/adrunkhuman/smedley_kernel/blob/a87832e6196168b6b6ac82701dc3f1dd95732848/mappings/evidence/telemetry.md#established-fields-and-identity
[pops]: https://github.com/adrunkhuman/smedley_kernel/blob/a87832e6196168b6b6ac82701dc3f1dd95732848/mappings/evidence/telemetry.md#pop-snapshots-identity-and-needs
[readers]: https://github.com/adrunkhuman/smedley_kernel/blob/a87832e6196168b6b6ac82701dc3f1dd95732848/kernel/game_state/src/readers.cpp#L1187-L1207
