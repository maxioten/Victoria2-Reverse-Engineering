# Button callbacks

| Function | Role | Evidence / limit |
| --- | --- | --- |
| `0x006DFE80` | Westernize button callback | Existing static identification |
| `0x00541B90` | Westernize clickability condition | Existing static identification |
| `0x00772300` | Single-player Play listener | Bound by frontend constructor; runtime-correlated native signal route |
| `0x00718CE0` / `0x00718CF0` | Topbar speed-up / speed-down callbacks | Invoke idler virtual byte slots `+0x164` / `+0x168`; runtime-correlated chain |

[Native UI and frontend](native-ui-and-frontend.md) documents controller
identity/lifetime, named lookup, press/release conventions, save/load/Play,
pause and native exit. All addresses above are preferred-base VAs.

The single-player role of `0x00772300` is established; the corresponding
multiplayer route remains unresolved. Other historical button identifications
remain pending recovery. GUI definition names or tooltip string references
alone do not establish action callbacks.
