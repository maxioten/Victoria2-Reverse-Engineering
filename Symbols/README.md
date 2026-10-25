# Symbols (CSV)

Names, globals and struct offsets of `v2game.exe` 3.04, one row per fact, kept as plain CSV so they can
be diffed, grepped and imported into Ghidra.

Source: research of October 2026, built on
this repository's notes (rows marked `re`) and re-checked against the 3.04 executable; rows marked `cp`
were found in that work. Copied here as of 2026-10-11.

| file | columns |
|---|---|
| `functions.csv` | `va, name, conf, area, src, note` |
| `globals.csv` | `va, name, type, conf, src, note` (globals, constants, strings, vtables) |
| `structs.csv` | `struct, offset, field, type, conf, src, note` |

- `va` is the listing address (image base `0x00400000`). The executable has a relocation table and
  `DYNAMIC_BASE`, so Windows may load it elsewhere (it was seen at `0x00080000`): at runtime use
  `base + (va - 0x00400000)`.
- `conf`: `C` confirmed in the code, `I` inferred, `?` unknown.
- `src`: `re` = from this repository, re-checked; `cp` = new findings (October 2026); `sm` = exported from
  [Smedley `a87832e`](https://github.com/adrunkhuman/smedley_kernel/blob/a87832e6196168b6b6ac82701dc3f1dd95732848/mappings/v2game-3.04.toml).
  The matching topic note states the evidence and limits. For `sm` rows, `C` confirms only the stated
  field or code site, not a whole layout, lifecycle or runtime outcome.
- `functions.csv` also holds instruction-site labels (names ending in `_site` or containing `Site`).
  They are branches, callsites or epilogues, **not function entries**.
- File offsets: `.text` = VA − 0x400C00, `.rdata` = VA − 0x401A00, `.data` = VA − 0x402600.

