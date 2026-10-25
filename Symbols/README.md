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
- `src`: `re` = from this repository, re-checked; `cp` = new findings (October 2026); `sm` = Smedley-derived evidence, with claim-specific limits in the linked note.
- Console initializer/epilogue and descriptor entries are detailed in [Engine/console.md](../Engine/console.md). An epilogue or toggle site is not a function entry. Console record rows marked `I` retain current implementation layouts without a complete native ABI/ownership audit.
- File offsets: `.text` = VA − 0x400C00, `.rdata` = VA − 0x401A00, `.data` = VA − 0x402600.

