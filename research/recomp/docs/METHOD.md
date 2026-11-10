# Method

## Target

| Field | Value |
|---|---|
| File | `v2game.exe` |
| SHA-256 | `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648` |
| Size | 12,294,656 bytes |
| Format | PE32 (EXE), i386 |
| Image base | `0x00400000` |
| Linker | 10.0 |
| Timestamp | 2016-01-04 16:44:03 UTC |
| Sections | `.text`, `.rdata`, `.data`, `.rsrc`, `.reloc` |
| Code range | `0x00401000`–`0x00C89200` |
| Data range | `0x00C8A000`–`0x013F4C24` |
| Imports | 345 functions from 17 DLLs |
| Exports | 86 |

The compiler is not confirmed. Linker 10.0 suggests MSVC 2010 (VC10); confirm
with `nfdx64dbg` or Detect It Easy before fixing a matching toolchain.

## Pipeline

pcrecomp commit `2adc02f` (2026-11-10), MIT.

```bash
# 1. PE analysis
python tools/pe/pe_analyze.py "$V2_BIN" --json "$OUT/pe_analysis.json"

# 2. Function recovery
python tools/disasm/disasm32.py "$V2_BIN" \
  --output "$OUT/functions.json" \
  --pe-json "$OUT/pe_analysis.json"

# 3. Full analysis + lift
python -m tools "$V2_BIN" --all \
  --output "$GEN" \
  --functions-json "$OUT/functions_full.json" \
  --pe-json "$OUT/pe_full.json" \
  --stubs "$GEN/import_stubs.c"
```

`V2_BIN` is a local copy of the user's executable; `OUT` and `GEN` are local
work directories outside Git.

## Environment

| Tool | Version |
|---|---|
| Python | 3.14.8 |
| capstone | 5.0.9 |
| pefile | 2024.8.26 |
| unicorn | 2.1.4 |
| numpy | 2.5.4 |
| gcc | 16.2.1 |

## Function recovery

`disasm32.py` uses recursive descent from the entry point, exports and call
targets, plus prologue patterns and a data-pointer scan. It ran six discovery
rounds:

- 22,981 initial candidates;
- 9,817 + 33 + 61,400 + 1,389 + 21 new targets in later rounds;
- 95,294 functions disassembled before alias/overlap cleanup;
- final catalog: 99,740 entries (35,601 starts, 64,139 aliases).

The 64,139 aliases are entries that share a body with another function. They
inflate the function count; coverage is measured on bytes, not entries.

## Lift

The full pipeline generated 100 source files of 1,000 functions each, plus
`recomp_dispatch.c` and `recomp_funcs.h`.

- 0 `/* ERROR lifting */`
- 0 `/* FAILED */`
- 0 `RT_UNIMPL`
- 194 `UNIMPLEMENTED` comments in 13 definitions

`UNIMPLEMENTED` means the lifter emitted a comment instead of translating that
instruction. It is not a hard failure, but it is a semantic gap until the
instruction is classified as data, unreachable or real code.

## Differential tests

The harnesses lift selected functions with pcrecomp's `Lifter`, compile them
with `runtime/recomp32`, run the original bytes under Unicorn and compare:

- all eight general registers;
- CF, PF, AF, ZF, SF, DF, OF;
- every changed byte of a 21 MiB guest window;
- x87 depth.

Leaf tests use one function per case. Non-leaf tests lift the direct-call
closure. Import tests replace the IAT call with a deterministic stub on both
sides. The top-of-stack return-address slots are ignored because
`RECOMP_CALL` pushes `0xDEAD0000`.

## Compilation

Every generated C file was compiled to an object with the pcrecomp
`recomp32` headers:

```bash
gcc -c -O0 -w -I runtime/recomp32 \
  -include "$GEN/recomp_funcs.h" "$GEN/recomp_XXXX.c" -o build/recomp_XXXX.o
```

No link step was attempted. The full executable needs a host runtime, `main`,
a real `recomp_lookup_import` and the game's dependencies.
