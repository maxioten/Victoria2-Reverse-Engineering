# Recompilation baseline for Victoria II

This directory records the first **static-recompilation baseline** of
`v2game.exe` with [pcrecomp](https://github.com/sp00nznet/pcrecomp). It is a
coverage and lift report, not a matching decompilation and not a playable
build.

Target: PE32/i386, image base `0x00400000`, linker 10.0, SHA-256
`62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.

## What was run

1. `pe_analyze.py` on a local copy of the executable.
2. `disasm32.py` to recover function boundaries and call targets.
3. `python -m tools <exe> --all` to lift the catalog to C.
4. Differential tests of selected functions against Unicorn.
5. Compilation of every generated C file to an object.

The executable, generated C, objects and Ghidra projects stay local. See
[PUBLICATION.md](PUBLICATION.md).

## Results

| Metric | Result |
|---|---:|
| PE sections | 5 |
| Imports | 345 functions from 17 DLLs |
| Exports | 86 |
| Code range | `0x00401000`–`0x00C89200` (8,946,176 bytes) |
| Function entries | **99,740** |
| — real starts | 35,601 |
| — aliases | 64,139 |
| — leaves (no calls) | 46,029 |
| — thunks | 91 |
| Instructions | **11,680,186** |
| Byte coverage | **95.3 %** (8,525,292 / 8,946,176) |
| Hard lift errors | **0** |
| `UNIMPLEMENTED` sites | 194 unique addresses / 13 definitions |
| Generated C | 100 source files + dispatch + header, 1.09 GiB |
| Compiled C files | **101 / 101** (`rc=0`) |
| Differential tests | **165 / 165** cases |

The 4.7 % of bytes not covered can be data, padding, unreachable code or
functions the discovery pass did not separate. It is not “lost code” without
classifying each range.

## `UNIMPLEMENTED` review

The 194 sites are concentrated in 13 definitions:

- **9** look like data interpreted as code: zero callers, no prologue, data-like
  bytes (`0x11` repeated, low entropy, `int 0x7f`, `aad`/`aam`/`bound`).
- **4** are real code with a prologue and callers; their only missing
  instruction is `pause`, a spin-loop hint that can be omitted without changing
  semantics.

Full table: [analysis/unimplemented_review.md](analysis/unimplemented_review.md).

## Differential tests

The harness lifts selected functions, compiles them with the pcrecomp
`recomp32` runtime, runs the original bytes under Unicorn and compares
registers, flags, memory and x87 depth.

| Group | Functions | Cases | Result |
|---|---:|---:|---:|
| Leaf functions | 40 | 120 | 120 / 120 |
| Non-leaf, internal calls | 5 | 15 | 15 / 15 |
| Imports with deterministic stubs | 10 | 30 | 30 / 30 |
| **Total** | **55** | **165** | **165 / 165** |

The tests ignore the top-of-stack return-address slots because pcrecomp's
`RECOMP_CALL` pushes `0xDEAD0000` instead of the real return address.

## Compilation

All 101 generated C files compile with:

```bash
gcc -c -O0 -w -I runtime/recomp32 \
  -include "$GEN/recomp_funcs.h" "$GEN/recomp_XXXX.c" -o build/recomp_XXXX.o
```

Total CPU time was 4,189.8 s; the object set is 1.79 GiB. One file
(`recomp_0031.c`) needed a local patch for two out-of-image calls from a
zero-caller data blob before it compiled. No full executable was linked.

## Limits

- This is **static lift**, not source reconstruction. Matching progress is
  measured with `reccmp`/`objdiff`, not by lifted functions.
- No full link, D3D9, SEH `__try/__except` or game boot was tested.
- `data-like` is a conservative verdict, not forensic proof.
- The runtime uses dummy return addresses for calls; those stack slots are not
  compared.

## Next steps

1. Classify the remaining 4.7 % of code bytes.
2. Link the 101 objects with the runtime and a real import lookup.
3. Test D3D9/SEH on Windows or Wine.
4. Start a matching-decompilation track for hot functions with `rebrew`,
   `reccmp` and `objdiff`.
5. Measure and optimize the hotspots in
   [docs/PERFORMANCE-PLAN.md](docs/PERFORMANCE-PLAN.md).

## Evidence

- [analysis/](analysis/): sanitized metrics and test results.
- [catalog/summary.json](catalog/summary.json): coverage and function summary.
- [docs/METHOD.md](docs/METHOD.md): exact pipeline and tool versions.
- [docs/LIMITS.md](docs/LIMITS.md): what these numbers do and do not prove.
- [docs/PERFORMANCE-PLAN.md](docs/PERFORMANCE-PLAN.md): performance work based
  on the existing `Engine/performance-profile.md`.
