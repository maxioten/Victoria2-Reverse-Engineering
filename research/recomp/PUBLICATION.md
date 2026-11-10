# Publication scope for `research/recomp`

This directory publishes the **methodology and aggregate evidence** of the
first pcrecomp pass. It does not publish the game or a reconstructed engine.

## Included

- `README.md`, `docs/METHOD.md`, `docs/LIMITS.md`,
  `docs/PERFORMANCE-PLAN.md`.
- Sanitized analysis JSON: PE metadata, coverage, function statistics,
  `UNIMPLEMENTED` review, differential-test results and compile summary.
- `catalog/summary.json`: aggregate function/coverage metadata.

## Not included

- `v2game.exe`, DLLs, saves, assets or any game file.
- `image.bin`, Ghidra projects, dumps or generated receipts.
- The 1.09 GiB of generated C and the 1.79 GiB of object files.
- Harness C files that contain lifted function bodies.
- Logs with local absolute paths.

## Why

The generated C is a derivative of the game executable and is not distributed
here. The existing repository policy in
[`research/docs/PUBLICATION.md`](../docs/PUBLICATION.md) already excludes
executables, saves, Ghidra projects and extensive pseudocode/disassembly.

## Reproducing

Users must supply their own `v2game.exe` with the SHA-256 listed in the README.
Place it outside Git and point the pcrecomp commands at that copy. Generated
artifacts stay in a local work directory.

## Future source publication

A matching decompilation track would publish reconstructed source separately.
That requires an explicit licensing and legal decision; it is not part of this
baseline.
