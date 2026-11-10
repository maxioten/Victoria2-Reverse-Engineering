# Reproduction tools

These scripts reproduce the selection and differential tests described in
[`../README.md`](../README.md). They do not contain game files or lifted C.

## Requirements

- Python 3.10+ with `capstone`, `pefile`, `unicorn` and `numpy`.
- A local checkout of [pcrecomp](https://github.com/sp00nznet/pcrecomp).
- `gcc` for the differential-test harnesses.
- Your own copy of `v2game.exe` with SHA-256
  `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.

## Environment

All paths come from environment variables; there are no local absolute paths
in the scripts.

| Variable | Default | Meaning |
|---|---|---|
| `V2_ROOT` | repo root | repository root |
| `V2_WORK` | `<root>/work` | local work directory |
| `V2_BIN` | `<root>/base-game/v2game.exe` | local executable |
| `V2_ANALYSIS` | `<work>/analysis` | pcrecomp JSON and `image.bin` |
| `V2_GEN` | `<work>/src/recomp/gen` | generated C |
| `V2_BUILD` | `<work>/build` | object output |
| `V2_LOGS` | `<work>/logs` | logs |
| `PCRECOMP_SRC` | `<root>/pcrecomp` | pcrecomp checkout |

`common.py` resolves these paths and adds the pcrecomp modules to
`sys.path`.

## Order

First run pcrecomp itself to produce the analysis:

```bash
python tools/pe/pe_analyze.py "$V2_BIN" --json "$V2_ANALYSIS/pe_analysis.json"
python tools/disasm/disasm32.py "$V2_BIN" \
  --output "$V2_ANALYSIS/functions.json" \
  --pe-json "$V2_ANALYSIS/pe_analysis.json"
python -m tools "$V2_BIN" --all --output "$V2_GEN" \
  --functions-json "$V2_ANALYSIS/functions_full.json" \
  --pe-json "$V2_ANALYSIS/pe_full.json" \
  --stubs "$V2_GEN/import_stubs.c"
```

The differential harnesses also need `image.bin`, the memory-mapped image used
by the guest. Generate it locally from the executable with `pefile`; it is not
committed.

## Scripts

| Script | Purpose |
|---|---|
| `select_targets.py` | pick branchless leaf functions for the leaf difftest |
| `review_unimplemented.py` | classify the `UNIMPLEMENTED` functions as data-like or code |
| `select_nonleaf.py` | pick branchless functions with an internal-call closure |
| `select_imports.py` | pick functions with one simple Win32 import |
| `target_difftest.py` | leaf differential test against Unicorn |
| `target_difftest_nonleaf.py` | non-leaf differential test |
| `target_difftest_imports.py` | import differential test with deterministic stubs |
| `measure_generated.py` | count generated files, lines, errors and `UNIMPLEMENTED` |
| `compile_all.sh` | compile every generated C file to an object |
| `gcc-lm` | `gcc` wrapper that adds `-lm` for pcrecomp's built-in difftest |
| `verify_public.py` | validate the public metadata package without the game binary |

## Notes

- The harnesses write temporary C and executables; keep them outside Git.
- `target_difftest*.py` ignore the top-of-stack return-address slots because
  `RECOMP_CALL` uses `0xDEAD0000`.
- The import tests use deterministic stubs, not real Windows API behavior.
- No script proves the whole engine; each covers a selected domain.
