# Three reconstructed C phases: clean-checkout reproduction

These are operational reconstructions, not original game source or a complete
recompiled engine. No Windows installation or running game is needed for this
bounded emulated comparison. Linux, Python 3.11+, an i686-w64-mingw32 GCC cross
compiler and a locally owned reference executable are required.

Target: Victoria II 3.04, SHA-256
`62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
Preferred and emulated image base: `0x00400000`. Intervals below are RVA, end excluded.

| Inferred role | RVA interval | Source directory |
| --- | --- | --- |
| Daily country preparation | `0x285aa9..0x285ae4` | `../tick-country-prepare-lab` |
| Daily province/POP preparation | `0x285ae4..0x285b22` | `../tick-pop-prepare-lab` |
| 1,000 RNG extractions, existing singleton | `0x285b69..0x285c09` | `../tick-recompile-lab` |

Each directory contains independent C, its assembly ABI bridge, build procedure
and differential verifier. Original instructions and their real callees execute
from the hash-checked PE in Unicorn; reconstructed code executes separately on
identical synthetic inputs. No original executable bytes are distributed.

## Reproduce from a fresh checkout

Install Python venv support and the MinGW i686 GCC cross compiler through your
Linux distribution. Debian/Ubuntu package names are `python3-venv` and
`gcc-mingw-w64-i686`. Then, from the repository root:

```sh
python3 -m venv .venv-three-phases
. .venv-three-phases/bin/activate
python -m pip install -r experiments/three-phases/requirements.txt
mkdir -p base-game
# Copy your own v2game.exe into base-game/; do not commit it.
export V2_CC=i686-w64-mingw32-gcc
python experiments/three-phases/reproduce.py
```

`V2_CC` accepts a compiler executable path, not shell flags. No project-local
compiler installation, debugger, Wine prefix, save, old build or receipt is
required. An alternative compiler can produce different code: acceptance depends
on the newly executed comparisons, not matching a historical blob hash.

The command checks the reference hash and refuses existing evidence directories.
It builds all three candidates and incorrect candidates for all three phases, then runs
all fixture matrices. Outputs, compiler logs, source copies and JSON receipts
remain in each lab's ignored `evidence/` directory. Preserve those directories;
use another clean checkout to repeat. Do not use Python `-O`: verifiers rely on
assertions. Failures must be investigated rather than relabeled as success.

## Evidence and limits

**confirmed only after a successful local run:** equality for the enumerated
fixtures, including compared memory, integer registers, flags and the FPU/SIMD
state captured by each verifier. Country/POP verifiers also compare FXSAVE;
RNG compares the explicitly listed control/SIMD registers, not a full FXSAVE.
Country writes are guarded; POP reads and writes are guarded. The deliberately
incorrect candidates for all three phases must be rejected for memory disagreement.

**inferred:** semantic object and field names. The C comments, numeric offsets,
synthetic graph constructors and allowed-access checks define the tested domain.
Graphs must be valid, finite, nonaliasing as specified, with stable descriptors
and globals; RNG requires an existing singleton and no concurrent access.
Global addresses remain tied to the specified image base. This is not a portable
standalone simulation library, a matching-source project or an optimization.

**hypothesis / pending:** behavior beyond these fixtures, independent whole-world
or campaign equivalence, remaining tick phases, allocation, serialization,
networking, rendering and safe parallelism. Earlier local native experiments do
not substitute for running this checkout. The native 365-day integration and its
large private journals are not packaged here; this PR provides a reproducible
bounded starting point without pretending those artifacts are present.
