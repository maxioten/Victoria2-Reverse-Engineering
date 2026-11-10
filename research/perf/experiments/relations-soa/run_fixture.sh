#!/usr/bin/env bash
# Build and run the native 683 x 683 relation fixture.
#
# The ASan/UBSan build checks values, pointer identity, pointer stability and
# canaries.  The optimized build then measures the same pass for each layout.
set -euo pipefail
cd "$(dirname "$0")"

CC=${CC:-gcc}
REPS=${REPS:-10}
ROUNDS=${ROUNDS:-5}
OUT=${OUT:-fixture-results.json}

"$CC" -std=c11 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
    -o fixture-asan fixture.c
ASAN_OPTIONS=detect_leaks=0 ./fixture-asan --correctness-only

"$CC" -std=c11 -O2 -march=native -o fixture fixture.c
./fixture --json --reps "$REPS" --rounds "$ROUNDS" | tee "$OUT"
