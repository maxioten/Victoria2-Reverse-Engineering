#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
CC=${CC:-gcc}
"$CC" -O2 -march=native -o microbench microbench.c
for i in 1 2 3; do
    echo "run $i"
    ./microbench
done
