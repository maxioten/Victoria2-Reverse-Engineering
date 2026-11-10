#!/usr/bin/env bash
# Compile every pcrecomp-generated C file to an object, 8 at a time.
set -u
ROOT=${V2_ROOT:-$(cd "$(dirname "$0")/../../.." && pwd)}
GEN=${GEN:-$ROOT/work/src/recomp/gen}
OUT=${OUT:-$ROOT/work/build}
LOGS=${LOGS:-$ROOT/work/logs/compile}
INC=${INC:-${PCRECOMP_SRC:-$ROOT/pcrecomp}/runtime/recomp32}
JOBS=${JOBS:-8}
mkdir -p "$OUT" "$LOGS"

one() {
    f="$1"
    b=$(basename "$f" .c)
    if [ -f "$OUT/$b.status" ] && [ -f "$OUT/$b.o" ]; then
        read -r _b rc _ms < "$OUT/$b.status"
        if [ "$rc" = 0 ]; then echo "skip $b"; return; fi
    fi
    start=$(date +%s%N)
    timeout 1800 gcc -c -O0 -w -I "$INC" -include "$GEN/recomp_funcs.h" "$f" -o "$OUT/$b.o" > "$LOGS/$b.log" 2>&1
    rc=$?
    end=$(date +%s%N)
    ms=$(( (end - start) / 1000000 ))
    printf '%s\t%s\t%s\n' "$b" "$rc" "$ms" > "$OUT/$b.status"
}
export -f one
export GEN OUT LOGS INC

ls "$GEN"/recomp_*.c | xargs -P "$JOBS" -I{} bash -c 'one "$@"' _ {}
