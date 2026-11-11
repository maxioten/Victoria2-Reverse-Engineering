#!/usr/bin/env bash
# Build v2migrate.dll. Prefers the pinned local toolchain (llvm-mingw,
# validated end-to-end in-game); falls back to mingw-w64 gcc if present.
set -euo pipefail
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
llvm_cc="$HOME/Documentos/v2/tools/llvm-mingw/llvm-mingw-20261104-msvcrt-ubuntu-22.04-x86_64/bin/i686-w64-mingw32-clang"
if [ -x "$llvm_cc" ]; then
  compiler="$llvm_cc"
else
  compiler="${V2MIGRATE_CC:-i686-w64-mingw32-gcc}"
fi
mkdir -p "$project_dir/build"
"$compiler" -std=c11 -O2 -Wall -Wextra -fno-strict-aliasing \
  -shared "$project_dir/src/plugin.c" "$project_dir/src/hooks.S" \
  -Wl,--kill-at,--dynamicbase,--nxcompat \
  -o "$project_dir/build/v2migrate.dll"
file "$project_dir/build/v2migrate.dll"
