#!/usr/bin/env bash
set -euo pipefail
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
compiler="${V2PROBE_CC:-i686-w64-mingw32-gcc}"
mkdir -p "$project_dir/build"
"$compiler" -std=c11 -O2 -Wall -Wextra -fno-strict-aliasing \
  -shared "$project_dir/src/plugin.c" "$project_dir/src/hooks.S" \
  -Wl,--kill-at,--dynamicbase,--nxcompat,-Map,"$project_dir/build/v2probe.map" \
  -o "$project_dir/build/v2probe.dll"
file "$project_dir/build/v2probe.dll"
