#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/../env.sh"
# Dedicated Wine prefix: debugging configuration never changes the player's prefix.
export WINEPREFIX="$V2_RE_ROOT/projects/wine-debug"
exec wine "$V2_RE_ROOT/../tools/x64dbg/release/x32/x32dbg.exe" \
  "$V2_RE_ROOT/../base-game/v2game.exe" "$@"
