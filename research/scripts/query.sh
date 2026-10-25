#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/../env.sh"
if [[ ! "${1:-}" =~ ^0x[[:xdigit:]]+$ ]]; then
  echo 'Uso: bash research/scripts/query.sh 0xRVA' >&2
  exit 2
fi
export JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS:-} -Duser.home=$V2_RE_ROOT/projects/tool-home"
exec "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$V2_RE_ROOT/projects" victoria2-3.04 \
  -process v2game.exe -readOnly -noanalysis -scriptPath "$V2_RE_ROOT/ghidra_scripts" \
  -postScript QueryEvidence.java "$1" "$V2_RE_ROOT/evidence/generated/queries"
