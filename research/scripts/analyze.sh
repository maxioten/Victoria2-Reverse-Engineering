#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/../env.sh"
mkdir -p "$V2_RE_ROOT/projects/tool-home" "$V2_RE_ROOT/evidence/generated/ghidra"
export JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS:-} -Duser.home=$V2_RE_ROOT/projects/tool-home"
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" \
  "$V2_RE_ROOT/projects" victoria2-3.04 \
  -import "$V2_RE_ROOT/../base-game/v2game.exe" \
  -scriptPath "$V2_RE_ROOT/ghidra_scripts" \
  -postScript ExportEvidence.java "$V2_RE_ROOT/evidence/generated/ghidra" \
  -max-cpu 4 -analysisTimeoutPerFile 600 \
  -log "$V2_RE_ROOT/evidence/generated/ghidra/analysis.log" \
  -scriptlog "$V2_RE_ROOT/evidence/generated/ghidra/script.log"
"$V2_RE_ROOT/.venv/bin/python" "$script_dir/analysis_status.py"
