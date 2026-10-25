#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/../env.sh"
export JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS:-} -Duser.home=$V2_RE_ROOT/projects/tool-home"
pass_dir="$(mktemp -d "$V2_RE_ROOT/evidence/generated/ghidra-resumed-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")"
echo "$pass_dir" > "$V2_RE_ROOT/evidence/generated/latest-resume.txt"
echo "Nueva pasada de Ghidra: $pass_dir"
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$V2_RE_ROOT/projects" victoria2-3.04 \
  -process v2game.exe -scriptPath "$V2_RE_ROOT/ghidra_scripts" \
  -preScript StabilizeReturningWrapper.java "$pass_dir/pre-analysis" \
  -postScript CorrectNullRelease.java "$pass_dir/analysis-corrections" \
  -postScript AnnotateRng.java "$pass_dir/analysis-annotations" \
  -max-cpu 4 -analysisTimeoutPerFile 1200 \
  -log "$pass_dir/analysis.log"
# Post-scripts can trigger another autoanalysis pass. Export only after saving
# and reopening read-only, so the snapshot describes the actual saved project.
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$V2_RE_ROOT/projects" victoria2-3.04 \
  -process v2game.exe -readOnly -noanalysis -scriptPath "$V2_RE_ROOT/ghidra_scripts" \
  -postScript AuditReturningWrapper.java "$pass_dir" \
  -postScript ExportEvidence.java "$pass_dir" \
  -log "$pass_dir/export.log"
"$V2_RE_ROOT/.venv/bin/python" "$script_dir/analysis_status.py" --output "$pass_dir" --existing-project --require-audit
echo 'Revisión guardada. Ver status.json para el límite de esta pasada.'
