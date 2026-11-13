# Contributing to Victoria II Reverse Engineering

Thank you for contributing! This repository is an **evidence-based reverse engineering and performance research project** targeting `v2game.exe` (SHA-256 `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`).

## Core Rules

1. **No proprietary or binary assets in Git**:
   - Never commit game executables (`.exe`), DLLs (`.dll`), save files (`.v2`), Wine prefixes, raw memory dumps, or extensive raw decompilations.
   - Keep local game files in `base-game/` (gitignored) and never modify them in place.
2. **Evidence-based claims only**:
   - Distinguish clearly between `[confirmed]` (verified against binary/runtime/Unicorn/debugger output) and `[inferred]` hypotheses.
   - Include exact virtual addresses (`0x...`), offsets, ABI details, and reproducible commands/scripts for every finding.
3. **Repository hygiene**:
   - Do not hardcode personal home directories (e.g., `/home/<user>/...`); use repo-relative paths or environment variables (`V2_GAME_DIR`, `WINEPREFIX`, `V2_SAVE_SOURCE`).
   - Run `python3 -m py_compile` on any modified Python scripts and `git diff --check` before opening a PR.

## Pull Request Workflow

1. Fork the repository and create a descriptive branch from `main` (e.g. `research/<topic>` or `docs/<topic>`).
2. Keep changes focused and verify that CI workflows pass.
3. Fill out the PR template checklist completely.
4. All contributions are licensed under the repository's [MIT License](LICENSE).
