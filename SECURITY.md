# Security Policy

## Scope

This repository contains reverse-engineering documentation, research scripts, clean-room reimplementation prototypes, and native hook experiments. It does **not** distribute proprietary game binaries.

Security reports in scope include:
- Vulnerabilities in repository scripts, build tools, or native hook/plugin prototypes (e.g., memory corruption, arbitrary code execution, unsafe deserialization, or supply-chain issues in CI workflows).
- Accidental inclusion of credentials, tokens, private paths, or proprietary binaries in the repository.

Issues in the unmodified proprietary `v2game.exe` binary itself are outside the control of this project unless they affect our hook/plugin interfaces.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Instead, report privately using **GitHub Private Vulnerability Reporting** (*Security → Advisories → Report a vulnerability* on the repository) or contact the repository maintainers directly.

We aim to acknowledge reports within 72 hours and coordinate a fix before public disclosure.
