# Victoria II Reverse Engineering Documentation

This repository documents evidence-based static and runtime reverse engineering of `v2game.exe` (SHA-256 `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`), primarily using Ghidra, Unicorn emulation, and controlled Wine instrumentation.

> **Scope & Legal Disclaimer:** This is an independent, clean-room reverse-engineering and performance research project. It is **not affiliated with or endorsed by Paradox Interactive**. Victoria II is a trademark of Paradox Interactive AB. No proprietary game binaries (`.exe`, `.dll`), game assets, save files (`.v2`), or extensive decompilations are distributed here. The [MIT License](LICENSE) applies solely to original documentation, analysis scripts, and clean-room prototypes authored in this repository.

## Repository Map & Maturity Status

| Area | Status | Purpose |
|---|---|---|
| [`Engine/`](Engine/), [`Economy/`](Economy/), [`AI/`](AI/), [`Technology/`](Technology/), [`Symbols/`](Symbols/) | **Reference docs** (`[confirmed]` / `[inferred]` tagged) | Architecture, subsystem semantics, symbols, and known patch targets ([`Patch/`](Patch/patch.md)). |
| [`research/`](research/README.md) & [`research/docs/contracts/`](research/docs/contracts/) | **Verified contracts** | Evidence-grounded behavioral contracts (POPs, economy, AI, combat, `HighPerfWinClock`, `Country_Recalculate`), Ghidra scripts, and verification harnesses. |
| [`research/perf/`](research/perf/README.md) & [`research/docs/perf/`](research/docs/perf/VERIFICATION-REPORT.md) | **Reproducible benchmarks & triage** | Fixed-save Wine baseline, 9-function hot-path triage ([`VERIFICATION-REPORT.md`](research/docs/perf/VERIFICATION-REPORT.md)), and A/B lab ([`P0-P2-LAB.md`](research/perf/P0-P2-LAB.md)). |
| [`experiments/p2-hook-lab/`](experiments/p2-hook-lab/README.md) | **Experimental R&D lab** | Hybrid P2 hook dispatcher (`C_hook`), `HighPerfWinClock` pilot, and `Country_Recalculate` variant (c) prototype (Unicorn + Wine harness validated; not an end-user mod). |
| [`experiments/three-phases/`](experiments/three-phases/), `experiments/tick-*-lab/` | **Experimental / clean-room R&D** | Reconstructed C tick-phase prototypes and build/verification labs. |
| [`tools/v2probe/`](tools/v2probe/README.md), [`CheatEngineTableVersion/`](CheatEngineTableVersion/) | **Auxiliary tooling** | Read-only RTTI probe plugin and community Cheat Engine memory tables. |

## Documentation Structure

### 📁 Engine
- [Engine Structure](Engine/engine-structure.md) — main loop, subsystem relationships, console, events, rendering, loans, and general engine architecture.
- [Entity Identity](Engine/entity-identity.md) — serialized state IDs, shared regions, and limits of POP identity across transitions.
- [Checksum](Engine/checksum.md) — how the game calculates the checksum.
- [Event](Engine/Event_System.md) — How the game creates and manages events
- [Message Dispatch](Engine/message-dispatch.md) — configurable popup/pause policy, nine instruction-site pairs, and notification/effect boundaries.
- [Script Execution Boundaries](Engine/script-execution-boundaries.md) — selected-option action execution versus event delivery, static region iteration, and attribution limits.
- [Game Speed System](Engine/game-speed.md) — speed index, update throttle, temporal processing, and B28 mapping.
- [RNG System](Engine/rng.md) — random-number list and Mersenne Twister regeneration path.
- [Country Daily Update](Engine/Country_Daily_Update.md) — How (developing) countries work.
- [Loading & Initialization](Engine/loading-initialization.md) — game-load finalization, state initialization, subsystem startup, and gameplay entry.
- [Buttons & Callbacks](Engine/buttons.md) — identified UI/button callbacks and their confidence levels.
- [Native Console](Engine/console.md) — command registration, bounded descriptor/call layouts, debug/FOW and dispatcher-identity limits.
- [Native UI & Frontend](Engine/native-ui-and-frontend.md) — named GUI lookup/signals, single-player save/load/Play, speed/pause, observer ownership, game-over detection and native exit.
- [Utility Functions](Engine/utilities.md) — renamed/reconstructed helper functions.
- [Reverse Engineering Conclusions](Engine/conclusions.md) — consolidated findings, limitations, and unresolved areas.
- [Daily Tick](Engine/daily-tick.md) — frame / hourly / daily call chain, `DayTick`, calendar, `Country_DailyUpdate` steps, the AI job queue and why a day spans several frames.
- [Performance Profile](Engine/performance-profile.md) — measured cost of a game day, the instructions the game waits on (cache misses on relations and pops), data layouts behind them.
- [Network (ENet)](Engine/network.md) — statically linked ENet, the session's 15/35 ms blocking poll every frame (also in single player).
- [Threads](Engine/threads.md) — the TBB `parallel_for` sites and why the big daily loops are not parallel-safe.
- [Triggers & Scopes](Engine/triggers-and-scopes.md) — trigger classes, `CEventScope` layout (self-pointer at +0x24), effects, keywords, thread safety of evaluation.
- [Political Reform Selection](Engine/political-reform-selection.md) — category-2 issue groups, country selection-array pointer, option registry, and narrow GFM current-selection evidence.
- [Decisions](Engine/decisions.md) — `CDecision`, the AI's daily decision loop and its CRT `rand()` roll, other evaluation sites.
- [Casus Belli Evaluation](Engine/Casus_Belli_Evaluation.md) — `cb_types.txt` loading, `IsAnyCBUsable` / `IsCBUsable`, who calls them daily.
- [Flag Atlases](Engine/flags.md) — how `flagfiles*.tga` are built, cached (TGA) and loaded (format from content), and their memory cost.

### 📁 Economy

* [Economy & Market](Economy/economy-market.md) — economic manager, supply/demand, prices, stockpiles, distribution, workers, and periodic economic processing.
* [Stockpiles](Economy/stockpiles.md) — artisan/factory stockpile subtraction and 64-bit good storage.
* [Banking and Credit](Economy/banking-and-credit.md) — loan principal, reserves, interest transfers and the unidentified state-to-POP payout path.
* [POP and Factory Storage](Economy/object-storage.md) — payload versus linked-node extents, traversal and factory injection fields.
* [Factory Construction](Economy/factory-construction.md) — factory construction validation, UI gates, state/type restrictions, and civilization checks.
* [Default & Debt Cleanup](Economy/default-and-debt-cleanup.md) — separates interest-shortfall handling, conditional construction refunds, and guarded creditor removal.
* [Production Identity & Clearing](Economy/production-identity-and-clearing.md) — RGO capacity/owner modifiers, narrow factory transfer identity, and clearing/attribution limits.
* [Economy Daily Path](Economy/economy-daily-path.md) — the daily economy call path, per-pop list walks, shared state, fixed-point price bounds (2^15) and corrections.


### 📁 Technology
- [Technology System](Technology/technology.md) — technology availability, player/AI research paths, civilization gates, and confirmed research patches.

### 📁 AI

- [National Focus AI](AI/Ai_national_focus.md) — The factors that lead the AI ​​to focus national attention on its country (soldiers, capital, etc.)
- [Relations AI](AI/Ai_relations.md) — Factors influencing an AI to accept an alliance, military access, etc
- [AI Daily Jobs](AI/Ai_daily_jobs.md) — the AI queue at `world+0xB84`, the 20 ms per-frame budget, `AI_CountryDailyJob_Update` and `AI_TargetScan`.
- [Random selection over an effect list](AI/Ai_random_selection.md) — `FUN_00876240`: the `rand() % count` pick over 8-byte pairs, its eleven filter exits and the two result bytes of `CEventScope`.

### 📁 Patches
- [Patch Registry](Patch/patch.md) — **all currently documented patch targets**, kept separate from vanilla behavior.

### 📁 Symbols
- [Symbols (CSV)](Symbols/README.md) — function names, globals and struct offsets as CSV (`va, name, conf, area, src, note`).

### 📁 Tools
- [v2probe](tools/v2probe/README.md) — The Grand Loader plugin with read-only hooks for the AI job; resolves live object types through MSVC RTTI instead of guessing offsets.

### 📁 CheatEngineTable 
- Cheat Engine Table — memory tables, dynamic analysis, and runtime address mapping.

## Methodology

Addresses shown in Ghidra are virtual addresses (VA). They must be converted to the corresponding executable **file offsets** before modifying `v2game.exe`.

Experimental modifications are explicitly separated from confirmed vanilla behavior. A patch should be applied only after verifying the expected original bytes at the target location.

## Source Scope & Credits

- These documents are derived from the reverse-engineering notes supplied for this project. Unconfirmed interpretations remain labeled as such.
- **Cheat Engine Credits:** Special thanks to **Vesper** for the research, tables, and memory structures included in the `CheatEngineTable Version` directory.


## Reproducible Research & Performance Labs

Verified findings, invariant contracts, harnesses, and Ghidra scripts live in [`research/`](research/README.md). Game binaries, Ghidra projects, raw memory dumps, and Wine prefixes always remain local (see [publication scope](research/docs/PUBLICATION.md) and [latest local validation summary](research/validation-summary.json)).

Key performance & hybrid-hook entry points:
- [P0–P2 Verification Report](research/docs/perf/VERIFICATION-REPORT.md) — baseline profiling, 9 hot-function triage dossiers (`PASS`), and `HighPerfWinClock` / `Country_Recalculate` readiness.
- [P2 Hook Architecture](research/docs/perf/P2-HOOK-ARCHITECTURE.md) — register-safe dispatcher (`C_hook`), `shadow`/`prod`/`bypass` modes, and ENet wait audit.
- [P0–P2 Benchmark Lab](research/perf/P0-P2-LAB.md) — headless Wine baseline, determinism checks, and A/B measurements.
- [P2 Hook Lab (`experiments/p2-hook-lab/`)](experiments/p2-hook-lab/README.md) — `llvm-mingw` hook blob, Unicorn equivalence tests, and Wine host harness.
