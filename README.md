# Victoria II Reverse Engineering Documentation

This repository documents static reverse engineering of `v2game.exe`, primarily using Ghidra.

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
- [Utility Functions](Engine/utilities.md) — renamed/reconstructed helper functions.
- [Reverse Engineering Conclusions](Engine/conclusions.md) — consolidated findings, limitations, and unresolved areas.
- [Daily Tick](Engine/daily-tick.md) — frame / hourly / daily call chain, `DayTick`, calendar, `Country_DailyUpdate` steps, the AI job queue and why a day spans several frames.
- [Performance Profile](Engine/performance-profile.md) — measured cost of a game day, the instructions the game waits on (cache misses on relations and pops), data layouts behind them.
- [Network (ENet)](Engine/network.md) — statically linked ENet, the session's 15/35 ms blocking poll every frame (also in single player).
- [Threads](Engine/threads.md) — the TBB `parallel_for` sites and why the big daily loops are not parallel-safe.
- [Triggers & Scopes](Engine/triggers-and-scopes.md) — trigger classes, `CEventScope` layout (self-pointer at +0x24), effects, keywords, thread safety of evaluation.
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


## Laboratorio de investigación reproducible

Los avances contrastados, modelos, verificadores, harnesses y scripts Ghidra están
en [research/](research/README.md). Incluye contratos de POPs, economía, IA, eventos
y combate con alcance, contraejemplos y procedimientos de reproducción explícitos.
Los binarios del juego, proyectos Ghidra, volcados y recibos generados permanecen
locales. Ver [alcance y preparación](research/docs/PUBLICATION.md) y
[resumen de la última validación local](research/validation-summary.json).
