# Victoria II Reverse Engineering Documentation

This repository documents static reverse engineering of `v2game.exe`, primarily using Ghidra.

## Documentation Structure

### 📁 Engine
- [Engine Structure](Engine/engine-structure.md) — main loop, subsystem relationships, console, events, rendering, loans, and general engine architecture.
- [Game Speed System](Engine/game-speed.md) — speed index, update throttle, temporal processing, and B28 mapping.
- [RNG System](Engine/rng.md) — random-number list and Mersenne Twister regeneration path.
- [Loading & Initialization](Engine/loading-initialization.md) — game-load finalization, state initialization, subsystem startup, and gameplay entry.
- [Buttons & Callbacks](Engine/buttons.md) — identified UI/button callbacks and their confidence levels.
- [Utility Functions](Engine/utilities.md) — renamed/reconstructed helper functions.
- [Reverse Engineering Conclusions](Engine/conclusions.md) — consolidated findings, limitations, and unresolved areas.

### 📁 Economy

* [Economy & Market](Economy/economy-market.md) — economic manager, supply/demand, prices, stockpiles, distribution, workers, and periodic economic processing.
* [Stockpiles](Economy/stockpiles.md) — artisan/factory stockpile subtraction and 64-bit good storage.
* [Factory Construction](Economy/factory-construction.md) — factory construction validation, UI gates, state/type restrictions, and civilization checks.


### 📁 Technology
- [Technology System](Technology/technology.md) — technology availability, player/AI research paths, civilization gates, and confirmed research patches.

### 📁 Patches
- [Patch Registry](Patches/patches.md) — **all currently documented patch targets**, kept separate from vanilla behavior.

### 📁 CheatEngineTable 
- Cheat Engine Table — memory tables, dynamic analysis, and runtime address mapping.

## Methodology

Addresses shown in Ghidra are virtual addresses (VA). They must be converted to the corresponding executable **file offsets** before modifying `v2game.exe`.

Experimental modifications are explicitly separated from confirmed vanilla behavior. A patch should be applied only after verifying the expected original bytes at the target location.

## Source Scope & Credits

- These documents are derived from the reverse-engineering notes supplied for this project. Unconfirmed interpretations remain labeled as such.
- **Cheat Engine Credits:** Special thanks to **Vesper** for the research, tables, and memory structures included in the `CheatEngineTable Version` directory.
