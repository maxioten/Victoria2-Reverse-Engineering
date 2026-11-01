# PART II — GENERAL ENGINE STRUCTURE, ECONOMY, CONSOLE AND FOG OF WAR

For state IDs, shared region definitions, and POP identity limits, see
[Entity identity](entity-identity.md). These narrow findings do not establish full object layouts.

```text
00AB0F91
  ENTRY
    |
    v
009DF550
  MAIN LOOP
    |
    +-- 009796B0
    |     WINMAIN / CLAUSEWITZ ENGINE
    |
    +-- 0068BF00
    |     ECONOMY
    |
    +-- AI
    |     |
    |     +-- AI_SimpleThresholdCheck
    |             |
    |             v
    |         EVENT SYSTEM
    |           008A67B0
    |
    +-- CONSOLE COMMANDS 
    |     |
    |     +-- debug command handler (00420eb0)
    |
    +-- RENDERING / FOG OF WAR
    |     |
    |     +-- FUN_0099da20
    |     +-- FUN_006592f0
    |
    +-- LOANS
    |     |
    |     +-- 00523400
    |
    +-- OTHER TICK SYSTEMS
          |
          +-- Country updates
          +-- POP updates
          +-- AI updates
          +-- Economy updates
          +-- Event updates
          +-- War updates
          +-- World updates
```

## DETAILED ECONOMIC FLOW

```text
0068BF00
  ECONOMY_UPDATE
    |
    v
WORLD MARKET UPDATE (00484060)
    |
    v
00482930
  UPDATE SUPPLY
    |
    +-- SUPPLY
    +-- DEMAND
    +-- 64-BIT COMPARISON
    +-- SIGNEDDIVIDEINT64
    +-- CALCULATESUPPLYMULTIPLIER
    |
    v
00482B...
  UPDATE PRICE
    |
    +-- BASE PRICE
    +-- MULTIPLIER
    +-- MINIMUM LIMIT
    |     DAT_00E45C30
    |     ×0.2 VANILLA
    |
    +-- MAXIMUM LIMIT
    |     DAT_00E45C28
    |     ×5.0 VANILLA
    |
    v
  FINAL PRICE
```

## EVENT FLOW

```text
AI_SIMPLETHRESHOLDCHECK
    |
    +-- Checks conditions
    +-- Checks thresholds
    +-- Makes calls related to events
    |
    v
008A67B0
  EVENT SYSTEM
```


## EVENT_SYSTEM

008A67B0
EVENT RESOURCE / EVENT MANAGER SYSTEM
        |
        +-- FUN_008A5AC0
        |     INITIALIZE EVENT MANAGER
        |
        +-- FUN_008A5C70
        |     INITIALIZE EVENT STRUCTURE
        |
        +-- FUN_009A1440
        |     INITIALIZE EVENT OBJECT
        |
        +-- FUN_008A6010
        |     GET MAIN EVENT NAME
        |
        +-- FUN_008A60F0
        |     GET SECONDARY EVENT NAME
        |
        +-- FUN_008A67B0
              LOAD EVENT RESOURCES
              
## CONSOLE

The native descriptor table registers `FUN_00420EB0` as the `debug` handler,
not an established universal console dispatcher. Its arguments include `fow`;
the reviewed branch directly toggles `0x00F092FB`, with zero meaning revealed
map in the checked runtime route.

[Console registration and native commands](console.md) documents the manager,
descriptors, invocation records and primary toggle sites. The earlier disabling
experiment does not establish a generic dispatch ABI. The relationship to the
historically labelled renderer flag `0x013F080C` and mirror
`[0x01258A74 + 0x6BC44]` remains unresolved.

## FOG OF WAR

Important structures:

```text
DAT_01258a74
    ↓
graphics/render device singleton

DAT_013f080c
    ↓
global FoW state
```

`FUN_0099da20` participates in graphics initialization/restore.

`FUN_006592f0` runs in the per-frame rendering path.

Experimental direct JZ→NOP patches were confirmed to break:

```text
FUN_0099da20 → text/UI rendering
FUN_006592f0 → terrain/map textures
```

Therefore the direct branch patches are not safe final FoW patches.

The preceding condition around:

```text
0x6594B4
```

still needs to be understood before implementing a clean permanent FoW-off patch.


# PART IX — GENERAL ENGINE STRUCTURE

```text
00AB0F91
  ENTRY
    |
    v
009DF550
  MAINLOOP
    |
    v
009796B0
  WINMAIN / CLAUSEWITZ ENGINE
    |
    +-- TIME
    |     |
    |     +-- 00685620
    |     +-- 00682BD0
    |
    +-- ECONOMY
    |     |
    |     +-- 0068BF00
    |     +-- 00520150
    |     +-- 006859C0
    |     +-- 00482930
    |     +-- 00482B...
    |
    +-- MARKET
    |     |
    |     +-- SUPPLY
    |     +-- DEMAND
    |     +-- PRICE
    |     +-- STOCKPILES
    |
    +-- AI
    |     |
    |     +-- AI_SimpleThresholdCheck
    |     +-- EVENT_SYSTEM
    |
    +-- CONSOLE
    |     |
    |     +-- console_commands
    |
    +-- RENDERING / FOW
    |     |
    |     +-- FUN_0099da20
    |     +-- FUN_006592f0
    |
    +-- LOANS
    |     |
    |     +-- 00523400
    |
    +-- GAME LOAD
    |     |
    |     +-- 00662010
    |
    +-- THREADS
    |     |
    |     +-- 00A7AED0
    |     +-- 00A7B0C0
    |     +-- 00A7B090
    |
    +-- OTHER SYSTEMS
          |
          +-- War
          +-- POPs
          +-- Countries
          +-- Research
          +-- Diplomacy
          +-- Events
          +-- Market
          +-- Rendering
```

---
