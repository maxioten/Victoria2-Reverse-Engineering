# PART X — IMPORTANT REVERSE ENGINEERING CONCLUSIONS

## ECONOMY

The economy is not a single function.

It consists of multiple layers:

```text
ECONOMIC MANAGER
       │
       ├── economic distribution
       │
       ├── economic list rebuilding
       │
       ├── market processing
       │
       ├── supply/demand
       │
       ├── price calculation
       │
       ├── periodic accounting
       │
       ├── POP economic updates
       │
       └── economic entry processing
```

The most important confirmed market price path remains:

```text
SUPPLY
  ↓
DEMAND
  ↓
COMPARISON
  ↓
SIGNED INT64 DIVISION
  ↓
SUPPLY MULTIPLIER
  ↓
PRICE
  ↓
MIN/MAX LIMITS
```

## STOCKPILES

Goods use a combination of:

```text
bitflags / positional indices
+
64-bit stockpile vector
```

The stockpile vector uses:

```text
8-byte entries
```

and therefore supports large quantities beyond a simple 32-bit integer representation.

## PRICE MODDING

The safest modification strategy is:

```text
DO NOT REPLACE:
Supply
Demand
Comparison
Division
Multiplier

ONLY MODIFY:
Minimum limit
Maximum limit
```

Desired:

```text
0.2 → 0.1
5.0 → 10.0
```

## PERIODIC ECONOMIC PROCESSING

`FUN_006859C0` appears to be a periodic calendar/economic accounting routine.

Working name:

```text
Economy_ProcessMonthlyTick
```

but the exact period still requires final calendar confirmation.

It appears to:

```text
determine calendar period
        ↓
process economic entities
        ↓
accumulate economic categories
        ↓
update historical economic report
```

## LOAD INITIALIZATION

`FUN_00662010` appears to be a one-time:

```text
Game_FinalizeLoadAndEnterGameplay
```

routine.

It performs:

```text
load-state transition
resolution setup
configuration loading
input/event registration
entity reset
subsystem initialization
entity integrity repair
configuration caching
spatial registration
load-time measurement
gameplay state transition
subsystem callbacks
```

It should not be confused with recurring economy/tick processing.

## MULTITHREADING

The executable already contains a generic worker-thread framework:

```text
CreateThread
    ↓
FUN_00A7AED0
    ↓
FUN_00A7B0C0
    ↓
FUN_00A7B090
    ↓
virtual worker body
```

However, the economic processing itself contains shared accumulators.

Therefore:

```text
EXISTENCE OF THREAD SYSTEM
        ≠
ECONOMY IS ALREADY PARALLEL
```

and:

```text
ADDING THREADS DIRECTLY TO ECONOMY
        ↓
LIKELY DATA RACES
```

Private accumulators followed by a merge are the safer long-term design.


# NOTES

```text
+-- Event function names remain tentative until their XREFs are fully
|   confirmed.
|
+-- 008A67B0 appears related to loading/managing event resources, but
|   it is not yet confirmed as the main event execution point.
|
+-- AI_SimpleThresholdCheck appears related to checks that may interact
|   with the event system.
|
+-- Removing event-system calls allowed some battles to start, but the
|   game later crashed after several days.
|
+-- Therefore event processing probably participates in later
|   maintenance/processing.
|
+-- Economy should preserve:
|      Supply → Demand → Comparison → Division →
|      Multiplier → Price → Limits
|
+-- console_commands is empirically confirmed as the central console
|   dispatcher. Disabling it removes all console commands.
|
+-- The "fow" command toggles DAT_013f080c, but changing the global flag
|   alone is insufficient to force FoW permanently off.
|
+-- Direct JZ→NOP patches in the rendering functions break their
|   respective rendering layers.
|
+-- FUN_006592f0 requires further inspection of the preceding condition
|   around 0x6594B4 before a final FoW patch is attempted.
|
+-- Generic helpers such as Buffer_ScaleValuesInRange,
|   Market_ComputeScaledDotProduct and the clamp routines are heavily
|   reused and should not automatically be considered market-specific.
|
+-- 00487410 is confirmed as a demand-side function in the inspected
|   path.
|
+-- 0047DCA0 confirms the relationship between good bitflags and the
|   64-bit stockpile vector.
|
+-- 00520150 contains shared economic accumulators and therefore should
|   not be naively parallelized.
|
+-- FUN_00969760 performs shared economic accumulation and is currently
|   considered unsafe for concurrent execution on the same object.
|
+-- The worker-thread framework exists, but the actual expensive worker
|   body is still being traced through the object at [ESI+0x18].
|
+-- FUN_006859C0 is currently best understood as a periodic economic /
|   calendar processing routine. "Monthly" is still a working name.
|
+-- FUN_00662010 is currently best understood as a one-time game-load
|   finalization and gameplay-entry routine.
|
+-- The 0x70-byte economic report structure and its individual category
|   meanings remain pending field-by-field reconstruction.
|
+-- Experimental patches must remain clearly separated from vanilla
|   behavior in the documentation.
```

