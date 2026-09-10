# PART VI — DETAILED MARKET / ECONOMY SYSTEM

## MAP 14 — COMPLETE ECONOMIC MANAGER FLOW

The economic manager is substantially larger than the simple `WorldMarket_Update` path.

Current consolidated structure:

```text
0068BF00
EconomyManager_UpdateFull
   |
   +--> 00520150
   |    CalculateEconomicDistribution
   |       |
   |       +--> large nested loops
   |       |
   |       +--> economic entries
   |       |
   |       +--> shared accumulators
   |       |
   |       +--> per-good accumulators
   |
   +--> EconomyManager_RebuildEconomicLists (0068d250)
   |
   +--> 00482930
   |    UpdateSupply
   |       |
   |       +--> SUPPLY
   |       +--> DEMAND
   |       +--> 64-bit comparison
   |       +--> SignedInt64Divide
   |       +--> CalculateSupplyMultiplier
   |       |
   |       v
   |    00482B...
   |    UpdatePrice
   |       |
   |       +--> BASE PRICE
   |       +--> MULTIPLIER
   |       +--> MIN PRICE
   |       +--> MAX PRICE
   |       +--> FINAL PRICE
   |
   +--> 004808D0
   |    ProcessMarketAndGoodsDistribution
   |
   +--> EconomyManager_PrepareEconomicUpdate (0068d950)
   |
   +--> Economy_Update(...,0)
   +--> Economy_Update(...,1)
   +--> Economy_Update(...,2)
   +--> Economy_Update(...,3)
   +--> Economy_Update(...,4)
   |
   +--> EconomyManager_ProcessEconomicEntries (0068dc70)
```

The exact semantic meaning of the five `Economy_Update (00489990)` passes remains under investigation.

The overall flow is nevertheless clearly centered around economic distribution, market calculations and periodic economic processing.


# MAP 15 — SUPPLY / DEMAND / PRICE PIPELINE

The most important market path currently reconstructed is:

```text
                    MARKET
                      │
                      ▼
              00482930
           UpdateSupply
                      │
          ┌───────────┴───────────┐
          │                       │
          ▼                       ▼
       SUPPLY                   DEMAND
          │                       │
          └───────────┬───────────┘
                      ▼
              64-BIT COMPARISON
                      │
                      ▼
             SignedInt64Divide
                      │
                      ▼
          CalculateSupplyMultiplier (00482610)
                      │
                      ▼
                00482B...?
              UpdatePrice
                      │
          ┌───────────┴───────────┐
          │                       │
          ▼                       ▼
      BASE PRICE              MULTIPLIER
          │                       │
          └───────────┬───────────┘
                      ▼
                PRICE LIMITS
                 /        \
                /          \
               ▼            ▼
           MINIMUM        MAXIMUM
          ×0.2 vanilla    ×5.0 vanilla
               │            │
               └─────┬──────┘
                     ▼
                FINAL PRICE
```

This vanilla flow should be preserved when modifying the price system.


# MAP 16 — PRICE LIMITS

Vanilla:

```text
MINIMUM PRICE
    =
BASE PRICE × 0.2
```

Address:

```text
DAT_00E45C30
```

Maximum:

```text
MAXIMUM PRICE
    =
BASE PRICE × 5.0
```

Address:

```text
DAT_00E45C28
```

Desired modified limits:

```text
MINIMUM = BASE PRICE × 0.1
MAXIMUM = BASE PRICE × 10.0
```

The objective is:

```text
Supply
  ↓
Demand
  ↓
Comparison
  ↓
64-bit division
  ↓
Supply multiplier
  ↓
Price calculation
  ↓
NEW LIMITS
  ↓
Final price
```

The vanilla supply/demand calculation must not be replaced.

Previous experimental modifications that replaced too much of the vanilla logic produced pathological behavior such as:

```text
supply > demand → price ≈ 0.01
supply < demand → price ≈ 1000
```

Therefore the correct approach is to modify the limits only.


# MAP 17 — PRICE LIMIT PATCH TARGETS

The lower-limit instruction was identified around:

```text
00482C46
```

with:

```asm
FLD qword ptr [DAT_00E45C30]
```

Current intended patch:

```text
DAT_00E45C30
    0.2
      ↓
    0.1
```

Upper limit:

```text
DAT_00E45C28
    5.0
      ↓
    10.0
```

These are the preferred patch points because they preserve the upstream supply/demand calculation.


# MAP 18 — MARKET DEMAND AGGREGATION

## `FUN_00487410`

Proposed name:

```text
ProcessGoodSupplyAndDemand
```

Status:

```text
CONFIRMED — DEMAND PATH
```

The function was inspected closely and confirmed to modify demand rather than supply.

Relevant instruction:

```asm
004877B1
LEA EAX,[EDX+EAX*8]
```

Interpretation:

```text
EDX
 ↓
real_demand container

EAX
 ↓
index into real_demand
```

Conceptually:

```text
GOOD
 │
 ▼
real_demand[good]
 │
 ▼
ADD REAL DEMAND
```

This is important because a function that appears to handle both "supply and demand" by name was experimentally determined to operate on the demand side in this path.


# MAP 19 — STOCKPILE CONTRIBUTION TO MARKET STATISTICS

Function:

```text
Buffer_AccumulateIndexedValue
```

Likely address:

```text
0047DC20
```

Important instructions:

```asm
0047DC56
MOV EDI,[ECX+EDX*8]

0047DC59
ADD [EAX],EDI
```

Interpretation:

```text
ECX + EDX*8
        ↓
stockpile amount

EDI
        ↓
amount

[EAX]
        ↓
global supply/demand accumulator
```

Depending on calling context, `[EAX]` represents the corresponding market accumulator.

This connects individual stockpiles to larger market statistics.


# MAP 20 — GENERIC MARKET / BUFFER HELPERS

Several functions were identified during the market investigation.

## `FUN_0047E3E0`

Proposed name:

```text
Market_ComputeScaledDotProduct 
```

Observed usage:

```text
~58 places
```

Current conclusion:

```text
Probably generic mathematical utility.
Not confirmed as market-specific.
```

## `FUN_0047DE60`

Proposed name:

```text
Buffer_ScaleValuesInRange
```

Alias:

```text
multiply_values_in_vector
```

Observed usage:

```text
~53 places
```

Operates on vectors / contiguous memory blocks.

Current conclusion:

```text
Generic vector/buffer helper.
```

## `FUN_0043A880`

```text
vector_resize
```

Generic vector resizing routine.

## `0x0047D9E0`

```text
clamp_0_to_arg8h_&_argch
```

Generic clamping routine.

## `FUN_004DD470`

Proposed name:

```text
multiply_goods_clamp_0_99999
```

Important constant:

```text
0xC34F8000
```

which corresponds to the fixed-point representation of approximately:

```text
99999
```

This function multiplies goods-related quantities and clamps the result to the expected range.


# MAP 21 — PER-POP ECONOMIC UPDATE

Function:

```text
Market_UpdatePopContributions (00485E40)
```

Proposed name:

```text
pop_daily_update_money
```

Observed responsibilities include:

```text
POP money
POP needs
needs met
bank / savings related values
other daily economic state
```

This function is likely downstream from the broader economic manager and represents per-POP economic processing rather than the global market calculation itself.


# MAP 22 — ECONOMIC DISTRIBUTION

## `00520150 — CalculateEconomicDistribution`

This function contains a large nested-loop structure.

Important loop:

```text
005205DA
MOV [EBP-0x14],0

005205E7
MOV [EBP-0x44],0

LAB_005205F0:

005205F0
MOV EDX,[EBP-0x3C]

005205F3
MOV EAX,[EDX+0x194]

005205F9
MOV ECX,[EBP-0x44]

005205FC
MOV ESI,[ECX+EAX]

005205FF
MOV EAX,[EBP-0x1C]

00520602
MOV EDX,[EAX+0x10]

00520605
SUB EDX,[EAX+0x0C]

00520608
SAR EDX,2

0052060E
MOV [EBP-0x5C],ESI

00520611
CMP ECX,EDX

00520613
JLE 0052061C

00520615
CALL FUN_0096BB70

0052061A
JMP 00520622

0052061C
MOV EAX,[EAX+0x0C]

0052061F
MOV EAX,[EAX+ECX*4]

00520622
MOV ECX,[EAX+0x3C]

00520625
MOV [EBP-0x2C],ECX

00520628
TEST ESI,ESI

0052062A
JZ 005208EE
```

The inner processing can repeat:

```text
005208E4
CMP [EBP-0x5C],0

005208E8
JNZ 00520630
```

before the outer iteration advances.

Outer-loop advancement:

```text
005208EE
MOV EAX,[EBP-0x14]

005208F1
ADD [EBP-0x44],0x10

005208F5
INC EAX

005208F6
MOV [EBP-0x14],EAX

005208F9
CMP EAX,[EBP-0x18]

005208FC
JL 005205F0
```

Therefore:

```text
outer index
    ↓
[EBP-0x44] += 0x10
    ↓
inner economic processing
    ↓
shared accumulators
    ↓
next economic entry
```


# MAP 23 — SHARED ECONOMIC ACCUMULATORS

The economic distribution loop writes to shared fields including:

```text
this + 0x8D8 + i*8
this + 0x900 + i*8
```

using 64-bit arithmetic:

```text
ADD
ADC
```

Other observed shared state includes:

```text
this + 0x13E8
this + 0x13EC
```

and:

```text
[EDI+0x274] + 0x28
```

with values related to:

```text
[EDI+0x58]
```

There are also local 64-bit accumulators:

```text
[EBP-0x34]
[EBP-0x30]
```

These observations indicate that the function is not simply a read-only iteration over independent entries.


# MAP 24 — MULTITHREADING / RACE CONDITION WARNING (UNDER DEVELOPMENT – NOT FINISHED)

The economic distribution loop is **not currently safe for naive parallelization**.

Conceptually:

```text
CPU0 ──┐
CPU1 ──┤
CPU2 ──┤──► SHARED ACCUMULATORS
CPU3 ──┘
```

Multiple iterations may modify the same:

```text
this + 0x8D8 + i*8
this + 0x900 + i*8
this + 0x13E8
this + 0x13EC
```

Therefore a naive:

```text
one thread = one outer iteration
```

could produce races and corrupted economic totals.

Preferred architecture:

```text
CPU0 → PRIVATE ACCUMULATORS
CPU1 → PRIVATE ACCUMULATORS
CPU2 → PRIVATE ACCUMULATORS
CPU3 → PRIVATE ACCUMULATORS
                │
                ▼
              MERGE
                │
                ▼
       SHARED ESI ACCUMULATORS
```

Fine-grained atomics around every `ADD/ADC` are probably too expensive for a simulation running continuously.

The first safe multithreading experiment should therefore be a harmless worker-thread test before moving economic work into parallel workers.


# MAP 25 — ECONOMIC HELPER `FUN_00969760`

`FUN_00969760` was investigated as a possible economic worker/helper.

Proposed Spanish names:

```text
AccumulateEconomicDataForElement
```

or:

```text
AccumulateEconomicData
```

The function performs many shared `+=` operations on the same object/state.

Current conclusion:

```text
NOT SAFE to execute concurrently on the same object
without separating accumulators or synchronization.
```

This is another indication that the economy cannot simply be made multithreaded by duplicating the existing calls.


# MAP 26 — WORKER THREAD SYSTEM (UNDER DEVELOPMENT (INCOMPLETE))

A separate worker-thread mechanism was identified in the executable. 

## `FUN_00A7AED0`

Proposed name:

```text
CreateWorkerThread
```

It uses the imported:

```text
CreateThread
```

Import address:

```text
00C8A1A8
```

Observed standard parameters:

```text
lpThreadAttributes = 0
dwStackSize        = 0
lpStartAddress     = FUN_00A7B0C0
lpParameter        = allocated 8-byte block containing this
dwCreationFlags    = 0
lpThreadId         = &ESI+4
```

The resulting thread HANDLE is stored at:

```text
[ESI+0x08]
```

and:

```text
[ESI+0x1C]
```

participates in thread priority/control state.


## `FUN_00A7B0C0`

Proposed name:

```text
WorkerThreadEntry
```

The function:

```text
1. frees the parameter block
2. obtains the worker object's vtable
3. reaches the worker dispatch function
```

Important virtual slot:

```text
vtable + 0x14
```

This points to:

```text
FUN_00A7B090
```


## `FUN_00A7B090`

This is the worker wrapper/dispatcher.

```asm
00A7B090  PUSH ESI
00A7B091  MOV ESI,ECX
00A7B093  CALL [GetCurrentThreadId]

00A7B099  CMP EAX,[ESI+0x0C]
00A7B09C  JNZ 00A7B0A2

00A7B09E  XOR EAX,EAX
00A7B0A0  POP ESI
00A7B0A1  RET

LAB_00A7B0A2:

00A7B0A2  MOV ECX,[ESI+0x18]
00A7B0A5  MOV EAX,[ECX]
00A7B0A7  MOV EDX,[EAX+0x4]
00A7B0AA  CALL EDX

00A7B0AC  MOV EAX,1
00A7B0B1  POP ESI
00A7B0B2  RET
```

Important observation:

```text
[ESI+0x18]
       ↓
object containing another vtable
       ↓
vtable + 0x04
       ↓
ACTUAL WORKER BODY
```

Therefore `FUN_00A7B090` itself is not necessarily the expensive worker function.


## Worker vtable

At:

```text
00E439F8
```

observed entries:

```text
+0x00 → 00A7AED0
+0x04 → 005A9600
+0x08 → 00A7B030
+0x0C → 00A7B040
+0x10 → 00A7B060
+0x14 → 00A7B090
+0x18 → 00A7AE80
```

`FUN_00A7AE80` appears to handle cleanup/wait/destruction-related behavior.

The exact worker body remains to be identified.


# MAP 27 — ECONOMIC PERIODIC TICK

## `FUN_006859C0`

Proposed name:

```text
Economy_ProcessMonthlyTick
```

Alternative:

```text
CityEconomy_RunPeriodicUpdate
```

Current evidence strongly suggests that this function is a recurring economic/calendar update rather than a one-time initialization routine.

### Temporal/calendar evidence

Observed code:

```c
iVar14 = (*(int *)(param_1 + 0xb0c) + -43800000) / 0x18;
```

The function uses calendar-related data and parallel tables:

```text
DAT_00F1027C
DAT_00F10280
```

together with leap-year / year-length calculations.

This strongly suggests that the function determines a calendar period such as:

```text
day
month
season
```

for periodic economic processing.

### RNG evidence

Observed state:

```text
DAT_00F0F6B0
```

with:

```text
DAT_00F0F6B0 =
    (DAT_00F0F6B0 + 1) % 0x270
```

and:

```text
0x270 = 624
```

which corresponds to the state size associated with MT19937.

The function also generates many temporary values in:

```text
auStack_1090
```

This suggests that the periodic economic processing may use pseudo-random values for economic variation or related simulation calculations.

### Economic-entry iteration

The function iterates over a structure/list associated with:

```text
param_1 + 0xADC
param_1 + 0xAE0
```

and accesses fields around:

```text
0xE78
0xE7C
0xE80
0xE84
0xE88
```

Multiple 64-bit accumulators are maintained.

Observed local accumulators include:

```text
uStack_98
uStack_A8
uStack_60
uStack_58
uStack_50
uStack_68
uStack_B0
```

This represents at least several independent economic categories.

The exact semantic names of all categories are not yet confirmed.

### Historical economic report

The function updates:

```text
DAT_00F20BFC
```

and uses:

```text
iVar18 = DAT_00F20BFC * 0x70;
```

The `0x70`-byte stride strongly suggests a fixed-size economic report record.

Relevant global area:

```text
DAT_012624E8
```

with nearby structures around:

```text
DAT_012624A8
...
DAT_012624F4
```

Current hypothesis:

```text
g_EconomyReportHistory[2]
```

and:

```text
g_EconomyReportActiveSlot
```

for:

```text
DAT_00F20BFC
```

This looks consistent with a double-buffered / alternating economic-history snapshot.

### Economic flow

Conceptually:

```text
CALENDAR / TIME
      │
      ▼
DETERMINE PERIOD
      │
      ▼
ITERATE ECONOMIC ENTRIES
      │
      ├── category A
      ├── category B
      ├── category C
      ├── category D
      ├── category E
      ├── category F
      └── category G
      │
      ▼
64-BIT ACCUMULATION
      │
      ▼
ECONOMIC REPORT
      │
      ▼
0x70-BYTE RECORD
      │
      ▼
HISTORICAL BUFFER
```

The exact meaning of each category still needs to be established by tracing the source fields at the relevant offsets.

### Related calls

The function was observed in the context of calls such as:

```text
Economy_Update (00489990)
EconomyManager_RebuildEconomicLists (0068d250)
UpdateTimeThrottle (00685620)
```

This reinforces the conclusion that it belongs to the periodic simulation/economic update layer.

### Current conclusion

`FUN_006859C0` should currently be treated as:

```text
PERIODIC ECONOMIC / CALENDAR UPDATE
```

with the stronger working name:

```text
Economy_ProcessMonthlyTick
```

The word "monthly" remains a working hypothesis until the calendar transitions are completely confirmed.


# MAP 28 — ECONOMIC REPORT STRUCTURE

Current hypothesis:

```text
DAT_012624E8
       │
       ▼
ECONOMY REPORT HISTORY
       │
       ├── SLOT 0
       │
       └── SLOT 1
```

Each record appears to occupy:

```text
0x70 bytes
```

The active slot is controlled by:

```text
DAT_00F20BFC
```

and the selected offset:

```text
DAT_00F20BFC * 0x70
```

Potential interpretation:

```text
EconomicReport
{
    category_0;
    category_1;
    category_2;
    category_3;
    category_4;
    category_5;
    category_6;
    ...
}
```

The exact field meanings remain pending.

Important:

```text
CATEGORY NAMES ARE NOT YET CONFIRMED
```

They should not be prematurely labeled as taxes, wages, trade, interest, etc. until the source fields and consumers are traced.


# MAP 29 — ECONOMIC TICK VS WORLD MARKET

The current investigation distinguishes at least two economic layers:

```text
                 ECONOMIC SYSTEM
                       │
          ┌────────────┴────────────┐
          │                         │
          ▼                         ▼
PERIODIC ECONOMIC TICK       WORLD MARKET
    006859C0                   00482930
          │                         │
          ▼                         ▼
calendar / accounting       supply / demand
          │                         │
          ▼                         ▼
economic report             multiplier
          │                         │
          ▼                         ▼
historical data             price
```

They are related, but they should not be treated as the same function.

The market-price path is specifically:

```text
00482930 → 00482B...
```

while the periodic economic accounting path is centered around:

```text
006859C0
```


# MAP 30 — LOAN / INTEREST SYSTEM

Function:

```text
00523400
```

Proposed name:

```text
CalculateLoanInterest
```

Responsibilities include:

```text
loan interest calculation
base interest
minimum interest
```

Vanilla base interest is associated with:

```text
LOAN_BASE_INTEREST
```

A previously identified section corresponds to the minimum/1% interest logic.

Experimental changes to the base interest should be treated separately from the market-price system.


# MAP 31 — MARKET / ECONOMY FUNCTION INDEX

```text
┌────────────┬───────────────────────────────────────────────┐
│ Address    │ Function / Role                               │
├────────────┼───────────────────────────────────────────────┤
│ 0068BF00   │ EconomyManager_UpdateFull                    │
│ 00520150   │ CalculateEconomicDistribution                │
│ 006859C0   │ Economy_ProcessMonthlyTick                   │
│ 004808D0   │ ProcessMarketAndGoodsDistribution             │
│ 00482930   │ UpdateSupply                                  │
│ 00482B...  │ UpdatePrice                                   │
│ 00487410   │ Market_ProcessGoodSupplyDemand               │
│ 0047DC20   │ Buffer_AccumulateIndexedValue                │
│ 0047DCA0   │ SubtractArtisanFactoryStockpile              │
│ 0047DE60   │ Buffer_ScaleValuesInRange                    │
│ 0047D9E0   │ Clamp                                         │
│ 0047E3E0   │ Market_ComputeScaledDotProduct               │
│ 0043A880   │ vector_resize                                 │
│ 004DD470   │ Multiply goods + clamp 0..99999              │
│ 00485E40   │ POP daily economic update                    │
│ 00523400   │ Loan interest                                │
│ 0054C600   │ intro_sort                                   │
└────────────┴───────────────────────────────────────────────┘
```
