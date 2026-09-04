# VICTORIA II — REVERSE ENGINEERING DOCUMENTATION

Consolidated document with all system maps collected so far.

---

# PART I — GAME SPEED SYSTEM

## MAP 1 — GAME SPEED SYSTEM (OVERVIEW)

```text
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│                           VICTORIA II — GAME SPEED SYSTEM                                     │
└──────────────────────────────────────────────────────────────────────────────────────────────┘


                                      SPEED COMMANDS
                                            │
                         ┌──────────────────┼──────────────────┐
                         │                  │                  │
                         ▼                  ▼                  ▼
                  0072EE90            0072EFE0            0064E608
               Increase Speed       Decrease Speed       gamespeed_max
                         │                  │                  │
                         └──────────────┬───┘                  │
                                        ▼
                                  B28 = B28 ± 1
                                  Clamp: 0..4
                                        │
                                        ▼
                              DAT_012588E8 + 0xB28
                                   GAME SPEED INDEX
                                        │
                         ┌──────────────┼──────────────┐
                         │              │              │
                         ▼              ▼              ▼
                      B28=0          B28=1          B28=2
                         │              │              │
                         ▼              ▼              ▼
                  SLOWEST_SPEED    SLOW_SPEED     NORMAL_SPEED
                         │              │              │
                         ▼              ▼              ▼
                     00F0956C       00F09570       00F09574
                       0.03f          0.03f          0.03f
                         │              │              │
                         └──────────────┼──────────────┘
                                        │
                         ┌──────────────┴──────────────┐
                         │                             │
                         ▼                             ▼
                      B28=3                         B28=4
                         │                             │
                         ▼                             ▼
                    FAST_SPEED                  FASTEST_SPEED
                         │                             │
                         ▼                             ▼
                     00F09578                     00F0957C
                       0.04f                         0.06f
                         │                             │
                         └──────────────┬──────────────┘
                                        │
                                        ▼
                         ┌─────────────────────────────┐
                         │  UPDATE TIME THROTTLE       │
                         │       00685620              │
                         └──────────────┬──────────────┘
                                        │
                                        ▼
                              MOV EAX,[EDI+0xB28]
                                        │
                                        ▼
                              EAX = B28 (0..4)
                                        │
                                        ▼
                MOVSS XMM0,[EAX*4 + DAT_00F0956C]
                                        │
                                        ▼
                         SELECT THROTTLE FLOAT
                                        │
                                        ▼
                              XMM0 = TABLE[B28]
                                        │
                                        ▼
                              × DAT_013F2AE8
                                        │
                                        ▼
                         DAT_012588F0 + 1.0
                                        │
                                        ▼
                              TIME THRESHOLD
                                        │
                                        ▼
                              TIME COMPARISON
                                        │
                         ┌──────────────┴──────────────┐
                         │                             │
                         ▼                             ▼
                    NOT REACHED                     REACHED
                         │                             │
                         ▼                             ▼
                        RET                 vtable + 0x100 CALL
                                                        │
                                                        ▼
                                      ProcessMessagePumpAndUpdate
                                             009DF2B0
                                                        │
                                                        ▼
                                               GAME UPDATE CYCLE


                         ╔══════════════════════════════════╗
                         ║      SECOND USE OF B28           ║
                         ╚════════════════╦═════════════════╝
                                          │
                                          ▼
                                     FUN_00682BD0
                              ProcessGameTimeAdvance
                                          │
                                          ▼
                                MOV EAX,[ESI+0xB28]
                                          │
                                          ▼
                                     EAX = B28
                                          │
                                          ▼
                                      B28 × 4
                                          │
                                          ▼
                                  SCALE TABLE
                                          │
                  ┌───────────────────────┼───────────────────────┐
                  │                       │                       │
                  ▼                       ▼                       ▼
               B28=0                  B28=1                  B28=2
                  │                       │                       │
                  ▼                       ▼                       ▼
                4.0f                    2.0f                    1.0f
                  │                       │                       │
                  ▼                       ▼                       ▼
             00F17B58                00F17B54                00F092FC
                  │                       │                       │
                  └───────────────────────┼───────────────────────┘
                                          │
                            ┌─────────────┴─────────────┐
                            │                           │
                            ▼                           ▼
                         B28=3                       B28=4
                            │                           │
                            ▼                           ▼
                          0.5f                       0.0004f
                            │                           │
                            ▼                           ▼
                       00F17898                    00E45BB8
                            │                           │
                            └─────────────┬─────────────┘
                                          │
                                          ▼
                            COMPLETE VANILLA TABLE
                                          │
                                          ▼
                         4.0 / 2.0 / 1.0 / 0.5 / 0.0004
```

---

## MAP 1A — VANILLA UPDATE TIME THROTTLE TABLE

The first table begins at:

```text
DAT_00F0956C
```

It is accessed through:

```asm
MOV EAX,[EDI+0xB28]
MOVSS XMM0,[EAX*4 + DAT_00F0956C]
```

This means:

```text
B28 = table index
```

and each entry occupies:

```text
4 bytes
```

Therefore, the exact order is:

```text
B28=0
    ↓
DAT_00F0956C
    ↓
0.03f

B28=1
    ↓
DAT_00F09570
    ↓
0.03f

B28=2
    ↓
DAT_00F09574
    ↓
0.03f

B28=3
    ↓
DAT_00F09578
    ↓
0.04f

B28=4
    ↓
DAT_00F0957C
    ↓
0.06f
```

### Complete table

```text
┌─────┬────────────┬───────────────┬──────────────┐
│ B28 │ Address    │ Vanilla Value │ UI Speed     │
├─────┼────────────┼───────────────┼──────────────┤
│  0  │ 00F0956C   │ 0.03f         │ SLOWEST      │
│  1  │ 00F09570   │ 0.03f         │ SLOW         │
│  2  │ 00F09574   │ 0.03f         │ NORMAL       │
│  3  │ 00F09578   │ 0.04f         │ FAST         │
│  4  │ 00F0957C   │ 0.06f         │ FASTEST      │
└─────┴────────────┴───────────────┴──────────────┘
```

### Vanilla bytes

```text
0.03f = 8F C2 F5 3C
0.04f = 0A D7 23 3D
0.06f = 8F C2 75 3D
```

Memory layout:

```text
00F0956C → 8F C2 F5 3C
00F09570 → 8F C2 F5 3C
00F09574 → 8F C2 F5 3C
00F09578 → 0A D7 23 3D
00F0957C → 8F C2 75 3D
```

---

## MAP 1B — UPDATE TIME THROTTLE

```text
                         UPDATE TIME THROTTLE
                                00685620
                                     │
                                     ▼
                           MOV EAX,[EDI+0xB28]
                                     │
                                     ▼
                              EAX = B28
                                0..4
                                     │
                                     ▼
                MOVSS XMM0,[EAX*4 + DAT_00F0956C]
                                     │
                                     ▼
                              TABLE[B28]
                                     │
                ┌────────────────────┼────────────────────┐
                │                    │                    │
                ▼                    ▼                    ▼
             B28=0                 B28=1                 B28=2
             0.03f                  0.03f                  0.03f
                │                    │                    │
                └────────────────────┼────────────────────┘
                                     │
                         ┌───────────┴───────────┐
                         │                       │
                         ▼                       ▼
                      B28=3                   B28=4
                      0.04f                   0.06f
                         │                       │
                         └───────────┬───────────┘
                                     │
                                     ▼
                                    XMM0
                                     │
                                     ▼
                            × DAT_013F2AE8
                                     │
                                     ▼
                         × (DAT_012588F0 + 1.0)
                                     │
                                     ▼
                              TIME THRESHOLD
                                     │
                                     ▼
                              TIME COMPARISON
                                     │
                     ┌───────────────┴───────────────┐
                     │                               │
                     ▼                               ▼
                NOT REACHED                       REACHED
                     │                               │
                     ▼                               ▼
                    RET                    vtable + 0x100
                                                    │
                                                    ▼
                                      ProcessMessagePumpAndUpdate
                                               009DF2B0
                                                    │
                                                    ▼
                                             GAME UPDATE
```

---

## MAP 1C — UPDATE TIME THROTTLE FORMULA

The relevant sequence is:

```asm
0068568B
MOV EAX,[EDI+0xB28]

00685691
MOVSS XMM0,[EAX*4 + DAT_00F0956C]

0068569A
MOVSS XMM1,[DAT_013F2AE8]

006856A2
CVTPS2PD XMM1,XMM1

006856A5
CVTPS2PD XMM0,XMM0

006856A8
MULSD XMM0,XMM1

006856AC
MOVSS XMM1,[DAT_012588F0]

006856B4
CVTPS2PD XMM1,XMM1

006856B7
ADDSD XMM1,[DOUBLE_00E45580]
```

`DOUBLE_00E45580`:

```text
1.0
```

Therefore:

```text
TABLE[B28]
      │
      ▼
× DAT_013F2AE8
      │
      ▼
× (DAT_012588F0 + 1.0)
      │
      ▼
TIME THRESHOLD
```

---

## MAP 2 — SECOND SYSTEM: FUN_00682BD0

```text
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│                    FUN_00682BD0 — PROCESS GAME TIME ADVANCE                                  │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
```

This function has several responsibilities related to temporal progression.

```text
FUN_00682BD0
│
├── 1. Accumulates time
│      │
│      └── [ESI+0xB14] += XMM0
│
├── 2. Checks [ESI+0xB20]
│      │
│      └── if != 0 → RETURN
│
├── 3. Reads B28
│      │
│      └── MOV EAX,[ESI+0xB28]
│
├── 4. Builds the temporal table
│      │
│      ├── B28=0 → 4.0f
│      ├── B28=1 → 2.0f
│      ├── B28=2 → 1.0f
│      ├── B28=3 → 0.5f
│      └── B28=4 → 0.0004f
│
├── 5. Selects TABLE[B28]
│
├── 6. Compares the accumulator [ESI+0xB14]
│      against the selected value
│
├── 7. Continues with temporal processing
│
├── 8. Processes calendar/date-related logic
│
└── 9. Modifies DAT_012588F0
```

---

## MAP 2A — TABLE CONSTRUCTION

Vanilla code:

```asm
00682C1F
MOVSS XMM0,[DAT_00F17B58]
```

Result:

```text
[EBP-0x24] = 4.0f
```

Then:

```asm
00682C32
MOVSS XMM0,[DAT_00F17B54]
```

Result:

```text
[EBP-0x20] = 2.0f
```

Then:

```asm
00682C3F
MOVSS XMM0,[DAT_00F092FC]
```

Result:

```text
[EBP-0x1C] = 1.0f
```

Then:

```asm
00682C4C
MOVSS XMM0,[DAT_00F17898]
```

Result:

```text
[EBP-0x18] = 0.5f
```

Finally:

```asm
00682C59
MOVSS XMM0,[DAT_00E45BB8]
```

Result:

```text
[EBP-0x14] = 0.0004f
```

---

## MAP 2B — EXACT TABLE ORDER

The order is **strictly B28 = 0 → 1 → 2 → 3 → 4**.

```text
                 MOV EAX,[ESI+0xB28]
                            │
                            ▼
                       EAX = B28
                            │
                            ▼
                          EAX×4
                            │
                            ▼
                 [EBP + EAX*4 - 0x24]
                            │
             ┌──────────────┼──────────────┐
             │              │              │
             ▼              ▼              ▼
          B28=0           B28=1          B28=2
             │              │              │
             ▼              ▼              ▼
       [EBP-0x24]      [EBP-0x20]      [EBP-0x1C]
             │              │              │
             ▼              ▼              ▼
           4.0f           2.0f           1.0f
             │              │              │
             ▼              ▼              ▼
       DAT_00F17B58   DAT_00F17B54   DAT_00F092FC


                            │
                            ▼
                       B28=3
                            │
                            ▼
                       [EBP-0x18]
                            │
                            ▼
                          0.5f
                            │
                            ▼
                       DAT_00F17898


                            │
                            ▼
                       B28=4
                            │
                            ▼
                       [EBP-0x14]
                            │
                            ▼
                        0.0004f
                            │
                            ▼
                       DAT_00E45BB8
```

---

## MAP 2C — COMPLETE VANILLA TABLE

```text
┌─────┬────────────┬────────────┬──────────────────────────┐
│ B28 │ LOCAL      │ DAT        │ VANILLA VALUE            │
├─────┼────────────┼────────────┼──────────────────────────┤
│  0  │ EBP-0x24   │ 00F17B58   │ 4.0f                     │
│  1  │ EBP-0x20   │ 00F17B54   │ 2.0f                     │
│  2  │ EBP-0x1C   │ 00F092FC   │ 1.0f                     │
│  3  │ EBP-0x18   │ 00F17898   │ 0.5f                     │
│  4  │ EBP-0x14   │ 00E45BB8   │ 0.0004f                  │
└─────┴────────────┴────────────┴──────────────────────────┘
```

### IEEE-754 bytes

```text
4.0f:
00 00 80 40

2.0f:
00 00 00 40

1.0f:
00 00 80 3F

0.5f:
00 00 00 3F

0.0004f:
17 B7 D1 38
```

---

## MAP 2D — ACCUMULATOR COMPARISON

The function uses:

```text
[ESI+0xB14]
```

as a temporal accumulator.

At the beginning:

```text
[ESI+0xB14] =
    [ESI+0xB14] + XMM0
```

It then selects:

```text
TABLE[B28]
```

and compares the accumulator against that value.

Conceptually:

```text
                    [ESI+0xB14]
                          │
                          ▼
                     ACCUMULATOR
                          │
                          │ compare
                          ▼
                     TABLE[B28]
                          │
              ┌───────────┴───────────┐
              │                       │
              ▼                       ▼
          NOT REACHED              REACHED
              │                       │
              ▼                       ▼
       continue / return        temporal processing
```

---

## MAP 3 — TEMPORAL PROCESSING BARRIERS

`FUN_00682BD0` contains several conditions that can alter or stop processing.

### BARRIER 1 — [ESI+0xB20]

```text
if ([ESI+0xB20] != 0)
    return;
```

Flow:

```text
FUN_00682BD0
      │
      ▼
CMP [ESI+0xB20]
      │
      ├── != 0 → RETURN
      │
      └── == 0 → CONTINUE
```

---

### BARRIER 2 — [ESI+0xBB8]

Vanilla code:

```asm
00682D05
CMP byte ptr [ESI+0xBB8],0

00682D0C
JZ 00682E5D
```

Vanilla bytes:

```text
0F 84 4B 01 00 00
```

Flow:

```text
                 [ESI+0xBB8]
                       │
                       ▼
                     CMP 0
                       │
             ┌─────────┴─────────┐
             │                   │
          == 0                != 0
             │                   │
             ▼                   ▼
       00682E5D             continues
```

This condition was experimentally confirmed to be a real barrier.

During testing, the following sequence:

```text
0F 84 4B 01 00 00
```

was replaced with:

```text
90 90 90 90 90 90
```

and processing continued through the following branch.

**This change is experimental and is NOT part of the vanilla code.**

---

## MAP 4 — TEMPORAL GLOBAL STATES

`FUN_00682BD0` modifies:

```text
DAT_012588E6
DAT_012588EC
DAT_012588F0
```

These states affect temporal behavior.

```text
FUN_00682BD0
      │
      ├──────────────► DAT_012588E6
      │
      ├──────────────► DAT_012588EC
      │
      └──────────────► DAT_012588F0
                              │
                              ▼
                       UpdateTimeThrottle
                              │
                              ▼
                     TIME THRESHOLD
```

---

## MAP 4A — DAT_012588F0

`DAT_012588F0` is especially important because it appears in both systems.

In `UpdateTimeThrottle`:

```text
DAT_012588F0 + 1.0
```

is part of the threshold calculation.

In `FUN_00682BD0`, it can be modified through different temporal branches.

Observed operations include:

```text
DAT_012588F0 × 0.95
```

```text
DAT_012588F0 × 0.9
```

and:

```text
DAT_012588F0 + 0.5
```

There is also logic related to date differences.

Therefore:

```text
FUN_00682BD0
      │
      ▼
DAT_012588F0
      │
      ▼
UpdateTimeThrottle
      │
      ▼
THRESHOLD
```

is an important connection within the system.

---

## MAP 5 — DAT_00E45BB8

```text
┌─────────────────────────────────────────────────────────┐
│ DAT_00E45BB8                                            │
├─────────────────────────────────────────────────────────┤
│ Address: 00E45BB8                                       │
│ Vanilla value: 0.0004f                                 │
│ Bytes: 17 B7 D1 38                                      │
│ Speed usage: B28=4                                     │
└─────────────────────────────────────────────────────────┘
```

Correspondence:

```text
B28=4
   ↓
DAT_00E45BB8
   ↓
0.0004f
```

Important:

`DAT_00E45BB8` has multiple XREFs within the executable.

Therefore:

```text
CHANGING DAT_00E45BB8
        ≠
CHANGING ONLY GAME SPEED
```

It may affect other consumers of this constant.

---

## MAP 6 — DAT_00F092FC

```text
┌─────────────────────────────────────────────────────────┐
│ DAT_00F092FC                                            │
├─────────────────────────────────────────────────────────┤
│ Address: 00F092FC                                       │
│ Vanilla value: 1.0f                                    │
│ Bytes: 00 00 80 3F                                     │
│ Speed usage: B28=2                                     │
└─────────────────────────────────────────────────────────┘
```

In `FUN_00682BD0`:

```text
B28=2
   ↓
DAT_00F092FC
   ↓
1.0f
```

It also appears in `FUN_00475150`:

```asm
0047527C
MOVSS XMM0,[DAT_00F092FC]

00475286
MOVSS [EDI+0x178],XMM0
```

Therefore:

```text
DAT_00F092FC
      │
      ├── FUN_00682BD0
      │       ↓
      │     B28=2
      │       ↓
      │      1.0f
      │
      └── FUN_00475150
              ↓
          [EDI+0x178]
```

This demonstrates that `DAT_00F092FC` directly participates in the speed table used by `FUN_00682BD0`.

---

## MAP 7 — SPEED DISPLAY / UI

```text
                              B28
                               │
                  ┌────────────┴────────────┐
                  │                         │
                  ▼                         ▼
             00715DE5                  0070DFE0
                  │                         │
                  ▼                         ▼
          SPEED NAME TABLE             Read B28
                  │                         │
     ┌────────────┼────────────┐            ▼
     │            │            │       ADD EAX,2
     ▼            ▼            ▼            │
   B28=0        B28=2        B28=4          ▼
  SLOWEST       NORMAL      FASTEST     [ESP+0x30]
     │            │            │            │
     └────────────┼────────────┘            ▼
                  │                    UI / STATE LOGIC
                  ▼
       00E11040 → SLOWEST_SPEED
       00E11050 → SLOW_SPEED
       00E1105C → NORMAL_SPEED
       00E1106C → FAST_SPEED
       00E11078 → FASTEST_SPEED
```

---

## MAP 8 — RELATIONSHIP BETWEEN THE TWO TABLES

```text
                         B28 = 0..4
                              │
                ┌─────────────┴─────────────┐
                │                           │
                ▼                           ▼
        TABLE 1 — THROTTLE          TABLE 2 — TEMPORAL
        DAT_00F0956C                FUN_00682BD0
                │                           │
                │                           │
       ┌────────┼────────┐          ┌───────┼───────────────┐
       │        │        │          │       │       │       │
       ▼        ▼        ▼          ▼       ▼       ▼       ▼
     0.03     0.03     0.03        4.0     2.0     1.0     0.5
       │        │        │          │       │       │       │
       │        │        │          │       │       │       │
       └────────┼────────┘          └───────┼───────┼───────┘
                │                           │       │
                ▼                           ▼       ▼
          B28=3 → 0.04                B28=3 → 0.5
          B28=4 → 0.06                B28=4 → 0.0004
                │                           │
                └─────────────┬─────────────┘
                              │
                              ▼
                        TEMPORAL SYSTEM
```

The tables **do not contain the same values and do not perform exactly the same function**.

The only thing they directly share is the index:

```text
B28
```

---

## MAP 9 — COMPLETE B28 MAPPING

```text
┌─────┬──────────────────┬──────────────┬──────────────────────┬──────────────┐
│ B28 │ SPEED            │ UI           │ UPDATE TIME THROTTLE │ TEMPORAL     │
├─────┼──────────────────┼──────────────┼──────────────────────┼──────────────┤
│  0  │ SLOWEST_SPEED    │ SLOWEST      │ 0.03f                │ 4.0f         │
│  1  │ SLOW_SPEED       │ SLOW         │ 0.03f                │ 2.0f         │
│  2  │ NORMAL_SPEED     │ NORMAL       │ 0.03f                │ 1.0f         │
│  3  │ FAST_SPEED       │ FAST         │ 0.04f                │ 0.5f         │
│  4  │ FASTEST_SPEED    │ FASTEST      │ 0.06f                │ 0.0004f      │
└─────┴──────────────────┴──────────────┴──────────────────────┴──────────────┘
```

The order of both tables is:

```text
B28=0
    ↓
B28=1
    ↓
B28=2
    ↓
B28=3
    ↓
B28=4
```

The order must not be interpreted based on the numerical value of the floats or the address of the constants.

The `B28` index determines which entry is used.

---

## MAP 10 — COMPLETE SYSTEM FLOW

```text
                         Increase / Decrease Speed
                                  │
                                  ▼
                             B28 = 0..4
                                  │
             ┌────────────────────┼────────────────────┐
             │                    │                    │
             ▼                    ▼                    ▼
          SPEED UI          UpdateTimeThrottle      FUN_00682BD0
        00715DE5 /             00685620                │
        0070DFE0                   │                   │
             │                     │                   ▼
             │                     │             MOV EAX,[ESI+0xB28]
             │                     │                   │
             │                     │                   ▼
             │                     │            TEMPORAL TABLE
             │                     │                   │
             │                     │       ┌───────────┼────────────┐
             │                     │       ▼           ▼            ▼
             │                     │      4.0         2.0          1.0
             │                     │       │           │            │
             │                     │       └───────────┼────────────┘
             │                     │                   │
             │                     │             0.5 / 0.0004
             │                     │                   │
             │                     ▼                   ▼
             │               DAT_00F0956C         B14 ACCUMULATOR
             │                     │                   │
             │                     ▼                   ▼
             │               0.03/0.04/0.06      B20 / BB8
             │                     │                   │
             │                     ▼                   ▼
             │              × DAT_013F2AE8       TEMPORAL LOGIC
             │                     │                   │
             │                     ▼                   ▼
             │          × (DAT_012588F0 + 1)    DAT_012588F0
             │                     │                   │
             │                     ▼                   │
             │               TIME THRESHOLD            │
             │                     │                   │
             │                     ▼                   │
             │              TIME COMPARISON            │
             │                     │                   │
             │                     ▼                   │
             │       ProcessMessagePumpAndUpdate ◄─────┘
             │                  009DF2B0
             │                     │
             └─────────────────────┴───────────────────►
                                      GAME UPDATE
```

---

## MAP 11 — IMPORTANT MODDING POINTS

```text
┌────────────────────────────────────────────────────────────────┐
│                    POINTS OF INTEREST                          │
├────────────────────┬───────────────────────────────────────────┤
│ 00685620           │ UpdateTimeThrottle                        │
│ 00682BD0           │ ProcessGameTimeAdvance                    │
│ 00F0956C           │ UpdateTimeThrottle table start            │
│ 00F0957C           │ B28=4 entry → 0.06f                       │
│ 00F17B58           │ B28=0 entry → 4.0f                        │
│ 00F17B54           │ B28=1 entry → 2.0f                        │
│ 00F092FC           │ B28=2 entry → 1.0f                        │
│ 00F17898           │ B28=3 entry → 0.5f                        │
│ 00E45BB8           │ B28=4 entry → 0.0004f                     │
│ 012588F0           │ Shared temporal factor                    │
│ [ESI+0xB14]        │ Temporal accumulator                       │
│ [ESI+0xB20]        │ State that can stop the function           │
│ [ESI+0xBB8]        │ Temporal condition/barrier                 │
│ 009DF2B0           │ ProcessMessagePumpAndUpdate                │
└────────────────────┴───────────────────────────────────────────┘
```

---

## MAP 12 — CONCLUSION

The Victoria II speed system uses:

```text
                         B28 = 0..4
                              │
                ┌─────────────┴─────────────┐
                │                           │
                ▼                           ▼
       UPDATE TIME THROTTLE        TIME ADVANCE
             00685620                  00682BD0
                │                           │
                ▼                           ▼
       0.03/0.03/0.03/0.04/0.06   4.0/2.0/1.0/0.5/0.0004
                │                           │
                ▼                           ▼
       DAT_013F2AE8                [ESI+0xB14]
                │                           │
                ▼                           ▼
       DAT_012588F0                [ESI+0xB20]
                │                           │
                │                      [ESI+0xBB8]
                │                           │
                └──────────────┬────────────┘
                               │
                               ▼
                         GAME UPDATE
```

The current conclusion is that **B28 is the central speed index**, but Victoria II uses **two different tables** to control different aspects of temporal processing.

The `UpdateTimeThrottle` table controls the threshold used to determine when the update cycle should execute.

The `FUN_00682BD0` table is used in time-advance processing and contains five complete entries, including:

```text
B28=4 → 0.0004f
```

Therefore, the correct and complete table is:

```text
B28=0 → 4.0f
B28=1 → 2.0f
B28=2 → 1.0f
B28=3 → 0.5f
B28=4 → 0.0004f
```

And the `UpdateTimeThrottle` table:

```text
B28=0 → 0.03f
B28=1 → 0.03f
B28=2 → 0.03f
B28=3 → 0.04f
B28=4 → 0.06f
```

These are the **vanilla values**.

Values modified during testing, such as the `4.0f` introduced via a code cave at `00685691`, `5.0f` in tests involving `DAT_00F092FC`, `0.000001f` in `DAT_00E45BB8`, or the NOPs at `00682D0C`, must be considered **experimental patches**, not part of the vanilla system.

---

# PART II — GENERAL ENGINE STRUCTURE, ECONOMY, CONSOLE AND FOG OF WAR

```text
00AB0F91
  ENTRY / ENTRY POINT
    |
    v
009DF550
  MAIN LOOP
    |
    +-- 009796B0
    |     WINMAIN / CLAUSEWITZ ENGINE
    |       |
    |       +-- Engine initialization
    |       +-- Main game loop
    |       +-- Per-tick updates
    |
    +-- 0068BF00
    |     ECONOMY
    |       |
    |       +-- Economy_Update
    |       |     |
    |       |     +-- WorldMarket_Update
    |       |     |     |
    |       |     |     +-- 00482930
    |       |     |           UPDATE SUPPLY
    |       |     |             |
    |       |     |             +-- Supply
    |       |     |             +-- Demand
    |       |     |             +-- 64-bit comparison
    |       |     |             +-- SignedDivideInt64
    |       |     |             +-- CalculateSupplyMultiplier
    |       |     |             |
    |       |     |             v
    |       |     |           UPDATE PRICE
    |       |     |           00482B...
    |       |     |             |
    |       |     |             +-- Base price
    |       |     |             +-- Multiplier
    |       |     |             +-- Minimum limit
    |       |     |             |     DAT_00E45C30
    |       |     |             |     Vanilla: ×0.2
    |       |     |             |
    |       |     |             +-- Maximum limit
    |       |     |                   DAT_00E45C28
    |       |     |                   Vanilla: ×5.0
    |       |     |
    |       |     +-- Other economy functions
    |       |     |
    |       |     +-- [NEW — functions renamed by the teammate]
    |       |           |
    |       |           +-- FUN_0047e3e0
    |       |           |     Market_ComputeScaledDotProduct
    |       |           |     used in 58 different places
    |       |           |     probably NOT market-specific
    |       |           |     (generic math function, usage still unconfirmed)
    |       |           |
    |       |           +-- FUN_0047de60
    |       |           |     Buffer_ScaleValuesInRange
    |       |           |     alias: multiply_values_in_vector
    |       |           |     used in 53 places — operates on vectors /
    |       |           |     contiguous memory blocks
    |       |           |
    |       |           +-- Buffer_AccumulateIndexedValue
    |       |           |     alias: add_stockpiles_to_market_stats
    |       |           |     adds stockpiled amounts to
    |       |           |     demand and supply
    |       |           |       0x0047dc56  MOV EDI,[ECX+EDX*8]
    |       |           |         ; stockpiled amount
    |       |           |       0x0047dc59  ADD [EAX],EDI
    |       |           |         ; [EAX] = global supply or demand
    |       |           |         ; (depending on context)
    |       |           |
    |       |           +-- FUN_0043a880
    |       |           |     vector_resize
    |       |           |
    |       |           +-- 0x0047d9e0
    |       |           |     clamping function
    |       |           |     alias: clamp_0_to_arg8h_&_argch
    |       |           |
    |       |           +-- FUN_004dd470
    |       |           |     alias: multiply_goods_clamp_0_99999
    |       |           |     0xc34f8000 = 3276767232 / 2^15 = 99999
    |       |           |
    |       |           +-- FUN_00487410
    |       |           |     Market_ProcessGoodSupplyDemand
    |       |           |     [region-wide aggregate close]
    |       |           |     alias: add_real_demand_for_good_1
    |       |           |     (there's another similar function, hence the "_1")
    |       |           |     CONFIRMED: only touches DEMAND, not supply
    |       |           |       0x004877b1  LEA EAX,[EDX+EAX*8]
    |       |           |         ; EAX = index into the real_demand container
    |       |           |         ; EDX = address of the real_demand container
    |       |           |
    |       |           +-- 0x0054c600
    |       |           |     intro_sort
    |       |           |
    |       |           +-- FUN_00485e40
    |       |           |     alias: pop_daily_update_money
    |       |           |     updates needs met, bank, and more (per POP)
    |       |           |
    |       |           +-- 00523400
    |       |                 alias: calculate_loan_interest
    |       |                 (matches the LOAN LOGIC below)
    |       |
    |       +-- 00523400
    |             LOANS
    |               |
    |               +-- Interest calculation
    |               +-- Base interest
    |               +-- Minimum interest limit
    |               +-- Interest patch logic
    |
    +-- AI
    |     |
    |     +-- AI_SimpleThresholdCheck
    |           |
    |           +-- Condition checks
    |           +-- Threshold evaluation
    |           +-- Calls related to event_system
    |           |
    |           v
    |       EVENT SYSTEM
    |         008A67B0
    |
    +-- 008A67B0
    |     EVENT RESOURCE SYSTEM / MANAGER
    |       |
    |       +-- FUN_008A5AC0
    |       |     INITIALIZE EVENT MANAGER
    |       |
    |       +-- FUN_008A5C70
    |       |     INITIALIZE EVENT STRUCTURE
    |       |
    |       +-- FUN_009A1440
    |       |     INITIALIZE EVENT OBJECT
    |       |
    |       +-- FUN_008A6010
    |       |     GET MAIN EVENT NAME
    |       |
    |       +-- FUN_008A60F0
    |       |     GET SECONDARY EVENT NAME
    |       |
    |       +-- FUN_008A67B0
    |             LOAD EVENT RESOURCES
    |             [MAIN STRUCTURE?]
    |
    +-- [NEW] CONSOLE COMMANDS
    |     |
    |     +-- console_commands (formerly FUN_00420EB0)
    |           MAIN CONSOLE DISPATCHER
    |             |
    |             +-- Receives param_2 = tokens of the typed command
    |             +-- Comparison cascade via FUN_0040b360 (strcmp)
    |             |     against DAT_00dfXXXX literals
    |             +-- Empirically confirmed: disabling this function
    |             |     removes console commands entirely
    |             |
    |             +-- Identified branches (partial, by behavior):
    |             |     |
    |             |     +-- Simple debug/log toggles
    |             |     |     DAT_012586d8  -> WorldMarket_Update /
    |             |     |                      Economy_Update log (confirmed,
    |             |     |                      writes to a file via
    |             |     |                      get_or_initialize_singleton_instance)
    |             |     |     DAT_0125873c, DAT_0125899e, DAT_0125873e,
    |             |     |     DAT_012587e0, DAT_00f09545, DAT_012586d7,
    |             |     |     DAT_00f09544, DAT_00f07da6  -> other per-subsystem
    |             |     |     log toggles (still no exact name)
    |             |     |
    |             |     +-- Global flags bitfield (iVar5+0xe8)
    |             |     |     toggles bits 0x800000..0x20000000 depending on branch
    |             |     |
    |             |     +-- "fow" command (CONFIRMED — see block below)
    |             |     |     0x422090 .. 0x4222e9
    |             |     |     toggles DAT_013f080c, writes to
    |             |     |     [DAT_01258a74 + 0x6bc44]
    |             |     |
    |             |     +-- Command with argument count ≥2/4/5/6
    |             |     |     reads offsets 0x38/0x54/0x70/0x8c from an
    |             |     |     object via DAT_012587e4 (possible goods
    |             |     |     table) — strong candidate for a market
    |             |     |     command with parameters
    |             |     |
    |             |     +-- Command with FUN_0090cc40/FUN_0090da40 +
    |             |     |     country tag + vtable+0x2c at offsets
    |             |     |     0x4c/0xd8/0xa0 — strong candidate for
    |             |     |     commands that modify a specific country's
    |             |     |     stats (treasury/prestige/infamy)
    |             |     |
    |             |     +-- Command with CharUpperBuffA + ~10 comparisons
    |             |           uppercase, each toggling a different bit
    |             |           (0x1,0x2,0x8,0x10,...,0x400) of the same
    |             |           bitfield — candidate for "log <category>"
    |             |
    |             +-- FUN_00428d40
    |                   adds param_1 to [EAX+0x10] and clamps between
    |                   0 and 0x186a0 (100000)
    |                   also used in FUN_00580480 (event/occupation)
    |                   generic accumulator-with-limit function,
    |                   NOT game speed (ruled out)
    |
    +-- [NEW] RENDERING / FOG OF WAR (FoW)
    |     |
    |     +-- DAT_01258a74
    |     |     pointer to the render device / graphics engine (singleton)
    |     |     written in InitializeGraphicsDevice
    |     |
    |     +-- DAT_013f080c
    |     |     global FoW state flag (0 = fog active,
    |     |     1 = fog disabled)
    |     |     written by console_commands (the "fow" command)
    |     |     mirrored in [DAT_01258a74 + 0x6bc44]
    |     |
    |     +-- InitializeGraphicsDevice (0x994577)
    |     |     initializes the +0x6bc44..+0x6bc98 block to 0
    |     |     (default state: fog active)
    |     |
    |     +-- FUN_0099da20
    |     |     graphics device INIT / RESTORE
    |     |     XREFs: InitializeGraphicsDevice, FUN_0099bf60,
    |     |             CheckAndRestoreGraphicsDevice
    |     |     0x99db69  CMP [ESI+0x6bc44],0
    |     |     0x99db7b  JZ  -> PUSH 3 (fog ON)
    |     |               (not taken) -> PUSH 2 (fog OFF)
    |     |     EMPIRICALLY CONFIRMED:
    |     |       patching this JZ->NOP breaks TEXT RENDERING
    |     |       (UI/HUD) — controls the text/initialization layer
    |     |       of that part of the engine (see images 1 and 2)
    |     |
    |     +-- FUN_006592f0
    |           runs in the PER-FRAME LOOP, right before
    |           CALL UpdateGameFrame (0x65957f)
    |           0x6594c7  CMP [EDI+0x6bc44],BL   (BL=0)
    |           0x6594cd  JZ  -> skips the block (fog not forced)
    |                     (not taken) -> PUSH 2,8 ; CALL vtable[0xe4]
    |                                    (forces fog OFF that frame)
    |           preceded by CheckAndRestoreGraphicsDevice
    |           (0x6594b4, TEST AL,AL / JZ LAB_00659737) — this
    |           prior condition may be skipping the whole block
    |           EMPIRICALLY CONFIRMED:
    |             patching this JZ->NOP breaks the MAP TERRAIN
    |             TEXTURES (see image 3) — controls the map
    |             texture render layer, not just the logic flag
    |           PENDING: review the prior condition in
    |             CheckAndRestoreGraphicsDevice before deciding
    |             on the final patch to keep FoW always OFF
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


DETAILED ECONOMIC FLOW
  |
  v
0068BF00
  ECONOMY_UPDATE
    |
    v
WORLD MARKET UPDATE
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


EVENT FLOW
  |
  v
AI_SIMPLETHRESHOLDCHECK
    |
    +-- Checks conditions
    |
    +-- Checks thresholds
    |
    +-- Makes calls related to events
    |
    v
008A67B0
  EVENT SYSTEM
    |
    +-- 008A5AC0
    |     Initialize Event Manager
    |
    +-- 008A5C70
    |     Initialize Event Structure
    |
    +-- 009A1440
    |     Initialize Event Object
    |
    +-- 008A6010
    |     Get Main Event Name
    |
    +-- 008A60F0
    |     Get Secondary Event Name
    |
    +-- 008A67B0
          Load Event Resources


PRICE FLOW CURRENTLY BEING MODIFIED
  |
  v
00482930
  SUPPLY
    |
    v
  DEMAND
    |
    v
  SUPPLY VS DEMAND COMPARISON
    |
    v
  SIGNEDDIVIDEINT64
    |
    v
  CALCULATESUPPLYMULTIPLIER
    |
    v
00482B...
  PRICE CALCULATION
    |
    +-- BASE PRICE
    |
    +-- MULTIPLIER
    |
    +-- MINIMUM LIMIT
    |     DAT_00E45C30
    |     |
    |     +-- VANILLA: ×0.2
    |     +-- MODIFIED: ×0.1
    |
    +-- MAXIMUM LIMIT
          DAT_00E45C28
          |
          +-- VANILLA: ×5.0
          +-- MODIFIED: ×10.0
    |
    v
  FINAL PRICE


SUPPLY PATCH
  |
  v
00482B03
  HOOK
    |
    v
00C8911A
  CODE CAVE
    |
    +-- Modify supply
    +-- Multiply value
    +-- Preserve registers
    +-- Execute original instructions
    +-- Return to original code
    |
    +-- PROBLEM FOUND
          |
          +-- Code cave reached approximately 00C891FF
          +-- The patch caused a CRASH


LOANS / INTEREST
  |
  v
00523400
  LOAN LOGIC (calculate_loan_interest)
    |
    +-- Interest calculation
    +-- LOAN_BASE_INTEREST
    +-- Minimum interest
    +-- Code related to the 1%
    |
    v
  INTEREST PATCH


[NEW] RENAMED UTILITY / HELPER FUNCTIONS
  |
  +-- FUN_0043ab60      Memory_CopyOverlapping -> zero_struct_array
  |                     (appears specific to int64 arrays)
  |
  +-- FUN_00aad56b      Memory_ValidateSize -> looks like an "operator new"
  |
  +-- FUN_0041a160      Struct_InitWithDefaults -> ctor_with_MTTH
  |                     probably an event constructor
  |
  +-- FUN_0096bbf0      Singleton_Construct
  |                     uses create_string_with_length("null_pop", 8)
  |                     and vtable.CAddAIStrategyEffect.138
  |                     -> possibly related to country AI
  |
  +-- thunk_FUN_00ab4d81  Stream_CheckState -> __ptmbcinfo
  |                     checks whether the thread uses MBCS or the local code page
  |
  +-- FUN_0047db00      Buffer_CopyAndResize -> CGoodsPool_copy_ctor
  |
  +-- fcn.004f50c0      factory_decay_without_inputs
  |                     code that decays factory level when inputs are missing


GENERAL ENGINE STRUCTURE
  |
  v
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
    +-- ECONOMY
    |     |
    |     v
    |   0068BF00
    |     |
    |     v
    |   00482930
    |     |
    |     v
    |   00482B...
    |
    +-- AI
    |     |
    |     v
    |   AI_SimpleThresholdCheck
    |     |
    |     v
    |   EVENT_SYSTEM
    |     |
    |     v
    |   008A67B0
    |
    +-- CONSOLE COMMANDS
    |     |
    |     v
    |   console_commands
    |
    +-- RENDERING / FOW
    |     |
    |     +-- FUN_0099da20   (init/restore -> text layer)
    |     +-- FUN_006592f0   (per-frame loop -> texture layer)
    |
    +-- LOANS
    |     |
    |     v
    |   00523400
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


NOTES
  |
  +-- The event function names are still tentative until their
  |   XREFs are fully confirmed.
  |
  +-- 008A67B0 appears related to loading / managing event
  |   resources, but it still can't be confirmed that this is
  |   the main point where events are EXECUTED.
  |
  +-- AI_SimpleThresholdCheck appears related to checks that may
  |   end up interacting with event_system.
  |
  +-- Removing the calls to event_system allows some battles to
  |   start, but the game later ends up crashing after several
  |   days.
  |
  +-- Because of that, event_system probably participates in
  |   some later processing / event maintenance, although it
  |   still needs to be determined exactly which.
  |
  +-- In the economy, it's best to preserve the vanilla flow:
  |   Supply -> Demand -> Comparison -> Division ->
  |   Multiplier -> Price -> Limits.
  |
  +-- The goal of the price patch is to modify only the limits
  |   without replacing the vanilla Supply/Demand logic.
  |
  +-- [NEW] console_commands confirmed as the single console
  |   dispatcher: disabling it removes ALL commands, without
  |   exception.
  |
  +-- [NEW] The "fow" command toggles DAT_013f080c, but that
  |   flag alone isn't enough to force fog-off from startup:
  |   the RENDERING functions that read it need to be modified
  |   too (FUN_0099da20 for text, FUN_006592f0 for terrain
  |   textures).
  |
  +-- [NEW] Patching the JZ->NOP directly in either of the two
  |   render functions BREAKS the layer they control (empirically
  |   confirmed with screenshots). Still need to review the prior
  |   condition in CheckAndRestoreGraphicsDevice (0x6594b4) before
  |   attempting a clean patch in FUN_006592f0 that doesn't break
  |   anything.
  |
  +-- [NEW] Utility functions identified by the teammate
  |   (Buffer_ScaleValuesInRange, clamp_0_to_arg8h_&_argch,
  |   multiply_goods_clamp_0_99999, etc.) are general-purpose and
  |   reused in dozens of places — useful as a cross-reference,
  |   not as economy-specific patch points.
```

---

# PART III — RANDOM NUMBER GENERATOR (RNG) SYSTEM

```text
                         v2game.exe+0xb0ecf0
                       RANDOM NUMBER LIST
                        (pre-generated in memory)
                                  │
                                  ▼
                         v2game.exe+0xb0f6b0
                        CURRENT LIST INDEX
                                  │
                                  ▼
                          func_009b7610
                    FUNCTION THAT POLLS A NUMBER
                                  │
                    ┌─────────────┴─────────────┐
                    │                           │
                    ▼                           ▼
             INDEX + 1                  LIST EXHAUSTED?
                    │                    (all numbers
                    ▼                     already used)
          RETURNS THE NUMBER                    │
          AT THAT LIST INDEX           ┌───────┴───────┐
                                          │               │
                                          ▼               ▼
                                         YES              NO
                                          │               │
                                          ▼               ▼
                                  func_009b7700      normal flow
                                  GENERATES A NEW      continues
                                  LIST WITH
                                  MERSENNE TWISTER
```

**Notes on the RNG** (as passed along by the teammate):

- The random number list lives at `v2game.exe+0xb0ecf0`.
- The current read index is at `v2game.exe+0xb0f6b0`; every time a random number is requested, that index is incremented by 1 and used to index into the list.
- Once all numbers in the list have been used, the game generates a new list using the Mersenne Twister algorithm.
- `func_009b7610` is where the game polls a number from the random number list.
- Inside that function, if it detects that all numbers have been used, it calls `func_009b7700` to generate a new set of random numbers via Mersenne Twister.

---

# PART IV — BUTTON CALLBACKS (PARTIAL, NOT FULLY CONFIRMED)

| Function | Role | Status |
|---|---|---|
| `func_6dfe80` | Callback when the **Westernize** button is pressed | Confirmed |
| `func_541b90` | Condition check for whether the Westernize button should be clickable | Confirmed |
| `func_772300` | **Play** button callback | Likely — the teammate believes there's a different function for SP and MP, and doesn't remember which one this is |
| (other button functions) | — | Previously identified but currently can't be found — pending recovery |

---

# PART V — [NEW] ARTISAN/FACTORY STOCKPILE SUBTRACTION

## MAP 13 — subtract_artisan_factory_stockpile_from_esi_stockpile (0x0047dca0)

A very important function: it shows how goods are stored as **bitflags** inside the artisan/factory base struct, and how the stockpile of an artisan/factory gets subtracted against the stockpile of another entity pointed to by `esi` (likely the market/province).

```text
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│         subtract_artisan_factory_stockpile_from_esi_stockpile  (0x0047dca0)                   │
│         subtract_artisan/factory_stockpile_from_esi_stockpile(int32_t artisan/factory)        │
└──────────────────────────────────────────────────────────────────────────────────────────────┘

  arg  int32_t artisan/factory   @ [ebp+0x08]
  var  int32_t var_18h           @ [ebp-0x18]
  var  int32_t var_14h           @ [ebp-0x14]
  var  int32_t var_ch            @ [ebp-0x0c]

                          PROLOGUE
                              │
                              ▼
                    push ebp / mov ebp,esp
                    sub esp,0x14
                              │
                              ▼
                EAX = [0x12587f4]   ; number_of_goods
                              │
                              ▼
                    push ebx / xor ebx,ebx   ; ebx = index = 0
                    push edi
                    [ebp-0x08] = EAX          ; save number_of_goods
                              │
                              ▼
                    TEST EAX,EAX
                              │
                     ┌────────┴────────┐
                     │                 │
                  <= 0               > 0
                     │                 │
                     ▼                 ▼
                    JLE            continues
                 (end of loop,
                  go to 0x47dd21)
                              │
                              ▼
        ╔═══════════════════════════════════════════════╗
        ║   MAIN LOOP — for each good (ebx = idx)        ║
        ╚═══════════════════════════════════════════════╝
                              │
                              ▼
                EDI = [ebp+0x08]        ; pointer to artisan/factory
                              │
                              ▼
             CL = [edi + ebx*1 + 0x08]
             ; artisan/factory.good_bit_flags[ebx]
             ; (bitflag: is this good present?)
                              │
                              ▼
                    TEST CL,CL
                              │
                     ┌────────┴────────┐
                     │                 │
                  == 0               != 0
                     │                 │
                     ▼                 ▼
                 JZ 0x47dd1b      continues
                 (good absent,
                  next
                  iteration)
                              │
                              ▼
             AL = [ebx + esi*1 + 0x08]
             ; esi.good_bit_flags[ebx]
             ; (bitflag of the destination/market stockpile)
                              │
                              ▼
                    TEST AL,AL
                              │
                     ┌────────┴────────┐
                     │                 │
                  == 0               != 0
                     │                 │
                     ▼                 ▼
              (branch A)          (branch B)
              JZ 0x47dce6         continues
```

### BRANCH A — the good's bit is NOT set in `esi` (0x47dce6)

Here `esi` doesn't yet have that good "active" in its bitflag; it needs to be activated and its real index within the stockpile vector calculated.

```text
                      BRANCH A (0x47dce6)
                              │
                              ▼
                EDX = [esi+0x4c]        ; stockpile_vector_end (or similar)
                              │
                              ▼
                EDX = EDX - [esi+0x48]  ; end - begin
                              │
                              ▼
                EDI = &[esi+0x48]       ; address of begin (pointer)
                              │
                              ▼
                EDX = EDX >> 3          ; SAR 3  → divide by 8
                                         ; (each stockpile entry
                                         ;  occupies 8 bytes: 2×int32)
                              │
                              ▼
        [ebx + esi*1 + 0x08] = DL
        ; esi.good_bit_flags[ebx] = new index
        ; (activates the bit / stores the assigned position)
                              │
                              ▼
                EAX = zero_extend(CL)   ; index of the good in artisan/factory
                              │
                              ▼
                ECX = [ebp+0x08]        ; artisan/factory
                EDX = [ECX+0x48]        ; artisan/factory.stockpile_vector_begin
                              │
                              ▼
                ECX = [EDX + EAX*8]        ; low part  (int64 low)
                EDX = [EDX + EAX*8 + 0x04] ; high part  (int64 high)
                              │
                              ▼
                NEG ECX
                ADC EDX,0x00
                NEG EDX
                ; ---------------------------------------------
                ; NEG ECX / ADC EDX,0 / NEG EDX
                ; = negation of a 64-bit integer (ECX:EDX)
                ; equivalent to:  value64 = -value64
                ; ---------------------------------------------
                              │
                              ▼
                EAX = &[ebp-0x14]
                [ebp-0x14] = ECX   ; low
                [ebp-0x10] = EDX   ; high
                              │
                              ▼
                CALL vector_push_back_edi
                ; inserts the NEGATED value (−the artisan/factory's
                ; good amount) as a new entry in esi's
                ; stockpile vector
                              │
                              ▼
                        (loop continues)
                        → 0x47dd1b
```

### BRANCH B — the good's bit IS set in `esi` (continues from 0x47dcc9)

Here `esi` already has an existing entry for that good; a direct 64-bit subtraction is simply performed on the existing entry.

```text
                      BRANCH B (continues)
                              │
                              ▼
                EDX = [esi+0x48]        ; esi.stockpile_vector_begin
                              │
                              ▼
                EAX = zero_extend(AL)   ; existing index in esi
                              │
                              ▼
                EAX = &[EDX + EAX*8]
                ; EAX = address of the (int64) entry for the good
                ; WITHIN esi's stockpile
                              │
                              ▼
                EDX = zero_extend(CL)   ; index of the good in artisan/factory
                              │
                              ▼
                ECX = [edi+0x48]        ; artisan/factory.stockpile_vector_begin
                              │
                              ▼
                EDI = [ECX + EDX*8]        ; artisan/factory: amount (low)
                              │
                              ▼
                [EAX] = [EAX] - EDI
                ; esi.stockpile[good].low -= artisan/factory.stockpile[good].low
                              │
                              ▼
                ECX = [ECX + EDX*8 + 0x04]  ; artisan/factory: amount (high)
                              │
                              ▼
                [EAX+0x04] = [EAX+0x04] - ECX (with SBB, propagates the borrow)
                ; esi.stockpile[good].high -= artisan/factory.stockpile[good].high
                              │
                              ▼
                    JMP 0x47dd1b (loop continues)
```

### LOOP CLOSE AND EPILOGUE

```text
                      0x47dd1b
                              │
                              ▼
                        INC EBX   ; next good
                              │
                              ▼
                CMP EBX, [ebp-0x08]   ; ebx < number_of_goods ?
                              │
                     ┌────────┴────────┐
                     │                 │
                    JL                no
                (back to the loop  │
                 at 0x47dcb6)      ▼
                                (end of loop)
                                    │
                                    ▼
                              0x47dd21
                                    │
                                    ▼
                              POP EDI
                              EAX = ESI   ; returns esi (pointer)
                              POP EBX
                              MOV ESP,EBP
                              POP EBP
                              RET 0x04
```

### Conceptual summary

```text
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│                                SUMMARY — WHAT IT DOES                                         │
├──────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                                │
│  For each good (index 0..number_of_goods-1):                                                 │
│                                                                                                │
│    1) If the artisan/factory does NOT have that good (bitflag=0) → skip it.                  │
│                                                                                                │
│    2) If the artisan/factory DOES have the good:                                             │
│         a) If esi (destination) did NOT yet have an entry for that good:                      │
│              - calculates the free index (based on the vector's current size)                │
│              - marks esi's bitflag with that index                                            │
│              - inserts into esi's vector the NEGATED (int64) amount                           │
│                of the good taken from the artisan/factory                                     │
│                                                                                                │
│         b) If esi (destination) already had an entry for that good:                          │
│              - directly subtracts (int64, low+high with SBB) the artisan/factory's           │
│                amount from esi's existing entry                                               │
│                                                                                                │
│  Net result: esi.stockpile[good] -= artisan/factory.stockpile[good]                          │
│  (either by creating the entry with the negative value, or by subtracting from the existing)  │
│                                                                                                │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Key points / findings

```text
┌────────────────────────────┬───────────────────────────────────────────────────────────────┐
│ Element                     │ Meaning                                                        │
├────────────────────────────┼───────────────────────────────────────────────────────────────┤
│ [0x12587f4]                 │ number_of_goods — total number of goods (global)              │
│ [edi/esi + idx + 0x08]      │ per-good bitflag: is this good present/active?                │
│                              │ (0 = absent, !=0 → also doubles as the index once assigned)   │
│ [entity + 0x48]             │ stockpile_vector_begin — start of the stockpile vector          │
│ [entity + 0x4c]             │ stockpile_vector_end — end of the stockpile vector             │
│ (end - begin) >> 3          │ number of entries already used (each entry = 8 bytes = int64)  │
│ stockpile entry             │ a 64-bit integer (2×int32: low/high) per good                  │
│ NEG ECX / ADC EDX,0 / NEG EDX│ negation of a full 64-bit integer                              │
│ vector_push_back_edi        │ appends a new 8-byte (int64) entry to esi's vector             │
│ SUB + SBB                   │ 64-bit subtraction with borrow propagation                     │
└────────────────────────────┴───────────────────────────────────────────────────────────────┘
```

**Conclusion:** this function confirms that the goods of an artisan/factory are represented via **positional bitflags** inside the base struct (offset `+0x08` onward, one per good), and that the actual stockpile (the amounts) lives in a **vector of 64-bit integers** pointed to from `+0x48` (begin) and `+0x4c` (end). The index within that vector is not necessarily the same as the bitflag's `idx`: it is recalculated dynamically based on how many entries already exist, and that recalculated index is stored back into the bitflag byte itself (reusing the same byte for two purposes: "is it present?" and "what position in the vector is it at?").

---

ESPAÑOL: 

# VICTORIA II — DOCUMENTACIÓN DE INGENIERÍA INVERSA

Documento consolidado con todos los mapas del sistema recopilados hasta ahora.

---

# PARTE I — SISTEMA DE VELOCIDAD DE JUEGO

## MAPA 1 — SISTEMA DE VELOCIDAD DE JUEGO (VISIÓN GENERAL)

```text
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│                           VICTORIA II — SISTEMA DE VELOCIDAD DE JUEGO                         │
└──────────────────────────────────────────────────────────────────────────────────────────────┘


                                   COMANDOS DE VELOCIDAD
                                            │
                         ┌──────────────────┼──────────────────┐
                         │                  │                  │
                         ▼                  ▼                  ▼
                  0072EE90            0072EFE0            0064E608
               Increase Speed       Decrease Speed       gamespeed_max
                         │                  │                  │
                         └──────────────┬───┘                  │
                                        ▼
                                  B28 = B28 ± 1
                                  Clamp: 0..4
                                        │
                                        ▼
                              DAT_012588E8 + 0xB28
                                ÍNDICE DE VELOCIDAD
                                        │
                         ┌──────────────┼──────────────┐
                         │              │              │
                         ▼              ▼              ▼
                      B28=0          B28=1          B28=2
                         │              │              │
                         ▼              ▼              ▼
                  SLOWEST_SPEED    SLOW_SPEED     NORMAL_SPEED
                         │              │              │
                         ▼              ▼              ▼
                     00F0956C       00F09570       00F09574
                       0.03f          0.03f          0.03f
                         │              │              │
                         └──────────────┼──────────────┘
                                        │
                         ┌──────────────┴──────────────┐
                         │                             │
                         ▼                             ▼
                      B28=3                         B28=4
                         │                             │
                         ▼                             ▼
                    FAST_SPEED                  FASTEST_SPEED
                         │                             │
                         ▼                             ▼
                     00F09578                     00F0957C
                       0.04f                         0.06f
                         │                             │
                         └──────────────┬──────────────┘
                                        │
                                        ▼
                         ┌─────────────────────────────┐
                         │  UPDATE TIME THROTTLE       │
                         │       00685620              │
                         └──────────────┬──────────────┘
                                        │
                                        ▼
                              MOV EAX,[EDI+0xB28]
                                        │
                                        ▼
                              EAX = B28 (0..4)
                                        │
                                        ▼
                MOVSS XMM0,[EAX*4 + DAT_00F0956C]
                                        │
                                        ▼
                       SELECCIÓN DEL FLOAT DE THROTTLE
                                        │
                                        ▼
                              XMM0 = TABLA[B28]
                                        │
                                        ▼
                              × DAT_013F2AE8
                                        │
                                        ▼
                         DAT_012588F0 + 1.0
                                        │
                                        ▼
                              UMBRAL DE TIEMPO
                                        │
                                        ▼
                            COMPARACIÓN DE TIEMPO
                                        │
                         ┌──────────────┴──────────────┐
                         │                             │
                         ▼                             ▼
                   NO ALCANZADO                   ALCANZADO
                         │                             │
                         ▼                             ▼
                        RET                 vtable + 0x100 CALL
                                                        │
                                                        ▼
                                      ProcessMessagePumpAndUpdate
                                             009DF2B0
                                                        │
                                                        ▼
                                        CICLO DE ACTUALIZACIÓN DEL JUEGO


                         ╔══════════════════════════════════╗
                         ║      SEGUNDO USO DE B28          ║
                         ╚════════════════╦═════════════════╝
                                          │
                                          ▼
                                     FUN_00682BD0
                              ProcesarAvanceTemporalDelJuego
                                          │
                                          ▼
                                MOV EAX,[ESI+0xB28]
                                          │
                                          ▼
                                     EAX = B28
                                          │
                                          ▼
                                      B28 × 4
                                          │
                                          ▼
                                 TABLA DE ESCALA
                                          │
                  ┌───────────────────────┼───────────────────────┐
                  │                       │                       │
                  ▼                       ▼                       ▼
               B28=0                  B28=1                  B28=2
                  │                       │                       │
                  ▼                       ▼                       ▼
                4.0f                    2.0f                    1.0f
                  │                       │                       │
                  ▼                       ▼                       ▼
             00F17B58                00F17B54                00F092FC
                  │                       │                       │
                  └───────────────────────┼───────────────────────┘
                                          │
                            ┌─────────────┴─────────────┐
                            │                           │
                            ▼                           ▼
                         B28=3                       B28=4
                            │                           │
                            ▼                           ▼
                          0.5f                       0.0004f
                            │                           │
                            ▼                           ▼
                       00F17898                    00E45BB8
                            │                           │
                            └─────────────┬─────────────┘
                                          │
                                          ▼
                            TABLA COMPLETA VANILLA
                                          │
                                          ▼
                         4.0 / 2.0 / 1.0 / 0.5 / 0.0004
```

---

## MAPA 1A — TABLA VANILLA DE UPDATE TIME THROTTLE

La primera tabla comienza en:

```text
DAT_00F0956C
```

Se accede mediante:

```asm
MOV EAX,[EDI+0xB28]
MOVSS XMM0,[EAX*4 + DAT_00F0956C]
```

Esto significa que:

```text
B28 = índice de la tabla
```

y cada entrada ocupa:

```text
4 bytes
```

Por lo tanto, el orden exacto es:

```text
B28=0
    ↓
DAT_00F0956C
    ↓
0.03f

B28=1
    ↓
DAT_00F09570
    ↓
0.03f

B28=2
    ↓
DAT_00F09574
    ↓
0.03f

B28=3
    ↓
DAT_00F09578
    ↓
0.04f

B28=4
    ↓
DAT_00F0957C
    ↓
0.06f
```

### Tabla completa

```text
┌─────┬────────────┬───────────────┬──────────────┐
│ B28 │ Dirección  │ Valor Vanilla │ Velocidad UI │
├─────┼────────────┼───────────────┼──────────────┤
│  0  │ 00F0956C   │ 0.03f         │ SLOWEST      │
│  1  │ 00F09570   │ 0.03f         │ SLOW         │
│  2  │ 00F09574   │ 0.03f         │ NORMAL       │
│  3  │ 00F09578   │ 0.04f         │ FAST         │
│  4  │ 00F0957C   │ 0.06f         │ FASTEST      │
└─────┴────────────┴───────────────┴──────────────┘
```

### Bytes vanilla

```text
0.03f = 8F C2 F5 3C
0.04f = 0A D7 23 3D
0.06f = 8F C2 75 3D
```

Disposición en memoria:

```text
00F0956C → 8F C2 F5 3C
00F09570 → 8F C2 F5 3C
00F09574 → 8F C2 F5 3C
00F09578 → 0A D7 23 3D
00F0957C → 8F C2 75 3D
```

---

## MAPA 1B — UPDATE TIME THROTTLE

```text
                         UPDATE TIME THROTTLE
                                00685620
                                     │
                                     ▼
                           MOV EAX,[EDI+0xB28]
                                     │
                                     ▼
                              EAX = B28
                                0..4
                                     │
                                     ▼
                MOVSS XMM0,[EAX*4 + DAT_00F0956C]
                                     │
                                     ▼
                              TABLA[B28]
                                     │
                ┌────────────────────┼────────────────────┐
                │                    │                    │
                ▼                    ▼                    ▼
             B28=0                 B28=1                 B28=2
             0.03f                  0.03f                  0.03f
                │                    │                    │
                └────────────────────┼────────────────────┘
                                     │
                         ┌───────────┴───────────┐
                         │                       │
                         ▼                       ▼
                      B28=3                   B28=4
                      0.04f                   0.06f
                         │                       │
                         └───────────┬───────────┘
                                     │
                                     ▼
                                    XMM0
                                     │
                                     ▼
                            × DAT_013F2AE8
                                     │
                                     ▼
                         × (DAT_012588F0 + 1.0)
                                     │
                                     ▼
                              UMBRAL DE TIEMPO
                                     │
                                     ▼
                            COMPARACIÓN DE TIEMPO
                                     │
                     ┌───────────────┴───────────────┐
                     │                               │
                     ▼                               ▼
                NO ALCANZADO                     ALCANZADO
                     │                               │
                     ▼                               ▼
                    RET                    vtable + 0x100
                                                    │
                                                    ▼
                                      ProcessMessagePumpAndUpdate
                                               009DF2B0
                                                    │
                                                    ▼
                                    ACTUALIZACIÓN DEL JUEGO
```

---

## MAPA 1C — FÓRMULA DE UPDATE TIME THROTTLE

La secuencia relevante es:

```asm
0068568B
MOV EAX,[EDI+0xB28]

00685691
MOVSS XMM0,[EAX*4 + DAT_00F0956C]

0068569A
MOVSS XMM1,[DAT_013F2AE8]

006856A2
CVTPS2PD XMM1,XMM1

006856A5
CVTPS2PD XMM0,XMM0

006856A8
MULSD XMM0,XMM1

006856AC
MOVSS XMM1,[DAT_012588F0]

006856B4
CVTPS2PD XMM1,XMM1

006856B7
ADDSD XMM1,[DOUBLE_00E45580]
```

`DOUBLE_00E45580`:

```text
1.0
```

Por lo tanto:

```text
TABLA[B28]
      │
      ▼
× DAT_013F2AE8
      │
      ▼
× (DAT_012588F0 + 1.0)
      │
      ▼
UMBRAL DE TIEMPO
```

---

## MAPA 2 — SEGUNDO SISTEMA: FUN_00682BD0

```text
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│                 FUN_00682BD0 — PROCESAR AVANCE TEMPORAL DEL JUEGO                             │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
```

Esta función tiene varias responsabilidades relacionadas con la progresión temporal.

```text
FUN_00682BD0
│
├── 1. Acumula tiempo
│      │
│      └── [ESI+0xB14] += XMM0
│
├── 2. Comprueba [ESI+0xB20]
│      │
│      └── si != 0 → RETURN
│
├── 3. Lee B28
│      │
│      └── MOV EAX,[ESI+0xB28]
│
├── 4. Construye la tabla temporal
│      │
│      ├── B28=0 → 4.0f
│      ├── B28=1 → 2.0f
│      ├── B28=2 → 1.0f
│      ├── B28=3 → 0.5f
│      └── B28=4 → 0.0004f
│
├── 5. Selecciona TABLA[B28]
│
├── 6. Compara el acumulador [ESI+0xB14]
│      contra el valor seleccionado
│
├── 7. Continúa con el procesamiento temporal
│
├── 8. Procesa lógica relacionada con calendario/fecha
│
└── 9. Modifica DAT_012588F0
```

---

## MAPA 2A — CONSTRUCCIÓN DE LA TABLA

Código vanilla:

```asm
00682C1F
MOVSS XMM0,[DAT_00F17B58]
```

Resultado:

```text
[EBP-0x24] = 4.0f
```

Luego:

```asm
00682C32
MOVSS XMM0,[DAT_00F17B54]
```

Resultado:

```text
[EBP-0x20] = 2.0f
```

Luego:

```asm
00682C3F
MOVSS XMM0,[DAT_00F092FC]
```

Resultado:

```text
[EBP-0x1C] = 1.0f
```

Luego:

```asm
00682C4C
MOVSS XMM0,[DAT_00F17898]
```

Resultado:

```text
[EBP-0x18] = 0.5f
```

Finalmente:

```asm
00682C59
MOVSS XMM0,[DAT_00E45BB8]
```

Resultado:

```text
[EBP-0x14] = 0.0004f
```

---

## MAPA 2B — ORDEN EXACTO DE LA TABLA

El orden es **estrictamente B28 = 0 → 1 → 2 → 3 → 4**.

```text
                 MOV EAX,[ESI+0xB28]
                            │
                            ▼
                       EAX = B28
                            │
                            ▼
                          EAX×4
                            │
                            ▼
                 [EBP + EAX*4 - 0x24]
                            │
             ┌──────────────┼──────────────┐
             │              │              │
             ▼              ▼              ▼
          B28=0           B28=1          B28=2
             │              │              │
             ▼              ▼              ▼
       [EBP-0x24]      [EBP-0x20]      [EBP-0x1C]
             │              │              │
             ▼              ▼              ▼
           4.0f           2.0f           1.0f
             │              │              │
             ▼              ▼              ▼
       DAT_00F17B58   DAT_00F17B54   DAT_00F092FC


                            │
                            ▼
                       B28=3
                            │
                            ▼
                       [EBP-0x18]
                            │
                            ▼
                          0.5f
                            │
                            ▼
                       DAT_00F17898


                            │
                            ▼
                       B28=4
                            │
                            ▼
                       [EBP-0x14]
                            │
                            ▼
                        0.0004f
                            │
                            ▼
                       DAT_00E45BB8
```

---

## MAPA 2C — TABLA VANILLA COMPLETA

```text
┌─────┬────────────┬────────────┬──────────────────────────┐
│ B28 │ LOCAL      │ DAT        │ VALOR VANILLA             │
├─────┼────────────┼────────────┼──────────────────────────┤
│  0  │ EBP-0x24   │ 00F17B58   │ 4.0f                     │
│  1  │ EBP-0x20   │ 00F17B54   │ 2.0f                     │
│  2  │ EBP-0x1C   │ 00F092FC   │ 1.0f                     │
│  3  │ EBP-0x18   │ 00F17898   │ 0.5f                     │
│  4  │ EBP-0x14   │ 00E45BB8   │ 0.0004f                  │
└─────┴────────────┴────────────┴──────────────────────────┘
```

### Bytes IEEE-754

```text
4.0f:
00 00 80 40

2.0f:
00 00 00 40

1.0f:
00 00 80 3F

0.5f:
00 00 00 3F

0.0004f:
17 B7 D1 38
```

---

## MAPA 2D — COMPARACIÓN DEL ACUMULADOR

La función utiliza:

```text
[ESI+0xB14]
```

como acumulador temporal.

Al comienzo:

```text
[ESI+0xB14] =
    [ESI+0xB14] + XMM0
```

Luego selecciona:

```text
TABLA[B28]
```

y compara el acumulador contra ese valor.

Conceptualmente:

```text
                    [ESI+0xB14]
                          │
                          ▼
                     ACUMULADOR
                          │
                          │ compara
                          ▼
                     TABLA[B28]
                          │
              ┌───────────┴───────────┐
              │                       │
              ▼                       ▼
          NO ALCANZADO             ALCANZADO
              │                       │
              ▼                       ▼
       continuar / return      procesamiento temporal
```

---

## MAPA 3 — BARRERAS DEL PROCESAMIENTO TEMPORAL

`FUN_00682BD0` contiene varias condiciones que pueden alterar o detener el procesamiento.

### BARRERA 1 — [ESI+0xB20]

```text
if ([ESI+0xB20] != 0)
    return;
```

Flujo:

```text
FUN_00682BD0
      │
      ▼
CMP [ESI+0xB20]
      │
      ├── != 0 → RETURN
      │
      └── == 0 → CONTINÚA
```

---

### BARRERA 2 — [ESI+0xBB8]

Código vanilla:

```asm
00682D05
CMP byte ptr [ESI+0xBB8],0

00682D0C
JZ 00682E5D
```

Bytes vanilla:

```text
0F 84 4B 01 00 00
```

Flujo:

```text
                 [ESI+0xBB8]
                       │
                       ▼
                     CMP 0
                       │
             ┌─────────┴─────────┐
             │                   │
          == 0                != 0
             │                   │
             ▼                   ▼
       00682E5D             continúa
```

Esta condición se confirmó experimentalmente como una barrera real.

Durante las pruebas, la siguiente secuencia:

```text
0F 84 4B 01 00 00
```

fue reemplazada por:

```text
90 90 90 90 90 90
```

y el procesamiento continuó a través de la siguiente rama.

**Este cambio es experimental y NO forma parte del código vanilla.**

---

## MAPA 4 — ESTADOS GLOBALES TEMPORALES

`FUN_00682BD0` modifica:

```text
DAT_012588E6
DAT_012588EC
DAT_012588F0
```

Estos estados afectan el comportamiento temporal.

```text
FUN_00682BD0
      │
      ├──────────────► DAT_012588E6
      │
      ├──────────────► DAT_012588EC
      │
      └──────────────► DAT_012588F0
                              │
                              ▼
                       UpdateTimeThrottle
                              │
                              ▼
                       UMBRAL DE TIEMPO
```

---

## MAPA 4A — DAT_012588F0

`DAT_012588F0` es especialmente importante porque aparece en ambos sistemas.

En `UpdateTimeThrottle`:

```text
DAT_012588F0 + 1.0
```

forma parte del cálculo del umbral.

En `FUN_00682BD0`, puede modificarse mediante distintas ramas temporales.

Operaciones observadas incluyen:

```text
DAT_012588F0 × 0.95
```

```text
DAT_012588F0 × 0.9
```

y:

```text
DAT_012588F0 + 0.5
```

También hay lógica relacionada con diferencias de fecha.

Por lo tanto:

```text
FUN_00682BD0
      │
      ▼
DAT_012588F0
      │
      ▼
UpdateTimeThrottle
      │
      ▼
UMBRAL
```

es una conexión importante dentro del sistema.

---

## MAPA 5 — DAT_00E45BB8

```text
┌─────────────────────────────────────────────────────────┐
│ DAT_00E45BB8                                            │
├─────────────────────────────────────────────────────────┤
│ Dirección: 00E45BB8                                     │
│ Valor vanilla: 0.0004f                                  │
│ Bytes: 17 B7 D1 38                                       │
│ Uso en velocidad: B28=4                                 │
└─────────────────────────────────────────────────────────┘
```

Correspondencia:

```text
B28=4
   ↓
DAT_00E45BB8
   ↓
0.0004f
```

Importante:

`DAT_00E45BB8` tiene múltiples XREFs dentro del ejecutable.

Por lo tanto:

```text
CAMBIAR DAT_00E45BB8
        ≠
CAMBIAR ÚNICAMENTE LA VELOCIDAD DE JUEGO
```

Puede afectar a otros consumidores de esta constante.

---

## MAPA 6 — DAT_00F092FC

```text
┌─────────────────────────────────────────────────────────┐
│ DAT_00F092FC                                            │
├─────────────────────────────────────────────────────────┤
│ Dirección: 00F092FC                                     │
│ Valor vanilla: 1.0f                                     │
│ Bytes: 00 00 80 3F                                       │
│ Uso en velocidad: B28=2                                 │
└─────────────────────────────────────────────────────────┘
```

En `FUN_00682BD0`:

```text
B28=2
   ↓
DAT_00F092FC
   ↓
1.0f
```

También aparece en `FUN_00475150`:

```asm
0047527C
MOVSS XMM0,[DAT_00F092FC]

00475286
MOVSS [EDI+0x178],XMM0
```

Por lo tanto:

```text
DAT_00F092FC
      │
      ├── FUN_00682BD0
      │       ↓
      │     B28=2
      │       ↓
      │      1.0f
      │
      └── FUN_00475150
              ↓
          [EDI+0x178]
```

Esto demuestra que `DAT_00F092FC` participa directamente en la tabla de velocidad utilizada por `FUN_00682BD0`.

---

## MAPA 7 — SPEED DISPLAY / UI

```text
                              B28
                               │
                  ┌────────────┴────────────┐
                  │                         │
                  ▼                         ▼
             00715DE5                  0070DFE0
                  │                         │
                  ▼                         ▼
          TABLA DE NOMBRES DE VELOCIDAD  Lee B28
                  │                         │
     ┌────────────┼────────────┐            ▼
     │            │            │       ADD EAX,2
     ▼            ▼            ▼            │
   B28=0        B28=2        B28=4          ▼
  SLOWEST       NORMAL      FASTEST     [ESP+0x30]
     │            │            │            │
     └────────────┼────────────┘            ▼
                  │                    LÓGICA DE UI / ESTADO
                  ▼
       00E11040 → SLOWEST_SPEED
       00E11050 → SLOW_SPEED
       00E1105C → NORMAL_SPEED
       00E1106C → FAST_SPEED
       00E11078 → FASTEST_SPEED
```

---

## MAPA 8 — RELACIÓN ENTRE LAS DOS TABLAS

```text
                         B28 = 0..4
                              │
                ┌─────────────┴─────────────┐
                │                           │
                ▼                           ▼
        TABLA 1 — THROTTLE          TABLA 2 — TEMPORAL
        DAT_00F0956C                FUN_00682BD0
                │                           │
                │                           │
       ┌────────┼────────┐          ┌───────┼───────────────┐
       │        │        │          │       │       │       │
       ▼        ▼        ▼          ▼       ▼       ▼       ▼
     0.03     0.03     0.03        4.0     2.0     1.0     0.5
       │        │        │          │       │       │       │
       │        │        │          │       │       │       │
       └────────┼────────┘          └───────┼───────┼───────┘
                │                           │       │
                ▼                           ▼       ▼
          B28=3 → 0.04                B28=3 → 0.5
          B28=4 → 0.06                B28=4 → 0.0004
                │                           │
                └─────────────┬─────────────┘
                              │
                              ▼
                       SISTEMA TEMPORAL
```

Las tablas **no contienen los mismos valores ni cumplen exactamente la misma función**.

Lo único que comparten directamente es el índice:

```text
B28
```

---

## MAPA 9 — MAPEO COMPLETO DE B28

```text
┌─────┬──────────────────┬──────────────┬──────────────────────┬──────────────┐
│ B28 │ VELOCIDAD        │ UI           │ UPDATE TIME THROTTLE │ TEMPORAL     │
├─────┼──────────────────┼──────────────┼──────────────────────┼──────────────┤
│  0  │ SLOWEST_SPEED    │ SLOWEST      │ 0.03f                │ 4.0f         │
│  1  │ SLOW_SPEED       │ SLOW         │ 0.03f                │ 2.0f         │
│  2  │ NORMAL_SPEED     │ NORMAL       │ 0.03f                │ 1.0f         │
│  3  │ FAST_SPEED       │ FAST         │ 0.04f                │ 0.5f         │
│  4  │ FASTEST_SPEED    │ FASTEST      │ 0.06f                │ 0.0004f      │
└─────┴──────────────────┴──────────────┴──────────────────────┴──────────────┘
```

El orden de ambas tablas es:

```text
B28=0
    ↓
B28=1
    ↓
B28=2
    ↓
B28=3
    ↓
B28=4
```

El orden no debe interpretarse según el valor numérico de los floats ni según la dirección de las constantes.

El índice `B28` determina qué entrada se utiliza.

---

## MAPA 10 — FLUJO COMPLETO DEL SISTEMA

```text
                         Increase / Decrease Speed
                                  │
                                  ▼
                             B28 = 0..4
                                  │
             ┌────────────────────┼────────────────────┐
             │                    │                    │
             ▼                    ▼                    ▼
          SPEED UI          UpdateTimeThrottle      FUN_00682BD0
        00715DE5 /             00685620                │
        0070DFE0                   │                   │
             │                     │                   ▼
             │                     │             MOV EAX,[ESI+0xB28]
             │                     │                   │
             │                     │                   ▼
             │                     │             TABLA TEMPORAL
             │                     │                   │
             │                     │       ┌───────────┼────────────┐
             │                     │       ▼           ▼            ▼
             │                     │      4.0         2.0          1.0
             │                     │       │           │            │
             │                     │       └───────────┼────────────┘
             │                     │                   │
             │                     │             0.5 / 0.0004
             │                     │                   │
             │                     ▼                   ▼
             │               DAT_00F0956C         ACUMULADOR B14
             │                     │                   │
             │                     ▼                   ▼
             │               0.03/0.04/0.06      B20 / BB8
             │                     │                   │
             │                     ▼                   ▼
             │              × DAT_013F2AE8       LÓGICA TEMPORAL
             │                     │                   │
             │                     ▼                   ▼
             │          × (DAT_012588F0 + 1)    DAT_012588F0
             │                     │                   │
             │                     ▼                   │
             │              UMBRAL DE TIEMPO           │
             │                     │                   │
             │                     ▼                   │
             │             COMPARACIÓN DE TIEMPO       │
             │                     │                   │
             │                     ▼                   │
             │       ProcessMessagePumpAndUpdate ◄─────┘
             │                  009DF2B0
             │                     │
             └─────────────────────┴───────────────────►
                             ACTUALIZACIÓN DEL JUEGO
```

---

## MAPA 11 — PUNTOS IMPORTANTES PARA MODDING

```text
┌────────────────────────────────────────────────────────────────┐
│                    PUNTOS DE INTERÉS                           │
├────────────────────┬───────────────────────────────────────────┤
│ 00685620           │ UpdateTimeThrottle                        │
│ 00682BD0           │ ProcesarAvanceTemporalDelJuego             │
│ 00F0956C           │ Inicio de la tabla de UpdateTimeThrottle  │
│ 00F0957C           │ Entrada B28=4 → 0.06f                     │
│ 00F17B58           │ Entrada B28=0 → 4.0f                      │
│ 00F17B54           │ Entrada B28=1 → 2.0f                      │
│ 00F092FC           │ Entrada B28=2 → 1.0f                      │
│ 00F17898           │ Entrada B28=3 → 0.5f                      │
│ 00E45BB8           │ Entrada B28=4 → 0.0004f                   │
│ 012588F0           │ Factor temporal compartido                │
│ [ESI+0xB14]        │ Acumulador temporal                        │
│ [ESI+0xB20]        │ Estado que puede detener la función        │
│ [ESI+0xBB8]        │ Condición/barrera temporal                 │
│ 009DF2B0           │ ProcessMessagePumpAndUpdate                │
└────────────────────┴───────────────────────────────────────────┘
```

---

## MAPA 12 — CONCLUSIÓN

El sistema de velocidad de Victoria II utiliza:

```text
                         B28 = 0..4
                              │
                ┌─────────────┴─────────────┐
                │                           │
                ▼                           ▼
       UPDATE TIME THROTTLE        AVANCE TEMPORAL
             00685620                  00682BD0
                │                           │
                ▼                           ▼
       0.03/0.03/0.03/0.04/0.06   4.0/2.0/1.0/0.5/0.0004
                │                           │
                ▼                           ▼
       DAT_013F2AE8                [ESI+0xB14]
                │                           │
                ▼                           ▼
       DAT_012588F0                [ESI+0xB20]
                │                           │
                │                      [ESI+0xBB8]
                │                           │
                └──────────────┬────────────┘
                               │
                               ▼
                     ACTUALIZACIÓN DEL JUEGO
```

La conclusión actual es que **B28 es el índice central de velocidad**, pero Victoria II utiliza **dos tablas diferentes** para controlar distintos aspectos del procesamiento temporal.

La tabla de `UpdateTimeThrottle` controla el umbral usado para determinar cuándo debe ejecutarse el ciclo de actualización.

La tabla de `FUN_00682BD0` se usa en el procesamiento del avance temporal y contiene cinco entradas completas, incluyendo:

```text
B28=4 → 0.0004f
```

Por lo tanto, la tabla correcta y completa es:

```text
B28=0 → 4.0f
B28=1 → 2.0f
B28=2 → 1.0f
B28=3 → 0.5f
B28=4 → 0.0004f
```

Y la tabla de `UpdateTimeThrottle`:

```text
B28=0 → 0.03f
B28=1 → 0.03f
B28=2 → 0.03f
B28=3 → 0.04f
B28=4 → 0.06f
```

Estos son los **valores vanilla**.

Los valores modificados durante las pruebas, como el `4.0f` introducido mediante un code cave en `00685691`, el `5.0f` en pruebas sobre `DAT_00F092FC`, el `0.000001f` en `DAT_00E45BB8`, o los NOP en `00682D0C`, deben considerarse **parches experimentales**, no parte del sistema vanilla.

---

# PARTE II — ESTRUCTURA GENERAL DEL MOTOR, ECONOMÍA, CONSOLA Y FOG OF WAR

```text
00AB0F91
  ENTRY / PUNTO DE ENTRADA
    |
    v
009DF550
  MAIN LOOP / BUCLE PRINCIPAL
    |
    +-- 009796B0
    |     WINMAIN / CLAUSEWITZ ENGINE
    |       |
    |       +-- Inicialización del motor
    |       +-- Bucle principal del juego
    |       +-- Actualizaciones por tick
    |
    +-- 0068BF00
    |     ECONOMY / ECONOMÍA
    |       |
    |       +-- Economy_Update
    |       |     |
    |       |     +-- WorldMarket_Update
    |       |     |     |
    |       |     |     +-- 00482930
    |       |     |           ACTUALIZAR SUMINISTRO / SUPPLY
    |       |     |             |
    |       |     |             +-- Oferta / Supply
    |       |     |             +-- Demanda / Demand
    |       |     |             +-- Comparación de 64 bits
    |       |     |             +-- DividirEntero64ConSigno
    |       |     |             +-- CalcularMultiplicadorSuministro
    |       |     |             |
    |       |     |             v
    |       |     |           ACTUALIZAR PRECIO
    |       |     |           00482B...
    |       |     |             |
    |       |     |             +-- Precio base
    |       |     |             +-- Multiplicador
    |       |     |             +-- Límite mínimo
    |       |     |             |     DAT_00E45C30
    |       |     |             |     Vanilla: ×0.2
    |       |     |             |
    |       |     |             +-- Límite máximo
    |       |     |                   DAT_00E45C28
    |       |     |                   Vanilla: ×5.0
    |       |     |
    |       |     +-- Otras funciones de economía
    |       |     |
    |       |     +-- [NUEVO — funciones renombradas por el compañero]
    |       |           |
    |       |           +-- FUN_0047e3e0
    |       |           |     Market_ComputeScaledDotProduct
    |       |           |     usada en 58 lugares distintos
    |       |           |     probablemente NO es específica de mercado
    |       |           |     (función matemática genérica, uso aún sin confirmar)
    |       |           |
    |       |           +-- FUN_0047de60
    |       |           |     Buffer_ScaleValuesInRange
    |       |           |     alias: multiply_values_in_vector
    |       |           |     usada en 53 lugares — opera sobre vectores /
    |       |           |     bloques de memoria contiguos
    |       |           |
    |       |           +-- Buffer_AccumulateIndexedValue
    |       |           |     alias: add_stockpiles_to_market_stats
    |       |           |     suma cantidades almacenadas (stockpile) a
    |       |           |     demand y supply
    |       |           |       0x0047dc56  MOV EDI,[ECX+EDX*8]
    |       |           |         ; cantidad stockpileada
    |       |           |       0x0047dc59  ADD [EAX],EDI
    |       |           |         ; [EAX] = supply o demand global
    |       |           |         ; (según contexto)
    |       |           |
    |       |           +-- FUN_0043a880
    |       |           |     vector_resize
    |       |           |
    |       |           +-- 0x0047d9e0
    |       |           |     función de clamping
    |       |           |     alias: clamp_0_to_arg8h_&_argch
    |       |           |
    |       |           +-- FUN_004dd470
    |       |           |     alias: multiply_goods_clamp_0_99999
    |       |           |     0xc34f8000 = 3276767232 / 2^15 = 99999
    |       |           |
    |       |           +-- FUN_00487410
    |       |           |     Market_ProcessGoodSupplyDemand
    |       |           |     [region-wide aggregate close]
    |       |           |     alias: add_real_demand_for_good_1
    |       |           |     (hay otra función similar, por eso el "_1")
    |       |           |     CONFIRMADO: solo toca DEMAND, no supply
    |       |           |       0x004877b1  LEA EAX,[EDX+EAX*8]
    |       |           |         ; EAX = índice en contenedor real_demand
    |       |           |         ; EDX = dirección del contenedor real_demand
    |       |           |
    |       |           +-- 0x0054c600
    |       |           |     intro_sort
    |       |           |
    |       |           +-- FUN_00485e40
    |       |           |     alias: pop_daily_update_money
    |       |           |     actualiza needs met, banco, y más (por POP)
    |       |           |
    |       |           +-- 00523400
    |       |                 alias: calculate_loan_interest
    |       |                 (coincide con LÓGICA DE PRÉSTAMOS más abajo)
    |       |
    |       +-- 00523400
    |             PRÉSTAMOS / LOANS
    |               |
    |               +-- Cálculo de intereses
    |               +-- Interés base
    |               +-- Límite mínimo de interés
    |               +-- Lógica del parche de intereses
    |
    +-- AI / INTELIGENCIA ARTIFICIAL
    |     |
    |     +-- AI_SimpleThresholdCheck
    |           |
    |           +-- Comprobación de condiciones
    |           +-- Evaluación de umbrales
    |           +-- Llamadas relacionadas con event_system
    |           |
    |           v
    |       SISTEMA DE EVENTOS
    |         008A67B0
    |
    +-- 008A67B0
    |     SISTEMA / GESTOR DE RECURSOS DE EVENTOS
    |       |
    |       +-- FUN_008A5AC0
    |       |     INICIALIZAR GESTOR DE EVENTOS
    |       |
    |       +-- FUN_008A5C70
    |       |     INICIALIZAR ESTRUCTURA DE EVENTO
    |       |
    |       +-- FUN_009A1440
    |       |     INICIALIZAR OBJETO EVENTO
    |       |
    |       +-- FUN_008A6010
    |       |     OBTENER NOMBRE EVENTO PRINCIPAL
    |       |
    |       +-- FUN_008A60F0
    |       |     OBTENER NOMBRE EVENTO SECUNDARIO
    |       |
    |       +-- FUN_008A67B0
    |             CARGAR RECURSOS DE EVENTOS
    |             [ESTRUCTURA PRINCIPAL?]
    |
    +-- [NUEVO] CONSOLA DE COMANDOS
    |     |
    |     +-- comandos_consola (antes FUN_00420EB0)
    |           DISPATCHER PRINCIPAL DE LA CONSOLA
    |             |
    |             +-- Recibe param_2 = tokens del comando escrito
    |             +-- Cascada de comparaciones vía FUN_0040b360 (strcmp)
    |             |     contra literales DAT_00dfXXXX
    |             +-- Confirmado empíricamente: si se desactiva esta
    |             |     función, los comandos de consola dejan de existir
    |             |
    |             +-- Ramas identificadas (parcial, por comportamiento):
    |             |     |
    |             |     +-- Toggles de debug/log simples
    |             |     |     DAT_012586d8  -> log de WorldMarket_Update /
    |             |     |                      Economy_Update (confirmado,
    |             |     |                      escribe a archivo vía
    |             |     |                      get_or_initialize_singleton_instance)
    |             |     |     DAT_0125873c, DAT_0125899e, DAT_0125873e,
    |             |     |     DAT_012587e0, DAT_00f09545, DAT_012586d7,
    |             |     |     DAT_00f09544, DAT_00f07da6  -> otros toggles
    |             |     |     de log por subsistema (aún sin nombre exacto)
    |             |     |
    |             |     +-- Bitfield de flags globales (iVar5+0xe8)
    |             |     |     togglea bits 0x800000..0x20000000 según rama
    |             |     |
    |             |     +-- Comando "fow" (CONFIRMADO — ver bloque abajo)
    |             |     |     0x422090 .. 0x4222e9
    |             |     |     togglea DAT_013f080c, escribe en
    |             |     |     [DAT_01258a74 + 0x6bc44]
    |             |     |
    |             |     +-- Comando con conteo de argumentos ≥2/4/5/6
    |             |     |     lee offsets 0x38/0x54/0x70/0x8c de un
    |             |     |     objeto vía DAT_012587e4 (posible tabla
    |             |     |     de bienes/goods) — candidato a comando
    |             |     |     de mercado con parámetros
    |             |     |
    |             |     +-- Comando con FUN_0090cc40/FUN_0090da40 +
    |             |     |     tag de país + vtable+0x2c en offsets
    |             |     |     0x4c/0xd8/0xa0 — candidato fuerte a
    |             |     |     comandos que modifican stats de un país
    |             |     |     específico (tesoro/prestigio/infamia)
    |             |     |
    |             |     +-- Comando con CharUpperBuffA + ~10 comparaciones
    |             |           uppercase, cada una togglea un bit distinto
    |             |           (0x1,0x2,0x8,0x10,...,0x400) del mismo
    |             |           bitfield — candidato a "log <categoria>"
    |             |
    |             +-- FUN_00428d40
    |                   suma param_1 a [EAX+0x10] y clampea entre
    |                   0 y 0x186a0 (100000)
    |                   usada también en FUN_00580480 (evento/ocupación)
    |                   función genérica de acumulador con límite,
    |                   NO es velocidad de juego (descartado)
    |
    +-- [NUEVO] RENDERIZADO / FOG OF WAR (FoW)
    |     |
    |     +-- DAT_01258a74
    |     |     puntero al render device / motor gráfico (singleton)
    |     |     escrito en InitializeGraphicsDevice
    |     |
    |     +-- DAT_013f080c
    |     |     flag global de estado FoW (0 = niebla activa,
    |     |     1 = niebla desactivada)
    |     |     escrito por comandos_consola (comando "fow")
    |     |     espejado en [DAT_01258a74 + 0x6bc44]
    |     |
    |     +-- InitializeGraphicsDevice (0x994577)
    |     |     inicializa el bloque +0x6bc44..+0x6bc98 en 0
    |     |     (estado por defecto: niebla activa)
    |     |
    |     +-- FUN_0099da20
    |     |     INIT / RESTORE del device gráfico
    |     |     XREFs: InitializeGraphicsDevice, FUN_0099bf60,
    |     |             CheckAndRestoreGraphicsDevice
    |     |     0x99db69  CMP [ESI+0x6bc44],0
    |     |     0x99db7b  JZ  -> PUSH 3 (fog ON)
    |     |               (no salta) -> PUSH 2 (fog OFF)
    |     |     CONFIRMADO EXPERIMENTALMENTE:
    |     |       parchear este JZ->NOP rompe el RENDERIZADO DE TEXTO
    |     |       (UI/HUD) — controla la capa de texto/inicialización
    |     |       de esa parte del motor (ver imágenes 1 y 2)
    |     |
    |     +-- FUN_006592f0
    |           corre en el LOOP POR FRAME, justo antes de
    |           CALL UpdateGameFrame (0x65957f)
    |           0x6594c7  CMP [EDI+0x6bc44],BL   (BL=0)
    |           0x6594cd  JZ  -> salta el bloque (fog no forzado)
    |                     (no salta) -> PUSH 2,8 ; CALL vtable[0xe4]
    |                                    (fuerza fog OFF ese frame)
    |           precedido por CheckAndRestoreGraphicsDevice
    |           (0x6594b4, TEST AL,AL / JZ LAB_00659737) — esta
    |           condición previa puede estar saltando todo el bloque
    |           CONFIRMADO EXPERIMENTALMENTE:
    |             parchear este JZ->NOP rompe las TEXTURAS DE TERRENO
    |             del mapa (ver imagen 3) — controla la capa de
    |             render de texturas del mapa, no solo el flag lógico
    |           PENDIENTE: revisar la condición previa en
    |             CheckAndRestoreGraphicsDevice antes de decidir
    |             el patch definitivo para dejar FoW siempre OFF
    |
    +-- OTROS SISTEMAS DEL TICK
          |
          +-- Actualización de países
          +-- Actualización de POPs
          +-- Actualización de IA
          +-- Actualización de economía
          +-- Actualización de eventos
          +-- Actualización de guerra
          +-- Actualización del mundo


FLUJO ECONÓMICO DETALLADO
  |
  v
0068BF00
  ECONOMY_UPDATE
    |
    v
WORLD MARKET UPDATE
    |
    v
00482930
  ACTUALIZAR SUMINISTRO
    |
    +-- SUPPLY
    +-- DEMAND
    +-- COMPARACIÓN 64-BIT
    +-- DIVIDIRENTERO64CONSIGNO
    +-- CALCULARMULTIPLICADORSUMINISTRO
    |
    v
00482B...
  ACTUALIZAR PRECIO
    |
    +-- PRECIO BASE
    +-- MULTIPLICADOR
    +-- LÍMITE MÍNIMO
    |     DAT_00E45C30
    |     ×0.2 VANILLA
    |
    +-- LÍMITE MÁXIMO
    |     DAT_00E45C28
    |     ×5.0 VANILLA
    |
    v
  PRECIO FINAL


FLUJO DE EVENTOS
  |
  v
AI_SIMPLETHRESHOLDCHECK
    |
    +-- Comprueba condiciones
    |
    +-- Comprueba umbrales
    |
    +-- Realiza llamadas relacionadas con eventos
    |
    v
008A67B0
  SISTEMA DE EVENTOS
    |
    +-- 008A5AC0
    |     Inicializar Gestor de Eventos
    |
    +-- 008A5C70
    |     Inicializar Estructura de Evento
    |
    +-- 009A1440
    |     Inicializar Objeto Evento
    |
    +-- 008A6010
    |     Obtener Nombre Evento Principal
    |
    +-- 008A60F0
    |     Obtener Nombre Evento Secundario
    |
    +-- 008A67B0
          Cargar Recursos de Eventos


FLUJO DE PRECIO QUE ESTAMOS MODIFICANDO
  |
  v
00482930
  SUMINISTRO
    |
    v
  DEMANDA
    |
    v
  COMPARACIÓN SUPPLY VS DEMAND
    |
    v
  DIVIDIRENTERO64CONSIGNO
    |
    v
  CALCULARMULTIPLICADORSUMINISTRO
    |
    v
00482B...
  CÁLCULO DEL PRECIO
    |
    +-- PRECIO BASE
    |
    +-- MULTIPLICADOR
    |
    +-- LÍMITE MÍNIMO
    |     DAT_00E45C30
    |     |
    |     +-- VANILLA: ×0.2
    |     +-- MODIFICADO: ×0.1
    |
    +-- LÍMITE MÁXIMO
          DAT_00E45C28
          |
          +-- VANILLA: ×5.0
          +-- MODIFICADO: ×10.0
    |
    v
  PRECIO FINAL


PARCHE DE SUMINISTRO
  |
  v
00482B03
  HOOK
    |
    v
00C8911A
  CODE CAVE
    |
    +-- Modificar suministro
    +-- Multiplicar valor
    +-- Preservar registros
    +-- Ejecutar instrucciones originales
    +-- Regresar al código original
    |
    +-- PROBLEMA ENCONTRADO
          |
          +-- Code cave llegaba aproximadamente a 00C891FF
          +-- El parche provocaba CRASH


PRÉSTAMOS / INTERESES
  |
  v
00523400
  LÓGICA DE PRÉSTAMOS (calculate_loan_interest)
    |
    +-- Cálculo del interés
    +-- LOAN_BASE_INTEREST
    +-- Interés mínimo
    +-- Código relacionado con el 1%
    |
    v
  PARCHE DE INTERÉS


[NUEVO] FUNCIONES UTILITARIAS / HELPERS RENOMBRADAS
  |
  +-- FUN_0043ab60      Memory_CopyOverlapping -> zero_struct_array
  |                     (parece específico de arrays int64)
  |
  +-- FUN_00aad56b      Memory_ValidateSize -> parece un "operator new"
  |
  +-- FUN_0041a160      Struct_InitWithDefaults -> ctor_with_MTTH
  |                     probablemente constructor de evento
  |
  +-- FUN_0096bbf0      Singleton_Construct
  |                     usa create_string_with_length("null_pop", 8)
  |                     y vtable.CAddAIStrategyEffect.138
  |                     -> posiblemente relacionado a IA de país
  |
  +-- thunk_FUN_00ab4d81  Stream_CheckState -> __ptmbcinfo
  |                     chequea si el thread usa MBCS o code page local
  |
  +-- FUN_0047db00      Buffer_CopyAndResize -> CGoodsPool_copy_ctor
  |
  +-- fcn.004f50c0      factory_decay_without_inputs
  |                     código que decae el nivel de fábricas sin inputs


ESTRUCTURA GENERAL DEL MOTOR
  |
  v
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
    +-- ECONOMÍA
    |     |
    |     v
    |   0068BF00
    |     |
    |     v
    |   00482930
    |     |
    |     v
    |   00482B...
    |
    +-- IA
    |     |
    |     v
    |   AI_SimpleThresholdCheck
    |     |
    |     v
    |   EVENT_SYSTEM
    |     |
    |     v
    |   008A67B0
    |
    +-- CONSOLA DE COMANDOS
    |     |
    |     v
    |   comandos_consola
    |
    +-- RENDERIZADO / FOW
    |     |
    |     +-- FUN_0099da20   (init/restore -> capa de texto)
    |     +-- FUN_006592f0   (loop por frame -> capa de texturas)
    |
    +-- PRÉSTAMOS
    |     |
    |     v
    |   00523400
    |
    +-- OTROS SISTEMAS
          |
          +-- Guerra
          +-- POPs
          +-- Países
          +-- Investigación
          +-- Diplomacia
          +-- Eventos
          +-- Mercado


NOTAS
  |
  +-- Los nombres de las funciones de eventos son todavía
  |   tentativos hasta confirmar completamente sus XREFs.
  |
  +-- 008A67B0 parece estar relacionado con la carga /
  |   gestión de recursos de eventos, pero todavía no podemos
  |   afirmar que sea el punto principal donde se EJECUTAN
  |   los eventos.
  |
  +-- AI_SimpleThresholdCheck parece estar relacionado con
  |   comprobaciones que pueden terminar interactuando con
  |   event_system.
  |
  +-- Quitar las llamadas a event_system permite que algunas
  |   batallas comiencen, pero posteriormente el juego termina
  |   crasheando después de varios días.
  |
  +-- Por eso event_system probablemente participa en algún
  |   procesamiento posterior / mantenimiento de eventos,
  |   aunque todavía hay que determinar exactamente cuál.
  |
  +-- En economía conviene preservar el flujo vanilla:
  |   Supply -> Demand -> Comparación -> División ->
  |   Multiplicador -> Precio -> Límites.
  |
  +-- El objetivo del parche de precio es modificar únicamente
  |   los límites sin reemplazar la lógica vanilla de
  |   Supply/Demand.
  |
  +-- [NUEVO] comandos_consola confirmado como el dispatcher
  |   único de la consola: desactivarlo elimina TODOS los
  |   comandos, sin excepción.
  |
  +-- [NUEVO] El comando "fow" togglea DAT_013f080c, pero ese
  |   flag por sí solo no alcanza para forzar niebla-off desde
  |   el arranque: hay que intervenir en las funciones de
  |   RENDERIZADO que lo leen (FUN_0099da20 para texto,
  |   FUN_006592f0 para texturas de terreno).
  |
  +-- [NUEVO] Patchear el JZ->NOP directo en cualquiera de las
  |   dos funciones de render ROMPE la capa que controlan
  |   (confirmado empíricamente con capturas). Falta revisar
  |   la condición previa en CheckAndRestoreGraphicsDevice
  |   (0x6594b4) antes de intentar un patch limpio en
  |   FUN_006592f0 que no rompa nada.
  |
  +-- [NUEVO] Funciones utilitarias identificadas por el
  |   compañero (Buffer_ScaleValuesInRange, clamp_0_to_arg8h_
  |   &_argch, multiply_goods_clamp_0_99999, etc.) son de
  |   propósito general y se reutilizan en decenas de lugares
  |   — útiles como referencia cruzada, no como puntos de
  |   parche específicos de economía.
```

---

# PARTE III — SISTEMA DE NÚMEROS ALEATORIOS (RNG)

```text
                         v2game.exe+0xb0ecf0
                       LISTA DE NÚMEROS ALEATORIOS
                        (pre-generada en memoria)
                                  │
                                  ▼
                         v2game.exe+0xb0f6b0
                        ÍNDICE ACTUAL DE LA LISTA
                                  │
                                  ▼
                          func_009b7610
                    FUNCIÓN QUE "POLLEA" UN NÚMERO
                                  │
                    ┌─────────────┴─────────────┐
                    │                           │
                    ▼                           ▼
             ÍNDICE + 1                  ¿LISTA AGOTADA?
                    │                    (todos los números
                    ▼                     ya fueron usados)
          DEVUELVE NÚMERO EN                     │
          ESE ÍNDICE DE LA LISTA          ┌───────┴───────┐
                                          │               │
                                          ▼               ▼
                                         SÍ               NO
                                          │               │
                                          ▼               ▼
                                  func_009b7700      continúa el
                                  GENERA NUEVA        flujo normal
                                  LISTA CON
                                  MERSENNE TWISTER
```

**Notas sobre RNG** (tal cual las pasó el compañero):

- La lista de aleatorios vive en `v2game.exe+0xb0ecf0`.
- El índice de lectura actual está en `v2game.exe+0xb0f6b0`; cada vez que se pide un número aleatorio, ese índice se incrementa en 1 y se usa para indexar la lista.
- Cuando se agotan todos los números de la lista, el juego genera una lista nueva usando el algoritmo Mersenne Twister.
- `func_009b7610` es el punto donde el juego "poll-ea" (extrae) un número de la lista de aleatorios.
- Dentro de esa función, si detecta que ya se usaron todos los números, llama a `func_009b7700` para generar el nuevo set de aleatorios vía Mersenne Twister.

---

# PARTE IV — CALLBACKS DE BOTONES (PARCIAL, SIN CONFIRMAR DEL TODO)

| Función | Rol | Estado |
|---|---|---|
| `func_6dfe80` | Callback al presionar el botón **Westernize** | Confirmado |
| `func_541b90` | Chequeo de condición para saber si el botón Westernize debe estar clickeable | Confirmado |
| `func_772300` | Callback del botón **Play** | Probable — el compañero cree que hay una función distinta para SP y MP, y no recuerda cuál de las dos es esta |
| (otras funciones de botones) | — | Las tenía identificadas pero no las encuentra por ahora — pendiente de recuperar |

---

# PARTE V — [NUEVO] RESTA DE STOCKPILE ARTESANO/FÁBRICA

## MAPA 13 — subtract_artisan_factory_stockpile_from_esi_stockpile (0x0047dca0)

Función muy importante: muestra cómo los bienes (goods) se almacenan como **bitflags** dentro de la estructura base de artesano/fábrica, y cómo se resta el stockpile de un artesano/fábrica contra el stockpile de otra entidad apuntada por `esi` (probablemente el mercado/provincia).

```text
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│         subtract_artisan_factory_stockpile_from_esi_stockpile  (0x0047dca0)                   │
│         subtract_artisan/factory_stockpile_from_esi_stockpile(int32_t artisan/factory)        │
└──────────────────────────────────────────────────────────────────────────────────────────────┘

  arg  int32_t artisan/factory   @ [ebp+0x08]
  var  int32_t var_18h           @ [ebp-0x18]
  var  int32_t var_14h           @ [ebp-0x14]
  var  int32_t var_ch            @ [ebp-0x0c]

                          PROLOGUE
                              │
                              ▼
                    push ebp / mov ebp,esp
                    sub esp,0x14
                              │
                              ▼
                EAX = [0x12587f4]   ; number_of_goods
                              │
                              ▼
                    push ebx / xor ebx,ebx   ; ebx = índice = 0
                    push edi
                    [ebp-0x08] = EAX          ; guarda number_of_goods
                              │
                              ▼
                    TEST EAX,EAX
                              │
                     ┌────────┴────────┐
                     │                 │
                  <= 0               > 0
                     │                 │
                     ▼                 ▼
                    JLE            continúa
                 (fin del loop,
                  ir a 0x47dd21)
                              │
                              ▼
        ╔═══════════════════════════════════════════════╗
        ║   LOOP PRINCIPAL — por cada good (ebx = idx)   ║
        ╚═══════════════════════════════════════════════╝
                              │
                              ▼
                EDI = [ebp+0x08]        ; puntero a artisan/factory
                              │
                              ▼
             CL = [edi + ebx*1 + 0x08]
             ; artisan/factory.good_bit_flags[ebx]
             ; (bitflag: ¿este good está presente?)
                              │
                              ▼
                    TEST CL,CL
                              │
                     ┌────────┴────────┐
                     │                 │
                  == 0               != 0
                     │                 │
                     ▼                 ▼
                 JZ 0x47dd1b      continúa
                 (good ausente,
                  siguiente
                  iteración)
                              │
                              ▼
             AL = [ebx + esi*1 + 0x08]
             ; esi.good_bit_flags[ebx]
             ; (bitflag del stockpile destino/mercado)
                              │
                              ▼
                    TEST AL,AL
                              │
                     ┌────────┴────────┐
                     │                 │
                  == 0               != 0
                     │                 │
                     ▼                 ▼
              (rama A)            (rama B)
              JZ 0x47dce6         continúa
```

### RAMA A — el bit del good NO está seteado en `esi` (0x47dce6)

Aquí `esi` todavía no tiene ese good "activo" en su bitflag; hay que activarlo y calcular su índice real dentro del vector de stockpile.

```text
                      RAMA A (0x47dce6)
                              │
                              ▼
                EDX = [esi+0x4c]        ; stockpile_vector_end (o similar)
                              │
                              ▼
                EDX = EDX - [esi+0x48]  ; end - begin
                              │
                              ▼
                EDI = &[esi+0x48]       ; dirección del begin (puntero)
                              │
                              ▼
                EDX = EDX >> 3          ; SAR 3  → divide entre 8
                                         ; (cada entrada del stockpile
                                         ;  ocupa 8 bytes: 2×int32)
                              │
                              ▼
        [ebx + esi*1 + 0x08] = DL
        ; esi.good_bit_flags[ebx] = nuevo índice
        ; (activa el bit / guarda la posición asignada)
                              │
                              ▼
                EAX = zero_extend(CL)   ; índice del good en artisan/factory
                              │
                              ▼
                ECX = [ebp+0x08]        ; artisan/factory
                EDX = [ECX+0x48]        ; artisan/factory.stockpile_vector_begin
                              │
                              ▼
                ECX = [EDX + EAX*8]        ; parte baja  (int64 low)
                EDX = [EDX + EAX*8 + 0x04] ; parte alta  (int64 high)
                              │
                              ▼
                NEG ECX
                ADC EDX,0x00
                NEG EDX
                ; ---------------------------------------------
                ; NEG ECX / ADC EDX,0 / NEG EDX
                ; = negación de un entero de 64 bits (ECX:EDX)
                ; equivalente a:  valor64 = -valor64
                ; ---------------------------------------------
                              │
                              ▼
                EAX = &[ebp-0x14]
                [ebp-0x14] = ECX   ; low
                [ebp-0x10] = EDX   ; high
                              │
                              ▼
                CALL vector_push_back_edi
                ; inserta el valor NEGADO (−cantidad del good
                ; en artisan/factory) como nueva entrada en el
                ; stockpile vector de esi
                              │
                              ▼
                        (continúa el loop)
                        → 0x47dd1b
```

### RAMA B — el bit del good SÍ está seteado en `esi` (continúa desde 0x47dcc9)

Aquí `esi` ya tiene una entrada existente para ese good; simplemente se resta directo (int64) sobre la entrada ya existente.

```text
                      RAMA B (continúa)
                              │
                              ▼
                EDX = [esi+0x48]        ; esi.stockpile_vector_begin
                              │
                              ▼
                EAX = zero_extend(AL)   ; índice existente en esi
                              │
                              ▼
                EAX = &[EDX + EAX*8]
                ; EAX = dirección de la entrada (int64) del good
                ; DENTRO del stockpile de esi
                              │
                              ▼
                EDX = zero_extend(CL)   ; índice del good en artisan/factory
                              │
                              ▼
                ECX = [edi+0x48]        ; artisan/factory.stockpile_vector_begin
                              │
                              ▼
                EDI = [ECX + EDX*8]        ; artisan/factory: cantidad (low)
                              │
                              ▼
                [EAX] = [EAX] - EDI
                ; esi.stockpile[good].low -= artisan/factory.stockpile[good].low
                              │
                              ▼
                ECX = [ECX + EDX*8 + 0x04]  ; artisan/factory: cantidad (high)
                              │
                              ▼
                [EAX+0x04] = [EAX+0x04] - ECX (con SBB, propaga el borrow)
                ; esi.stockpile[good].high -= artisan/factory.stockpile[good].high
                              │
                              ▼
                    JMP 0x47dd1b (continúa el loop)
```

### CIERRE DEL LOOP Y EPÍLOGO

```text
                      0x47dd1b
                              │
                              ▼
                        INC EBX   ; siguiente good
                              │
                              ▼
                CMP EBX, [ebp-0x08]   ; ebx < number_of_goods ?
                              │
                     ┌────────┴────────┐
                     │                 │
                    JL                no
                (vuelve al loop     │
                 en 0x47dcb6)       ▼
                                (fin del loop)
                                    │
                                    ▼
                              0x47dd21
                                    │
                                    ▼
                              POP EDI
                              EAX = ESI   ; retorna esi (puntero)
                              POP EBX
                              MOV ESP,EBP
                              POP EBP
                              RET 0x04
```

### Resumen conceptual

```text
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   RESUMEN — QUÉ HACE                                          │
├──────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                                │
│  Por cada good (índice 0..number_of_goods-1):                                                │
│                                                                                                │
│    1) Si el artisan/factory NO tiene ese good (bitflag=0) → lo salta.                        │
│                                                                                                │
│    2) Si el artisan/factory SÍ tiene el good:                                                │
│         a) Si esi (destino) NO tenía entrada para ese good todavía:                          │
│              - calcula el índice libre (según el tamaño actual del vector)                   │
│              - marca el bitflag de esi con ese índice                                        │
│              - inserta en el vector de esi la cantidad NEGADA                                │
│                (int64) del good tomada del artisan/factory                                   │
│                                                                                                │
│         b) Si esi (destino) YA tenía entrada para ese good:                                  │
│              - resta directamente (int64, low+high con SBB) la cantidad                      │
│                del artisan/factory a la entrada existente de esi                              │
│                                                                                                │
│  Resultado neto: esi.stockpile[good] -= artisan/factory.stockpile[good]                      │
│  (ya sea creando la entrada con el valor negativo, o restando sobre la existente)             │
│                                                                                                │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Puntos clave / hallazgos

```text
┌────────────────────────────┬───────────────────────────────────────────────────────────────┐
│ Elemento                    │ Significado                                                   │
├────────────────────────────┼───────────────────────────────────────────────────────────────┤
│ [0x12587f4]                 │ number_of_goods — cantidad total de bienes (global)           │
│ [edi/esi + idx + 0x08]      │ bitflag por good: ¿está presente/activo ese good?             │
│                              │ (0 = ausente, !=0 → además funciona como índice al asignarse) │
│ [entidad + 0x48]            │ stockpile_vector_begin — inicio del vector de stockpile        │
│ [entidad + 0x4c]            │ stockpile_vector_end — fin del vector de stockpile             │
│ (end - begin) >> 3          │ cantidad de entradas ya usadas (cada entrada = 8 bytes = int64)│
│ entrada de stockpile        │ es un entero de 64 bits (2×int32: low/high) por good           │
│ NEG ECX / ADC EDX,0 / NEG EDX│ negación de un entero de 64 bits completo                     │
│ vector_push_back_edi        │ agrega una nueva entrada de 8 bytes (int64) al vector de esi   │
│ SUB + SBB                   │ resta de 64 bits con propagación de acarreo (borrow)           │
└────────────────────────────┴───────────────────────────────────────────────────────────────┘
```

**Conclusión:** esta función confirma que los bienes (goods) de un artisan/factory se representan mediante **bitflags posicionales** dentro de la estructura base (offset `+0x08` en adelante, uno por good), y que el stockpile real (las cantidades) vive en un **vector de enteros de 64 bits** apuntado desde `+0x48` (begin) y `+0x4c` (end). El índice dentro de ese vector no es necesariamente el mismo `idx` del bitflag: se recalcula dinámicamente según cuántas entradas ya existen, y ese índice recalculado se vuelve a guardar en el propio byte del bitflag (reutilizando el mismo byte para dos propósitos: "¿está presente?" y "¿en qué posición del vector está?").

---

