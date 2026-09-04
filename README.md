# VICTORIA II — REVERSE ENGINEERING DOCUMENTATION
Consolidated document with all system maps collected so far.


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

Each entry occupies 4 bytes.

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
                         ┌───────────┴───────────┐
                         │                       │
                         ▼                       ▼
                      B28=0..2                B28=3..4
                      0.03f                   0.04f/0.06f
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

## MAP 1C — UPDATE TIME THROTTLE FORMULA

Relevant sequence:

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

`DOUBLE_00E45580 = 1.0`

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

# MAP 2 — SECOND SYSTEM: FUN_00682BD0

```text
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│                    FUN_00682BD0 — PROCESS GAME TIME ADVANCE                                  │
└──────────────────────────────────────────────────────────────────────────────────────────────┘

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
├── 4. Builds temporal table
│      │
│      ├── B28=0 → 4.0f
│      ├── B28=1 → 2.0f
│      ├── B28=2 → 1.0f
│      ├── B28=3 → 0.5f
│      └── B28=4 → 0.0004f
│
├── 5. Selects TABLE[B28]
│
├── 6. Compares [ESI+0xB14]
│      against selected value
│
├── 7. Continues temporal processing
│
├── 8. Processes calendar/date logic
│
└── 9. Modifies DAT_012588F0
```

## MAP 2A — TABLE CONSTRUCTION

```text
00682C1F
MOVSS XMM0,[DAT_00F17B58]
→ [EBP-0x24] = 4.0f

00682C32
MOVSS XMM0,[DAT_00F17B54]
→ [EBP-0x20] = 2.0f

00682C3F
MOVSS XMM0,[DAT_00F092FC]
→ [EBP-0x1C] = 1.0f

00682C4C
MOVSS XMM0,[DAT_00F17898]
→ [EBP-0x18] = 0.5f

00682C59
MOVSS XMM0,[DAT_00E45BB8]
→ [EBP-0x14] = 0.0004f
```

## MAP 2B — EXACT TABLE ORDER

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

IEEE-754:

```text
4.0f      = 00 00 80 40
2.0f      = 00 00 00 40
1.0f      = 00 00 80 3F
0.5f      = 00 00 00 3F
0.0004f   = 17 B7 D1 38
```

## MAP 2D — ACCUMULATOR COMPARISON

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

# MAP 3 — TEMPORAL PROCESSING BARRIERS

## BARRIER 1 — [ESI+0xB20]

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

## BARRIER 2 — [ESI+0xBB8]

Vanilla:

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

Experimental patch:

```text
90 90 90 90 90 90
```

This was experimentally confirmed as a real processing barrier.

The NOP patch is **not vanilla**.

---

# MAP 4 — TEMPORAL GLOBAL STATES

`FUN_00682BD0` modifies:

```text
DAT_012588E6
DAT_012588EC
DAT_012588F0
```

Relationship:

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

## MAP 4A — DAT_012588F0

Observed operations include:

```text
DAT_012588F0 × 0.95
DAT_012588F0 × 0.9
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

This is an important connection between the two temporal systems.

---

# MAP 5 — DAT_00E45BB8

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

```text
CHANGING DAT_00E45BB8
        ≠
CHANGING ONLY GAME SPEED
```

It has multiple XREFs.

---

# MAP 6 — DAT_00F092FC

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

It also appears in:

```text
FUN_00475150
```

with:

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

---

# MAP 7 — SPEED DISPLAY / UI

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

# MAP 8 — RELATIONSHIP BETWEEN THE TWO TABLES

```text
                         B28 = 0..4
                              │
                ┌─────────────┴─────────────┐
                │                           │
                ▼                           ▼
        TABLE 1 — THROTTLE          TABLE 2 — TEMPORAL
        DAT_00F0956C                FUN_00682BD0
                │                           │
       0.03/0.03/0.03/0.04/0.06     4.0/2.0/1.0/0.5/0.0004
                │                           │
                └─────────────┬─────────────┘
                              │
                              ▼
                        TEMPORAL SYSTEM
```

The tables do not contain the same values and do not perform exactly the same function.

They directly share:

```text
B28
```

---

# MAP 9 — COMPLETE B28 MAPPING

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

---

# MAP 10 — COMPLETE SYSTEM FLOW

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
             │                     │                   ▼
             │                     │             B14 ACCUMULATOR
             │                     │                   │
             │                     │                   ▼
             │                     │              B20 / BB8
             │                     │                   │
             │                     │                   ▼
             │                     │            TEMPORAL LOGIC
             │                     │                   │
             │                     │                   ▼
             │                     │            DAT_012588F0
             │                     │                   │
             │                     ▼                   │
             │               DAT_00F0956C              │
             │                     │                   │
             │                     ▼                   │
             │               0.03/0.04/0.06           │
             │                     │                   │
             │                     ▼                   │
             │              × DAT_013F2AE8             │
             │                     │                   │
             │                     ▼                   │
             │          × (DAT_012588F0 + 1)           │
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

# MAP 11 — IMPORTANT MODDING POINTS

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
│ [ESI+0xB14]        │ Temporal accumulator                      │
│ [ESI+0xB20]        │ State that can stop the function          │
│ [ESI+0xBB8]        │ Temporal condition/barrier                │
│ 009DF2B0           │ ProcessMessagePumpAndUpdate               │
└────────────────────┴───────────────────────────────────────────┘
```

# MAP 12 — CONCLUSION

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

The current conclusion is that B28 is the central speed index, while Victoria II uses two different tables to control different aspects of temporal processing.

Experimental modifications such as:

```text
4.0f via code cave
5.0f tests involving DAT_00F092FC
0.000001f in DAT_00E45BB8
NOPs at 00682D0C
```

must be considered experimental patches, not vanilla behavior.


# PART II — GENERAL ENGINE STRUCTURE, ECONOMY, CONSOLE AND FOG OF WAR

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
    |     +-- console_commands (00420eb0)
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

`console_commands` was formerly identified as `FUN_00420EB0`.

It receives tokenized console input and performs a comparison cascade through command strings.

Empirical result:

```text
DISABLE console_commands
        ↓
ALL CONSOLE COMMANDS DISAPPEAR
```

The `"fow"` command was confirmed to toggle:

```text
DAT_013f080c
```

and mirror the value into:

```text
[DAT_01258a74 + 0x6bc44]
```

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


# PART III — RANDOM NUMBER GENERATOR (RNG) SYSTEM

```text
                         v2game.exe+0xb0ecf0
                       RANDOM NUMBER LIST
                                  │
                                  ▼
                         v2game.exe+0xb0f6b0
                        CURRENT LIST INDEX
                                  │
                                  ▼
                          fun_009b7610
                    FUNCTION THAT POLLS A NUMBER
                                  │
                    ┌─────────────┴─────────────┐
                    │                           │
                    ▼                           ▼
             INDEX + 1                   LIST EXHAUSTED?
                    │                           │
                    ▼                           ▼
          RETURNS NUMBER                 fun_009b7700
                                          │
                                          ▼
                                  GENERATES NEW LIST
                                  USING MERSENNE TWISTER
```

The list state uses:

```text
v2game.exe+0xb0ecf0
```

Current index:

```text
v2game.exe+0xb0f6b0
```

`fun_009b7610` polls the next number.

When exhausted, `fun_009b7700` regenerates the list.

The regeneration uses the Mersenne Twister / MT19937 family.


# PART IV — BUTTON CALLBACKS

| Function | Role | Status |
|---|---|---|
| `FUN_006dfe80` | Callback when Westernize button is pressed | Confirmed |
| `FUN_00541b90` | Condition for Westernize button clickability | Confirmed |
| `FUN_00772300` | Play button callback | Likely |
| Other button functions | Previously identified | Pending recovery |

The exact SP/MP Play callback distinction remains unresolved.


# PART V — ARTISAN / FACTORY STOCKPILE SUBTRACTION

## MAP 13 — `SubtractArtisanFactoryStockpileFromESIStockpile` — 0x0047DCA0

This function provides important evidence about how goods and stockpiles are represented.

```text
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│         SubtractArtisanFactoryStockpileFromESIStockpile  (0x0047dca0)                        │
└──────────────────────────────────────────────────────────────────────────────────────────────┘

For each good:

artisan/factory.good_bit_flags[idx]
                │
                ▼
          Is good present?
                │
          ┌─────┴─────┐
          │           │
         NO          YES
          │           │
          ▼           ▼
        SKIP    Check destination ESI
                         │
                  ┌──────┴──────┐
                  │             │
              absent          present
                  │             │
                  ▼             ▼
           create entry    subtract int64
           with -amount    directly
```

Important fields:

```text
[0x12587f4]
    number_of_goods

[entity + 0x08 + idx]
    good bitflag / positional index

[entity + 0x48]
    stockpile vector begin

[entity + 0x4C]
    stockpile vector end
```

Stockpile entries are:

```text
8 bytes
=
64-bit integer
=
2 × int32
```

The vector size is obtained through:

```text
(end - begin) >> 3
```

When the destination has no entry:

```text
artisan/factory amount
        ↓
NEG 64-bit value
        ↓
push_back into ESI stockpile vector
```

When the destination already has an entry:

```text
ESI stockpile
        -
artisan/factory stockpile
        ↓
64-bit SUB + SBB
```

Therefore the conceptual result is:

```text
ESI.stockpile[good]
    -=
artisan/factory.stockpile[good]
```

### Important finding

The byte at:

```text
entity + 0x08 + good_index
```

acts as a presence/index structure.

The actual amount is stored in the stockpile vector at:

```text
entity + 0x48
```

with 8-byte entries.

This is important for understanding the goods representation used by the market system.


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


# PART VII — GAME LOAD / INITIALIZATION SYSTEM

## MAP 32 — `FUN_00662010`

Proposed name:

```text
Game_FinalizeLoadAndEnterGameplay
```

Current conclusion:

```text
ONE-TIME LOAD FINALIZATION / GAMEPLAY INITIALIZATION
```

This function appears to execute after loading/initialization and before the game enters normal gameplay.

It should not be confused with the recurring economic tick.


# MAP 33 — LOAD STATE

At entry:

```asm
MOV dword ptr [EBX + 0x1E08],0x3
```

Working interpretation:

```text
EBX + 0x1E08
    ↓
load / initialization phase
```

Proposed name:

```text
m_LoadPhase
```

The exact enumeration values remain unconfirmed.


# MAP 34 — DISPLAY / RESOLUTION INITIALIZATION

The function reads resolution-related fields from objects around:

```text
ESI + 0x64
ESI + 0x68
```

and stores values into:

```text
EBX + 0x1E10
EBX + 0x1E14
EBX + 0x1E18
```

Working names:

```text
EBX + 0x1E10 → m_ScreenWidth
EBX + 0x1E14 → m_ScreenHeight
EBX + 0x1E18 → m_AspectRatioScaled
```

If the expected resolution objects are unavailable, the function falls back to reading configuration data from a stream.


# MAP 35 — INPUT / EVENT BINDING INITIALIZATION

The function repeatedly calls:

```text
ResolveOrRegisterEvent
```

using different string keys.

This appears to resolve/register configurable input or event bindings.

The exact event/key names are still being reconstructed.


# MAP 36 — ENTITY STATE RESET

The function iterates over entities/buildings and clears a state field:

```asm
*(EDI + 0x0C) = 0
```

Conceptually:

```text
FOR EACH ENTITY
    |
    ▼
RESET RUNTIME FLAG
```

This is consistent with restoring/rebuilding runtime state after loading.


# MAP 37 — SUBSYSTEM INITIALIZATION CHAIN

A long sequence of initialization calls is performed on the same primary object.

Observed functions:

```text
FUN_00521560
FUN_0050E540
FUN_005068F0
FUN_00521FD0
FUN_0050EA30
FUN_00530E40
FUN_0052FCD0
FUN_0051C890
FUN_005143B0
FUN_00517AF0
FUN_0051EB40
```

These should currently be treated as:

```text
SUBSYSTEM INITIALIZATION CHAIN
```

Their exact individual roles remain to be mapped.


# MAP 38 — ENTITY ID / INTEGRITY REPAIR

The function checks an entity field around:

```text
+0x34
```

and can assign a new value if it is zero.

The resulting value is limited to:

```text
0x186A0
```

which equals:

```text
100000
```

Conceptually:

```text
ENTITY ID
   │
   ├── already valid → keep
   │
   └── zero → assign new value
                 │
                 ▼
              clamp
              100000
```

This appears to be a post-load integrity/reconstruction mechanism.


# MAP 39 — CONFIGURATION CACHE

The final large block repeatedly constructs string keys and performs lookups.

The resulting configuration objects are cached into fields of the main object.

Observed destination offsets include examples such as:

```text
EBX + 0x11C8
EBX + 0x1268
EBX + 0x12B8
EBX + 0x1308
...
```

Conceptually:

```text
STRING KEY
    │
    ▼
CONFIG LOOKUP
    │
    ▼
CONFIG OBJECT
    │
    ▼
CACHE POINTER IN EBX
```

This is likely intended to avoid repeated string-based lookups during runtime.


# MAP 40 — GAMEPLAY TOGGLE SYNCHRONIZATION

The function reads a bitfield around:

```text
EBX + 0x7E0
```

and uses the result to select/configure different settings.

Several adjacent offsets are involved:

```text
+0x4
+0x8
+0xC
+0x10
+0x14
...
```

Working name:

```text
m_GameplayToggleFlags
```

These flags are synchronized with configuration objects.

Exact semantic names for each bit remain pending.


# MAP 41 — LARGE UI / OVERLAY OBJECT

The function allocates an object of approximately:

```text
0x3C0 bytes
```

and initializes it using configuration state.

A field around:

```text
+0x3B8
```

is read as a boolean/toggle.

Working hypothesis:

```text
minimap / overlay / camera-related controller
```

This remains unconfirmed.


# MAP 42 — SPATIAL GRID REGISTRATION

When not running in the relevant headless mode, entities are registered into a spatial structure.

Important state:

```text
DAT_012588E8 + 0xD11
```

If the relevant mode is inactive:

```text
for each entity
    |
    +-- entity->0x1D0 = EBX
    |
    +-- FUN_00407B10
    |
    +-- FUN_0068F390
```

`FUN_0068F390` is particularly interesting because it was also encountered in previous economic/entity processing.

Working interpretation:

```text
ENTITY
   ↓
SPATIAL / BUCKET REGISTRATION
   ↓
SIMULATION / RENDERING GRID
```


# MAP 43 — LOAD TIME MEASUREMENT

The function performs timestamp subtraction:

```text
FLD
FSUB
```

and writes the resulting value into a stream/log.

This is consistent with:

```text
LOAD TIME
```

measurement.


# MAP 44 — ENTER GAMEPLAY

Near the end:

```text
FUN_006480A0(EBX)
FUN_00648040(EBX,0xB,-1)
```

A state transition to:

```text
0xB
```

occurs.

Working interpretation:

```text
LOAD / INITIALIZATION
        ↓
STATE = 0xB
        ↓
GAMEPLAY
```

Exact state enum name remains unconfirmed.


# MAP 45 — SUBSYSTEM START CALLBACKS

A final loop processes approximately 32 callback slots:

```text
for ESI = 0; ESI < 0x20; ESI += 4
```

Each registered subsystem is accessed through:

```text
EBX + 0xD80 + ESI
```

and invokes a virtual callback around:

```text
vtable + 0x24
```

Conceptually:

```text
GAME ENTERING GAMEPLAY
        │
        ▼
32 SUBSYSTEM SLOTS
        │
        ├── callback
        ├── callback
        ├── callback
        ├── ...
        └── callback
```

This resembles an:

```text
OnGameStarted
OnLevelLoaded
```

broadcast mechanism, but the exact event name remains unconfirmed.


# PART VIII — RENAMED UTILITY / HELPER FUNCTIONS

```text
FUN_0043AB60
    Memory_CopyOverlapping
    → zero_struct_array
    → appears specific to int64 arrays

FUN_00AAD56B
    Memory_ValidateSize
    → possible operator new / allocation helper

FUN_0041A160
    Struct_InitWithDefaults
    → ctor_with_MTTH
    → probably event constructor

FUN_0096BBF0
    Singleton_Construct
    → create_string_with_length("null_pop",8)
    → vtable.CAddAIStrategyEffect.138
    → possibly country AI related

thunk_FUN_00AB4D81
    Stream_CheckState
    → __ptmbcinfo
    → checks MBCS/local code page

FUN_0047DB00
    Buffer_CopyAndResize
    → CGoodsPool_copy_ctor

fcn.004F50C0
    factory_decay_without_inputs
    → factory level decay when inputs are missing
```


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

ESPAÑOL: 

# VICTORIA II — DOCUMENTACIÓN DE INGENIERÍA INVERSA

Documento consolidado con todos los mapas de sistemas recopilados hasta el momento.


# PARTE I — SISTEMA DE VELOCIDAD DEL JUEGO

## MAPA 1 — SISTEMA DE VELOCIDAD DEL JUEGO (VISIÓN GENERAL)

```text
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│                         VICTORIA II — SISTEMA DE VELOCIDAD DEL JUEGO                         │
└──────────────────────────────────────────────────────────────────────────────────────────────┘


                                  COMANDOS DE VELOCIDAD
                                            │
                         ┌──────────────────┼──────────────────┐
                         │                  │                  │
                         ▼                  ▼                  ▼
                  0072EE90            0072EFE0            0064E608
               Aumentar velocidad   Disminuir velocidad   gamespeed_max
                         │                  │                  │
                         └──────────────┬───┘                  │
                                        ▼
                                  B28 = B28 ± 1
                                  Límite: 0..4
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
                  VELOCIDAD_MÍNIMA  VELOCIDAD_LENTA  VELOCIDAD_NORMAL
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
                    VELOCIDAD_RÁPIDA             VELOCIDAD_MÁXIMA
                         │                             │
                         ▼                             ▼
                     00F09578                     00F0957C
                       0.04f                         0.06f
                         │                             │
                         └──────────────┬──────────────┘
                                        │
                                        ▼
                         ┌─────────────────────────────┐
                         │  CONTROL DEL TIEMPO DE     │
                         │       ACTUALIZACIÓN        │
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
                         SELECCIONAR FLOAT DE CONTROL
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
                              UMBRAL TEMPORAL
                                        │
                                        ▼
                              COMPARACIÓN TEMPORAL
                                        │
                         ┌──────────────┴──────────────┐
                         │                             │
                         ▼                             ▼
                    NO ALCANZADO                    ALCANZADO
                         │                             │
                         ▼                             ▼
                       RET                 CALL vtable + 0x100
                                                        │
                                                        ▼
                                      ProcesarMensajesYActualizar
                                             009DF2B0
                                                        │
                                                        ▼
                                               CICLO DE ACTUALIZACIÓN


                         ╔══════════════════════════════════╗
                         ║      SEGUNDO USO DE B28          ║
                         ╚════════════════╦═════════════════╝
                                          │
                                          ▼
                                     FUN_00682BD0
                              ProcesarAvanceTiempoJuego
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
                            TABLA COMPLETA DE LA VERSIÓN VANILLA
                                          │
                                          ▼
                         4.0 / 2.0 / 1.0 / 0.5 / 0.0004
```

## MAPA 1A — TABLA VANILLA DEL CONTROL DEL TIEMPO DE ACTUALIZACIÓN

La primera tabla comienza en:

```text
DAT_00F0956C
```

Se accede mediante:

```asm
MOV EAX,[EDI+0xB28]
MOVSS XMM0,[EAX*4 + DAT_00F0956C]
```

Esto significa:

```text
B28 = índice de la tabla
```

Cada entrada ocupa 4 bytes.

### Tabla completa

```text
┌─────┬────────────┬────────────────┬──────────────────┐
│ B28 │ Dirección  │ Valor Vanilla  │ Velocidad UI     │
├─────┼────────────┼────────────────┼──────────────────┤
│  0  │ 00F0956C   │ 0.03f          │ MÍNIMA           │
│  1  │ 00F09570   │ 0.03f          │ LENTA            │
│  2  │ 00F09574   │ 0.03f          │ NORMAL           │
│  3  │ 00F09578   │ 0.04f          │ RÁPIDA           │
│  4  │ 00F0957C   │ 0.06f          │ MÁXIMA           │
└─────┴────────────┴────────────────┴──────────────────┘
```

### Bytes vanilla

```text
0.03f = 8F C2 F5 3C
0.04f = 0A D7 23 3D
0.06f = 8F C2 75 3D
```

Distribución en memoria:

```text
00F0956C → 8F C2 F5 3C
00F09570 → 8F C2 F5 3C
00F09574 → 8F C2 F5 3C
00F09578 → 0A D7 23 3D
00F0957C → 8F C2 75 3D
```

## MAPA 1B — CONTROL DEL TIEMPO DE ACTUALIZACIÓN

```text
                         CONTROL DEL TIEMPO DE ACTUALIZACIÓN
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
                              ┌────────────┴────────────┐
                              │                         │
                              ▼                         ▼
                           B28=0..2                  B28=3..4
                           0.03f                    0.04f/0.06f
                              │                         │
                              └────────────┬────────────┘
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
                                    UMBRAL TEMPORAL
                                           │
                                           ▼
                                  COMPARACIÓN TEMPORAL
                                           │
                            ┌──────────────┴──────────────┐
                            │                             │
                            ▼                             ▼
                       NO ALCANZADO                    ALCANZADO
                            │                             │
                            ▼                             ▼
                           RET                     vtable + 0x100
                                                          │
                                                          ▼
                                      ProcesarMensajesYActualizar
                                               009DF2B0
                                                          │
                                                          ▼
                                             ACTUALIZACIÓN DEL JUEGO
```

## MAPA 1C — FÓRMULA DEL CONTROL DEL TIEMPO DE ACTUALIZACIÓN

Secuencia relevante:

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

`DOUBLE_00E45580 = 1.0`

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
UMBRAL TEMPORAL
```


# MAPA 2 — SEGUNDO SISTEMA: FUN_00682BD0

```text
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│                 FUN_00682BD0 — PROCESAR AVANCE DEL TIEMPO DEL JUEGO                         │
└──────────────────────────────────────────────────────────────────────────────────────────────┘

FUN_00682BD0
│
├── 1. Acumula tiempo
│      │
│      └── [ESI+0xB14] += XMM0
│
├── 2. Comprueba [ESI+0xB20]
│      │
│      └── si != 0 → RETORNO
│
├── 3. Lee B28
│      │
│      └── MOV EAX,[ESI+0xB28]
│
├── 4. Construye tabla temporal
│      │
│      ├── B28=0 → 4.0f
│      ├── B28=1 → 2.0f
│      ├── B28=2 → 1.0f
│      ├── B28=3 → 0.5f
│      └── B28=4 → 0.0004f
│
├── 5. Selecciona TABLA[B28]
│
├── 6. Compara [ESI+0xB14]
│      con el valor seleccionado
│
├── 7. Continúa el procesamiento temporal
│
├── 8. Procesa lógica de calendario/fecha
│
└── 9. Modifica DAT_012588F0
```

## MAPA 2A — CONSTRUCCIÓN DE LA TABLA

```text
00682C1F
MOVSS XMM0,[DAT_00F17B58]
→ [EBP-0x24] = 4.0f

00682C32
MOVSS XMM0,[DAT_00F17B54]
→ [EBP-0x20] = 2.0f

00682C3F
MOVSS XMM0,[DAT_00F092FC]
→ [EBP-0x1C] = 1.0f

00682C4C
MOVSS XMM0,[DAT_00F17898]
→ [EBP-0x18] = 0.5f

00682C59
MOVSS XMM0,[DAT_00E45BB8]
→ [EBP-0x14] = 0.0004f
```

## MAPA 2B — ORDEN EXACTO DE LA TABLA

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

## MAPA 2C — TABLA VANILLA COMPLETA

```text
┌─────┬────────────┬────────────┬──────────────────────────┐
│ B28 │ LOCAL      │ DAT        │ VALOR VANILLA            │
├─────┼────────────┼────────────┼──────────────────────────┤
│  0  │ EBP-0x24   │ 00F17B58   │ 4.0f                     │
│  1  │ EBP-0x20   │ 00F17B54   │ 2.0f                     │
│  2  │ EBP-0x1C   │ 00F092FC   │ 1.0f                     │
│  3  │ EBP-0x18   │ 00F17898   │ 0.5f                     │
│  4  │ EBP-0x14   │ 00E45BB8   │ 0.0004f                  │
└─────┴────────────┴────────────┴──────────────────────────┘
```

IEEE-754:

```text
4.0f      = 00 00 80 40
2.0f      = 00 00 00 40
1.0f      = 00 00 80 3F
0.5f      = 00 00 00 3F
0.0004f   = 17 B7 D1 38
```

## MAPA 2D — COMPARACIÓN DEL ACUMULADOR

```text
                    [ESI+0xB14]
                          │
                          ▼
                       ACUMULADOR
                          │
                          │ comparar
                          ▼
                       TABLA[B28]
                          │
              ┌───────────┴───────────┐
              │                       │
              ▼                       ▼
          NO ALCANZADO             ALCANZADO
              │                       │
              ▼                       ▼
       continuar / retorno       procesamiento temporal
```


# MAPA 3 — BARRERAS DEL PROCESAMIENTO TEMPORAL

## BARRERA 1 — [ESI+0xB20]

```text
FUN_00682BD0
      │
      ▼
CMP [ESI+0xB20]
      │
      ├── != 0 → RETORNO
      │
      └── == 0 → CONTINUAR
```

## BARRERA 2 — [ESI+0xBB8]

Vanilla:

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

Parche experimental:

```text
90 90 90 90 90 90
```

Esto fue confirmado experimentalmente como una barrera real de procesamiento.

El parche NOP **no forma parte del comportamiento vanilla**.


# MAPA 4 — ESTADOS GLOBALES TEMPORALES

`FUN_00682BD0` modifica:

```text
DAT_012588E6
DAT_012588EC
DAT_012588F0
```

Relación:

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
                    ControlTiempoActualizacion
                              │
                              ▼
                         UMBRAL TEMPORAL
```

## MAPA 4A — DAT_012588F0

Operaciones observadas incluyen:

```text
DAT_012588F0 × 0.95
DAT_012588F0 × 0.9
DAT_012588F0 + 0.5
```

También existe lógica relacionada con diferencias de fechas.

Por lo tanto:

```text
FUN_00682BD0
      │
      ▼
DAT_012588F0
      │
      ▼
ControlTiempoActualizacion
      │
      ▼
UMBRAL
```

Esta es una conexión importante entre ambos sistemas temporales.


# MAPA 5 — DAT_00E45BB8

```text
┌─────────────────────────────────────────────────────────┐
│ DAT_00E45BB8                                            │
├─────────────────────────────────────────────────────────┤
│ Dirección: 00E45BB8                                    │
│ Valor vanilla: 0.0004f                                 │
│ Bytes: 17 B7 D1 38                                      │
│ Uso de velocidad: B28=4                                │
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

```text
CAMBIAR DAT_00E45BB8
        ≠
CAMBIAR SOLAMENTE LA VELOCIDAD DEL JUEGO
```

Tiene múltiples XREFs.


# MAPA 6 — DAT_00F092FC

```text
┌─────────────────────────────────────────────────────────┐
│ DAT_00F092FC                                            │
├─────────────────────────────────────────────────────────┤
│ Dirección: 00F092FC                                    │
│ Valor vanilla: 1.0f                                    │
│ Bytes: 00 00 80 3F                                     │
│ Uso de velocidad: B28=2                                │
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

También aparece en:

```text
FUN_00475150
```

con:

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


# MAPA 7 — VISUALIZACIÓN DE VELOCIDAD / INTERFAZ

```text
                              B28
                               │
                  ┌────────────┴────────────┐
                  │                         │
                  ▼                         ▼
             00715DE5                  0070DFE0
                  │                         │
                  ▼                         ▼
          TABLA DE NOMBRES DE         Leer B28
             VELOCIDAD                    │
                  │                       ▼
     ┌────────────┼────────────┐     ADD EAX,2
     │            │            │            │
     ▼            ▼            ▼            ▼
   B28=0        B28=2        B28=4     [ESP+0x30]
  MÍNIMA        NORMAL       MÁXIMA        │
     │            │            │            ▼
     └────────────┼────────────┘     LÓGICA UI / ESTADO
                  │
                  ▼
       00E11040 → VELOCIDAD_MÍNIMA
       00E11050 → VELOCIDAD_LENTA
       00E1105C → VELOCIDAD_NORMAL
       00E1106C → VELOCIDAD_RÁPIDA
       00E11078 → VELOCIDAD_MÁXIMA
```


# MAPA 8 — RELACIÓN ENTRE LAS DOS TABLAS

```text
                         B28 = 0..4
                              │
                ┌─────────────┴─────────────┐
                │                           │
                ▼                           ▼
        TABLA 1 — CONTROL             TABLA 2 — TEMPORAL
        DAT_00F0956C                   FUN_00682BD0
                │                           │
       0.03/0.03/0.03/0.04/0.06     4.0/2.0/1.0/0.5/0.0004
                │                           │
                └─────────────┬─────────────┘
                              │
                              ▼
                       SISTEMA TEMPORAL
```

Las tablas no contienen los mismos valores y no realizan exactamente la misma función.

Comparten directamente:

```text
B28
```


# MAPA 9 — MAPEO COMPLETO DE B28

```text
┌─────┬──────────────────┬──────────────┬──────────────────────┬──────────────┐
│ B28 │ VELOCIDAD        │ INTERFAZ     │ CONTROL ACTUALIZACIÓN│ TEMPORAL     │
├─────┼──────────────────┼──────────────┼──────────────────────┼──────────────┤
│  0  │ VELOCIDAD_MÍNIMA │ MÍNIMA       │ 0.03f                │ 4.0f         │
│  1  │ VELOCIDAD_LENTA  │ LENTA        │ 0.03f                │ 2.0f         │
│  2  │ VELOCIDAD_NORMAL │ NORMAL       │ 0.03f                │ 1.0f         │
│  3  │ VELOCIDAD_RÁPIDA │ RÁPIDA       │ 0.04f                │ 0.5f         │
│  4  │ VELOCIDAD_MÁXIMA │ MÁXIMA       │ 0.06f                │ 0.0004f      │
└─────┴──────────────────┴──────────────┴──────────────────────┴──────────────┘
```


# MAPA 10 — FLUJO COMPLETO DEL SISTEMA

```text
                         Aumentar / Disminuir Velocidad
                                      │
                                      ▼
                                 B28 = 0..4
                                      │
             ┌────────────────────────┼────────────────────────┐
             │                        │                        │
             ▼                        ▼                        ▼
       VELOCIDAD UI          ControlTiempoActualizacion   FUN_00682BD0
       00715DE5 /                00685620                    │
       0070DFE0                     │                        │
             │                      │                        ▼
             │                      │                MOV EAX,[ESI+0xB28]
             │                      │                        │
             │                      │                        ▼
             │                      │                 TABLA TEMPORAL
             │                      │                        │
             │                      │                        ▼
             │                      │                 ACUMULADOR B14
             │                      │                        │
             │                      │                        ▼
             │                      │                    B20 / BB8
             │                      │                        │
             │                      │                        ▼
             │                      │                 LÓGICA TEMPORAL
             │                      │                        │
             │                      │                        ▼
             │                      │                 DAT_012588F0
             │                      │                        │
             │                      ▼                        │
             │                DAT_00F0956C                    │
             │                      │                         │
             │                      ▼                         │
             │                0.03/0.04/0.06                  │
             │                      │                         │
             │                      ▼                         │
             │               × DAT_013F2AE8                    │
             │                      │                         │
             │                      ▼                         │
             │            × (DAT_012588F0 + 1)                │
             │                      │                         │
             │                      ▼                         │
             │                 UMBRAL TEMPORAL                 │
             │                      │                         │
             │                      ▼                         │
             │              COMPARACIÓN TEMPORAL               │
             │                      │                         │
             │                      ▼                         │
             │       ProcesarMensajesYActualizar ◄────────────┘
             │                  009DF2B0
             │                      │
             └──────────────────────┴─────────────────────────►
                                      ACTUALIZACIÓN DEL JUEGO
```


# MAPA 11 — PUNTOS IMPORTANTES PARA MODDING

```text
┌────────────────────────────────────────────────────────────────┐
│                    PUNTOS DE INTERÉS                            │
├────────────────────┬───────────────────────────────────────────┤
│ 00685620           │ ControlTiempoActualizacion                │
│ 00682BD0           │ ProcesarAvanceTiempoJuego                 │
│ 00F0956C           │ Inicio de tabla de actualización           │
│ 00F0957C           │ Entrada B28=4 → 0.06f                     │
│ 00F17B58           │ Entrada B28=0 → 4.0f                      │
│ 00F17B54           │ Entrada B28=1 → 2.0f                      │
│ 00F092FC           │ Entrada B28=2 → 1.0f                      │
│ 00F17898           │ Entrada B28=3 → 0.5f                      │
│ 00E45BB8           │ Entrada B28=4 → 0.0004f                   │
│ 012588F0           │ Factor temporal compartido                │
│ [ESI+0xB14]        │ Acumulador temporal                        │
│ [ESI+0xB20]        │ Estado que puede detener la función       │
│ [ESI+0xBB8]        │ Condición/barrera temporal                 │
│ 009DF2B0           │ ProcesarMensajesYActualizar                │
└────────────────────┴───────────────────────────────────────────┘
```


# MAPA 12 — CONCLUSIÓN

El sistema de velocidad de Victoria II utiliza:

```text
                         B28 = 0..4
                              │
                ┌─────────────┴─────────────┐
                │                           │
                ▼                           ▼
       CONTROL DEL TIEMPO DE         AVANCE TEMPORAL
          ACTUALIZACIÓN                  00682BD0
             00685620                      │
                │                          │
                ▼                          ▼
       0.03/0.03/0.03/0.04/0.06    4.0/2.0/1.0/0.5/0.0004
                │                          │
                ▼                          ▼
       DAT_013F2AE8                [ESI+0xB14]
                │                          │
                ▼                          ▼
       DAT_012588F0                [ESI+0xB20]
                │                          │
                │                     [ESI+0xBB8]
                │                          │
                └──────────────┬───────────┘
                               │
                               ▼
                         ACTUALIZACIÓN DEL JUEGO
```

La conclusión actual es que **B28 es el índice central de velocidad**, mientras que Victoria II utiliza dos tablas diferentes para controlar distintos aspectos del procesamiento temporal.

Las modificaciones experimentales como:

```text
4.0f mediante code cave
pruebas con 5.0f usando DAT_00F092FC
0.000001f en DAT_00E45BB8
NOPs en 00682D0C
```

deben considerarse **parches experimentales**, no comportamiento vanilla.


# PARTE II — ESTRUCTURA GENERAL DEL MOTOR, ECONOMÍA, CONSOLA Y NIEBLA DE GUERRA

```text
00AB0F91
  ENTRADA
    |
    v
009DF550
  BUCLE PRINCIPAL
    |
    +-- 009796B0
    |     WINMAIN / MOTOR CLAUSEWITZ
    |
    +-- 0068BF00
    |     ECONOMÍA
    |
    +-- IA
    |     |
    |     +-- ComprobarUmbralSimpleIA
    |             |
    |             v
    |         SISTEMA DE EVENTOS
    |           008A67B0
    |
    +-- COMANDOS DE CONSOLA
    |     |
    |     +-- console_commands (00420eb0)
    |
    +-- RENDERIZADO / NIEBLA DE GUERRA
    |     |
    |     +-- FUN_0099da20
    |     +-- FUN_006592f0
    |
    +-- PRÉSTAMOS
    |     |
    |     +-- 00523400
    |
    +-- OTROS SISTEMAS DE TICK
          |
          +-- Actualizaciones de países
          +-- Actualizaciones de POPs
          +-- Actualizaciones de IA
          +-- Actualizaciones económicas
          +-- Actualizaciones de eventos
          +-- Actualizaciones de guerras
          +-- Actualizaciones del mundo
```

## FLUJO ECONÓMICO DETALLADO

```text
0068BF00
  ACTUALIZAR_ECONOMÍA
    |
    v
ACTUALIZAR MERCADO MUNDIAL (00484060)
    |
    v
00482930
  ACTUALIZAR SUMINISTRO
    |
    +-- SUMINISTRO
    +-- DEMANDA
    +-- COMPARACIÓN DE 64 BITS
    +-- DIVIDIR_ENTERO64_CON_SIGNO
    +-- CALCULAR_MULTIPLICADOR_SUMINISTRO
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
```

## FLUJO DE EVENTOS

```text
COMPROBAR_UMBRAL_SIMPLE_IA
    |
    +-- Comprueba condiciones
    +-- Comprueba umbrales
    +-- Realiza llamadas relacionadas con eventos
    |
    v
008A67B0
  SISTEMA DE EVENTOS
```


## SISTEMA_DE_EVENTOS

```text
008A67B0
SISTEMA DE RECURSOS / GESTOR DE EVENTOS
        |
        +-- FUN_008A5AC0
        |     INICIALIZAR GESTOR DE EVENTOS
        |
        +-- FUN_008A5C70
        |     INICIALIZAR ESTRUCTURA DE EVENTO
        |
        +-- FUN_009A1440
        |     INICIALIZAR OBJETO DE EVENTO
        |
        +-- FUN_008A6010
        |     OBTENER NOMBRE DEL EVENTO PRINCIPAL
        |
        +-- FUN_008A60F0
        |     OBTENER NOMBRE DEL EVENTO SECUNDARIO
        |
        +-- FUN_008A67B0
              CARGAR RECURSOS DE EVENTOS
```

## CONSOLA

`console_commands` fue identificado anteriormente como `FUN_00420EB0`.

Recibe la entrada de consola tokenizada y realiza una cascada de comparaciones mediante cadenas de comandos.

Resultado empírico:

```text
DESHABILITAR console_commands
        ↓
DESAPARECEN TODOS LOS COMANDOS DE CONSOLA
```

El comando `"fow"` fue confirmado como responsable de alternar:

```text
DAT_013f080c
```

y reflejar el valor en:

```text
[DAT_01258a74 + 0x6bc44]
```

## NIEBLA DE GUERRA

Estructuras importantes:

```text
DAT_01258a74
    ↓
singleton del dispositivo gráfico/renderizado

DAT_013f080c
    ↓
estado global de la Niebla de Guerra
```

`FUN_0099da20` participa en la inicialización/restauración gráfica.

`FUN_006592f0` se ejecuta en la ruta de renderizado por frame.

Los parches experimentales directos JZ→NOP fueron confirmados como causantes de romper:

```text
FUN_0099da20 → renderizado de texto/UI
FUN_006592f0 → texturas del terreno/mapa
```

Por lo tanto, los parches directos de saltos condicionales **no son parches finales seguros para la Niebla de Guerra**.

La condición anterior alrededor de:

```text
0x6594B4
```

todavía debe comprenderse antes de implementar un parche limpio y permanente para desactivar la Niebla de Guerra.


# PARTE III — SISTEMA DEL GENERADOR DE NÚMEROS ALEATORIOS (RNG)

```text
                         v2game.exe+0xb0ecf0
                       LISTA DE NÚMEROS ALEATORIOS
                                  │
                                  ▼
                         v2game.exe+0xb0f6b0
                        ÍNDICE ACTUAL DE LA LISTA
                                  │
                                  ▼
                          fun_009b7610
                    FUNCIÓN QUE OBTIENE UN NÚMERO
                                  │
                    ┌─────────────┴─────────────┐
                    │                           │
                    ▼                           ▼
             ÍNDICE + 1                   ¿LISTA AGOTADA?
                    │                           │
                    ▼                           ▼
          DEVUELVE EL NÚMERO                fun_009b7700
                                               │
                                               ▼
                                      GENERA UNA NUEVA LISTA
                                      USANDO MERSENNE TWISTER
```

El estado de la lista utiliza:

```text
v2game.exe+0xb0ecf0
```

Índice actual:

```text
v2game.exe+0xb0f6b0
```

`fun_009b7610` obtiene el siguiente número.

Cuando la lista se agota, `fun_009b7700` regenera la lista.

La regeneración utiliza la familia **Mersenne Twister / MT19937**.


# PARTE IV — CALLBACKS DE BOTONES

| Función | Función | Estado |
|---|---|---|
| `FUN_006dfe80` | Callback al pulsar el botón Occidentalizar | Confirmado |
| `FUN_00541b90` | Condición para determinar si el botón Occidentalizar puede pulsarse | Confirmado |
| `FUN_00772300` | Callback del botón Jugar | Probable |
| Otras funciones de botones | Identificadas anteriormente | Pendiente de recuperar |

La distinción exacta entre los callbacks de Jugar SP/MP sigue sin resolverse.


# PARTE V — SUSTRACCIÓN DEL STOCKPILE DE ARTESANOS/FÁBRICAS

## MAPA 13 — `RestarStockpileArtesanoFabricaDelStockpileESI` — 0x0047DCA0

Esta función proporciona evidencia importante sobre cómo están representados los bienes y los stockpiles.

```text
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│       RestarStockpileArtesanoFabricaDelStockpileESI (0x0047dca0)                             │
└──────────────────────────────────────────────────────────────────────────────────────────────┘

Por cada bien:

artisan/factory.good_bit_flags[idx]
                │
                ▼
          ¿Está presente el bien?
                │
          ┌─────┴─────┐
          │           │
         NO          SÍ
          │           │
          ▼           ▼
       OMITIR    Comprobar destino ESI
                         │
                  ┌──────┴──────┐
                  │             │
             ausente          presente
                  │             │
                  ▼             ▼
          crear entrada    restar int64
          con -cantidad    directamente
```

Campos importantes:

```text
[0x12587f4]
    cantidad_de_bienes

[entity + 0x08 + idx]
    bitflag / índice posicional del bien

[entity + 0x48]
    inicio del vector de stockpile

[entity + 0x4C]
    final del vector de stockpile
```

Las entradas del stockpile son:

```text
8 bytes
=
entero de 64 bits
=
2 × int32
```

El tamaño del vector se obtiene mediante:

```text
(end - begin) >> 3
```

Cuando el destino no tiene una entrada:

```text
cantidad del artesano/fábrica
        ↓
NEG valor de 64 bits
        ↓
push_back en el vector de stockpile ESI
```

Cuando el destino ya tiene una entrada:

```text
stockpile ESI
        -
stockpile artesano/fábrica
        ↓
SUB + SBB de 64 bits
```

Por lo tanto, conceptualmente:

```text
ESI.stockpile[bien]
    -=
artesano/fábrica.stockpile[bien]
```

### Hallazgo importante

El byte ubicado en:

```text
entity + 0x08 + índice_del_bien
```

actúa como estructura de presencia/índice.

La cantidad real se almacena en el vector de stockpile en:

```text
entity + 0x48
```

con entradas de 8 bytes.

Esto es importante para comprender la representación de bienes utilizada por el sistema de mercado.


# PARTE VI — SISTEMA DETALLADO DE MERCADO / ECONOMÍA

## MAPA 14 — FLUJO COMPLETO DEL GESTOR ECONÓMICO

El gestor económico es considerablemente más grande que la ruta simple de `ActualizarMercadoMundial`.

Estructura consolidada actual:

```text
0068BF00
ActualizarGestorEconomicoCompleto
   |
   +--> 00520150
   |    CalcularDistribucionEconomica
   |       |
   |       +--> grandes bucles anidados
   |       |
   |       +--> entradas económicas
   |       |
   |       +--> acumuladores compartidos
   |       |
   |       +--> acumuladores por bien
   |
   +--> ReconstruirListasEconomicas (0068d250)
   |
   +--> 00482930
   |    ActualizarSuministro
   |       |
   |       +--> SUMINISTRO
   |       +--> DEMANDA
   |       +--> comparación de 64 bits
   |       +--> DividirEntero64ConSigno
   |       +--> CalcularMultiplicadorSuministro
   |       |
   |       v
   |    00482B...
   |    ActualizarPrecio
   |       |
   |       +--> PRECIO BASE
   |       +--> MULTIPLICADOR
   |       +--> PRECIO MÍNIMO
   |       +--> PRECIO MÁXIMO
   |       +--> PRECIO FINAL
   |
   +--> 004808D0
   |    ProcesarMercadoYDistribucionBienes
   |
   +--> PrepararActualizacionEconomica (0068d950)
   |
   +--> ActualizarEconomia(...,0)
   +--> ActualizarEconomia(...,1)
   +--> ActualizarEconomia(...,2)
   +--> ActualizarEconomia(...,3)
   +--> ActualizarEconomia(...,4)
   |
   +--> ProcesarEntradasEconomicas (0068dc70)
```

El significado semántico exacto de las cinco pasadas de `ActualizarEconomia (00489990)` sigue bajo investigación.

No obstante, el flujo general está claramente centrado en la distribución económica, los cálculos de mercado y el procesamiento económico periódico.


## MAPA 15 — TUBERÍA SUMINISTRO / DEMANDA / PRECIO

La ruta de mercado más importante reconstruida actualmente es:

```text
                    MERCADO
                      │
                      ▼
              00482930
           ActualizarSuministro
                      │
          ┌───────────┴───────────┐
          │                       │
          ▼                       ▼
      SUMINISTRO                DEMANDA
          │                       │
          └───────────┬───────────┘
                      ▼
              COMPARACIÓN DE 64 BITS
                      │
                      ▼
             DividirEntero64ConSigno
                      │
                      ▼
          CalcularMultiplicadorSuministro (00482610)
                      │
                      ▼
                00482B...?
              ActualizarPrecio
                      │
          ┌───────────┴───────────┐
          │                       │
          ▼                       ▼
      PRECIO BASE             MULTIPLICADOR
          │                       │
          └───────────┬───────────┘
                      ▼
                LÍMITES DE PRECIO
                 /        \
                /          \
               ▼            ▼
           MÍNIMO         MÁXIMO
          ×0.2 vanilla    ×5.0 vanilla
               │            │
               └─────┬──────┘
                     ▼
                PRECIO FINAL
```

Este flujo vanilla debería conservarse al modificar el sistema de precios.


## MAPA 16 — LÍMITES DE PRECIO

Vanilla:

```text
PRECIO MÍNIMO
    =
PRECIO BASE × 0.2
```

Dirección:

```text
DAT_00E45C30
```

Máximo:

```text
PRECIO MÁXIMO
    =
PRECIO BASE × 5.0
```

Dirección:

```text
DAT_00E45C28
```

Límites modificados deseados:

```text
MÍNIMO = PRECIO BASE × 0.1
MÁXIMO = PRECIO BASE × 10.0
```

Objetivo:

```text
Suministro
  ↓
Demanda
  ↓
Comparación
  ↓
División de 64 bits
  ↓
Multiplicador de suministro
  ↓
Cálculo de precio
  ↓
NUEVOS LÍMITES
  ↓
Precio final
```

El cálculo vanilla de suministro/demanda **no debe reemplazarse**.

Modificaciones experimentales anteriores que reemplazaron demasiado de la lógica vanilla produjeron comportamientos patológicos como:

```text
suministro > demanda → precio ≈ 0.01
suministro < demanda → precio ≈ 1000
```

Por lo tanto, el enfoque correcto es modificar solamente los límites.


## MAPA 17 — OBJETIVOS DEL PARCHE DE LÍMITES DE PRECIO

La instrucción del límite inferior fue identificada alrededor de:

```text
00482C46
```

con:

```asm
FLD qword ptr [DAT_00E45C30]
```

Parche previsto:

```text
DAT_00E45C30
    0.2
      ↓
    0.1
```

Límite superior:

```text
DAT_00E45C28
    5.0
      ↓
    10.0
```

Estos son los puntos de parche preferidos porque conservan el cálculo anterior de suministro/demanda.


## MAPA 18 — AGREGACIÓN DE DEMANDA DEL MERCADO

### `FUN_00487410`

Nombre propuesto:

```text
ProcesarSuministroYDemandaDelBien
```

Estado:

```text
CONFIRMADO — RUTA DE DEMANDA
```

La función fue inspeccionada detalladamente y se confirmó que modifica la demanda y no el suministro.

Instrucción relevante:

```asm
004877B1
LEA EAX,[EDX+EAX*8]
```

Interpretación:

```text
EDX
 ↓
contenedor real_demand

EAX
 ↓
índice dentro de real_demand
```

Conceptualmente:

```text
BIEN
 │
 ▼
real_demand[bien]
 │
 ▼
AÑADIR DEMANDA REAL
```

Esto es importante porque una función que por nombre parece manejar tanto "suministro como demanda" fue determinada experimentalmente como perteneciente al lado de la demanda en esta ruta.


## MAPA 19 — CONTRIBUCIÓN DEL STOCKPILE A LAS ESTADÍSTICAS DEL MERCADO

Función:

```text
AcumularValorIndexadoBuffer
```

Dirección probable:

```text
0047DC20
```

Instrucciones importantes:

```asm
0047DC56
MOV EDI,[ECX+EDX*8]

0047DC59
ADD [EAX],EDI
```

Interpretación:

```text
ECX + EDX*8
        ↓
cantidad del stockpile

EDI
        ↓
cantidad

[EAX]
        ↓
acumulador global de suministro/demanda
```

Dependiendo del contexto de llamada, `[EAX]` representa el acumulador de mercado correspondiente.

Esto conecta los stockpiles individuales con estadísticas de mercado de mayor nivel.


## MAPA 20 — HELPERS GENÉRICOS DE MERCADO / BUFFER

Varias funciones fueron identificadas durante la investigación del mercado.

### `FUN_0047E3E0`

Nombre propuesto:

```text
Mercado_CalcularProductoPuntoEscalado
```

Uso observado:

```text
~58 lugares
```

Conclusión actual:

```text
Probablemente utilidad matemática genérica.
No confirmado como específico del mercado.
```

### `FUN_0047DE60`

Nombre propuesto:

```text
Buffer_EscalarValoresEnRango
```

Alias:

```text
multiplicar_valores_en_vector
```

Uso observado:

```text
~53 lugares
```

Opera sobre vectores / bloques de memoria contiguos.

Conclusión actual:

```text
Helper genérico de vector/buffer.
```

### `FUN_0043A880`

```text
redimensionar_vector
```

Rutina genérica para redimensionar vectores.

### `0x0047D9E0`

```text
limitar_0_a_arg8h_y_argch
```

Rutina genérica de limitación.

### `FUN_004DD470`

Nombre propuesto:

```text
MultiplicarBienesYLimitar0_99999
```

Constante importante:

```text
0xC34F8000
```

que corresponde a la representación de punto fijo de aproximadamente:

```text
99999
```

Esta función multiplica cantidades relacionadas con bienes y limita el resultado al rango esperado.


## MAPA 21 — ACTUALIZACIÓN ECONÓMICA POR POP

Función:

```text
ActualizarContribucionesEconomicasPOP (00485E40)
```

Nombre propuesto:

```text
ActualizarDineroDiarioPOP
```

Responsabilidades observadas incluyen:

```text
dinero del POP
necesidades del POP
necesidades satisfechas
valores relacionados con banco / ahorros
otros estados económicos diarios
```

Esta función probablemente se encuentra aguas abajo del gestor económico general y representa el procesamiento económico por POP, en lugar del cálculo global del mercado.


## MAPA 22 — DISTRIBUCIÓN ECONÓMICA

### `00520150 — CalcularDistribucionEconomica`

Esta función contiene una estructura de grandes bucles anidados.

Bucle importante:

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

El procesamiento interno puede repetirse:

```text
005208E4
CMP [EBP-0x5C],0

005208E8
JNZ 00520630
```

antes de avanzar la iteración externa.

Avance del bucle externo:

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

Por lo tanto:

```text
índice externo
    ↓
[EBP-0x44] += 0x10
    ↓
procesamiento económico interno
    ↓
acumuladores compartidos
    ↓
siguiente entrada económica
```


## MAPA 23 — ACUMULADORES ECONÓMICOS COMPARTIDOS

El bucle de distribución económica escribe en campos compartidos como:

```text
this + 0x8D8 + i*8
this + 0x900 + i*8
```

utilizando aritmética de 64 bits:

```text
ADD
ADC
```

Otros estados compartidos observados:

```text
this + 0x13E8
this + 0x13EC
```

y:

```text
[EDI+0x274] + 0x28
```

con valores relacionados con:

```text
[EDI+0x58]
```

También existen acumuladores locales de 64 bits:

```text
[EBP-0x34]
[EBP-0x30]
```

Estas observaciones indican que la función no es simplemente una iteración de solo lectura sobre entradas independientes.


## MAPA 24 — MULTIHILO / ADVERTENCIA DE CONDICIÓN DE CARRERA
### (EN DESARROLLO — NO TERMINADO)

El bucle de distribución económica **no es actualmente seguro para una paralelización ingenua**.

Conceptualmente:

```text
CPU0 ──┐
CPU1 ──┤
CPU2 ──┤──► ACUMULADORES COMPARTIDOS
CPU3 ──┘
```

Varias iteraciones pueden modificar los mismos:

```text
this + 0x8D8 + i*8
this + 0x900 + i*8
this + 0x13E8
this + 0x13EC
```

Por lo tanto, un enfoque ingenuo:

```text
un hilo = una iteración externa
```

podría producir condiciones de carrera y totales económicos corruptos.

Arquitectura preferida:

```text
CPU0 → ACUMULADORES PRIVADOS
CPU1 → ACUMULADORES PRIVADOS
CPU2 → ACUMULADORES PRIVADOS
CPU3 → ACUMULADORES PRIVADOS
                │
                ▼
             COMBINAR
                │
                ▼
       ACUMULADORES ESI COMPARTIDOS
```

Los atómicos de grano fino alrededor de cada `ADD/ADC` probablemente serían demasiado costosos para una simulación que se ejecuta continuamente.

Por lo tanto, el primer experimento seguro de multihilo debería ser una prueba inofensiva de worker thread antes de mover el trabajo económico a workers paralelos.


## MAPA 25 — HELPER ECONÓMICO `FUN_00969760`

`FUN_00969760` fue investigada como posible worker/helper económico.

Nombres españoles propuestos:

```text
AcumularDatosEconomicosElemento
```

o:

```text
AcumularDatosEconomicos
```

La función realiza muchas operaciones `+=` sobre el mismo objeto/estado compartido.

Conclusión actual:

```text
NO ES SEGURA para ejecutarse concurrentemente sobre el mismo objeto
sin separar los acumuladores o utilizar sincronización.
```

Esta es otra indicación de que la economía no puede hacerse multihilo simplemente duplicando las llamadas existentes.


## MAPA 26 — SISTEMA DE WORKERS / HILOS
### (EN DESARROLLO — INCOMPLETO)

Se identificó un mecanismo separado de workers dentro del ejecutable.

### `FUN_00A7AED0`

Nombre propuesto:

```text
CrearHiloWorker
```

Utiliza la importación:

```text
CreateThread
```

Dirección de importación:

```text
00C8A1A8
```

Parámetros estándar observados:

```text
lpThreadAttributes = 0
dwStackSize        = 0
lpStartAddress     = FUN_00A7B0C0
lpParameter        = bloque asignado de 8 bytes que contiene this
dwCreationFlags    = 0
lpThreadId         = &ESI+4
```

El HANDLE resultante del hilo se almacena en:

```text
[ESI+0x08]
```

y:

```text
[ESI+0x1C]
```

participa en el estado de prioridad/control del hilo.


### `FUN_00A7B0C0`

Nombre propuesto:

```text
EntradaHiloWorker
```

La función:

```text
1. libera el bloque de parámetros
2. obtiene la vtable del objeto worker
3. llega a la función de despacho del worker
```

Slot virtual importante:

```text
vtable + 0x14
```

Apunta a:

```text
FUN_00A7B090
```


### `FUN_00A7B090`

Esta es la envoltura/despachador del worker.

```asm
00A7B090  PUSH ESI
00A7B091  MOV ESI,ECX
00A7B093  CALL [GetCurrentThreadId]

00A7B099  CMP EAX,[ESI+0x0C]
00A7B09C  JNZ 00A7B0A2

00A7B09E  XOR EAX,EAX
00A7B0A0  POP ESI
00A7A0A1  RET

LAB_00A7B0A2:

00A7B0A2  MOV ECX,[ESI+0x18]
00A7B0A5  MOV EAX,[ECX]
00A7B0A7  MOV EDX,[EAX+0x4]
00A7B0AA  CALL EDX

00A7B0AC  MOV EAX,1
00A7B0B1  POP ESI
00A7B0B2  RET
```

Observación importante:

```text
[ESI+0x18]
       ↓
objeto que contiene otra vtable
       ↓
vtable + 0x04
       ↓
CUERPO REAL DEL WORKER
```

Por lo tanto, `FUN_00A7B090` en sí misma no necesariamente es la función costosa del worker.


### Vtable del worker

En:

```text
00E439F8
```

entradas observadas:

```text
+0x00 → 00A7AED0
+0x04 → 005A9600
+0x08 → 00A7B030
+0x0C → 00A7B040
+0x10 → 00A7B060
+0x14 → 00A7B090
+0x18 → 00A7AE80
```

`FUN_00A7AE80` parece encargarse de limpieza/espera/destrucción.

El cuerpo exacto del worker todavía debe identificarse.


## MAPA 27 — TICK ECONÓMICO PERIÓDICO

### `FUN_006859C0`

Nombre propuesto:

```text
ProcesarTickEconomicoMensual
```

Alternativa:

```text
EjecutarActualizacionPeriodicaEconomicaCiudad
```

La evidencia actual indica fuertemente que esta función es una actualización económica/calendario recurrente y no una rutina de inicialización ejecutada una sola vez.

### Evidencia temporal/calendario

Código observado:

```c
iVar14 = (*(int *)(param_1 + 0xb0c) + -43800000) / 0x18;
```

La función utiliza datos relacionados con el calendario y tablas paralelas:

```text
DAT_00F1027C
DAT_00F10280
```

junto con cálculos de años bisiestos / duración del año.

Esto sugiere fuertemente que la función determina un período del calendario como:

```text
día
mes
estación
```

para el procesamiento económico periódico.

### Evidencia RNG

Estado observado:

```text
DAT_00F0F6B0
```

con:

```text
DAT_00F0F6B0 =
    (DAT_00F0F6B0 + 1) % 0x270
```

y:

```text
0x270 = 624
```

lo que corresponde al tamaño de estado asociado con MT19937.

La función también genera muchos valores temporales en:

```text
auStack_1090
```

Esto sugiere que el procesamiento económico periódico puede utilizar valores pseudoaleatorios para variaciones económicas u otros cálculos relacionados con la simulación.

### Iteración de entradas económicas

La función itera sobre una estructura/lista asociada a:

```text
param_1 + 0xADC
param_1 + 0xAE0
```

y accede a campos alrededor de:

```text
0xE78
0xE7C
0xE80
0xE84
0xE88
```

Se mantienen múltiples acumuladores de 64 bits.

Acumuladores locales observados:

```text
uStack_98
uStack_A8
uStack_60
uStack_58
uStack_50
uStack_68
uStack_B0
```

Esto representa al menos varias categorías económicas independientes.

El significado semántico exacto de todas las categorías todavía no está confirmado.

### Informe económico histórico

La función actualiza:

```text
DAT_00F20BFC
```

y utiliza:

```text
iVar18 = DAT_00F20BFC * 0x70;
```

El stride de `0x70` bytes sugiere fuertemente un registro de informe económico de tamaño fijo.

Área global relevante:

```text
DAT_012624E8
```

con estructuras cercanas alrededor de:

```text
DAT_012624A8
...
DAT_012624F4
```

Hipótesis actual:

```text
g_HistorialInformeEconomico[2]
```

y:

```text
g_SlotInformeEconomicoActivo
```

para:

```text
DAT_00F20BFC
```

Esto parece consistente con un snapshot de historial económico doblemente almacenado / alternado.

### Flujo económico

Conceptualmente:

```text
CALENDARIO / TIEMPO
      │
      ▼
DETERMINAR PERÍODO
      │
      ▼
ITERAR ENTRADAS ECONÓMICAS
      │
      ├── categoría A
      ├── categoría B
      ├── categoría C
      ├── categoría D
      ├── categoría E
      ├── categoría F
      └── categoría G
      │
      ▼
ACUMULACIÓN DE 64 BITS
      │
      ▼
INFORME ECONÓMICO
      │
      ▼
REGISTRO DE 0x70 BYTES
      │
      ▼
BUFFER HISTÓRICO
```

El significado exacto de cada categoría todavía debe establecerse rastreando los campos fuente en los offsets correspondientes.

### Llamadas relacionadas

La función fue observada en el contexto de llamadas como:

```text
ActualizarEconomia (00489990)
ReconstruirListasEconomicas (0068d250)
ControlTiempoActualizacion (00685620)
```

Esto refuerza la conclusión de que pertenece a la capa de actualización económica/periódica de la simulación.

### Conclusión actual

`FUN_006859C0` debe tratarse actualmente como:

```text
ACTUALIZACIÓN ECONÓMICA / DE CALENDARIO PERIÓDICA
```

con el nombre de trabajo:

```text
ProcesarTickEconomicoMensual
```

La palabra "mensual" sigue siendo una hipótesis de trabajo hasta confirmar completamente las transiciones del calendario.


# MAPA 28 — ESTRUCTURA DEL INFORME ECONÓMICO

Hipótesis actual:

```text
DAT_012624E8
       │
       ▼
HISTORIAL DE INFORMES ECONÓMICOS
       │
       ├── SLOT 0
       │
       └── SLOT 1
```

Cada registro parece ocupar:

```text
0x70 bytes
```

El slot activo está controlado por:

```text
DAT_00F20BFC
```

y el offset seleccionado:

```text
DAT_00F20BFC * 0x70
```

Interpretación potencial:

```text
InformeEconomico
{
    categoria_0;
    categoria_1;
    categoria_2;
    categoria_3;
    categoria_4;
    categoria_5;
    categoria_6;
    ...
}
```

El significado exacto de los campos sigue pendiente.

Importante:

```text
LOS NOMBRES DE LAS CATEGORÍAS TODAVÍA NO ESTÁN CONFIRMADOS
```

No deberían etiquetarse prematuramente como impuestos, salarios, comercio, intereses, etc., hasta rastrear los campos fuente y sus consumidores.


# MAPA 29 — TICK ECONÓMICO PERIÓDICO VS MERCADO MUNDIAL

La investigación actual distingue al menos dos capas económicas:

```text
                 SISTEMA ECONÓMICO
                       │
          ┌────────────┴────────────┐
          │                         │
          ▼                         ▼
TICK ECONÓMICO PERIÓDICO      MERCADO MUNDIAL
       006859C0                   00482930
          │                         │
          ▼                         ▼
calendario / contabilidad    suministro / demanda
          │                         │
          ▼                         ▼
informe económico            multiplicador
          │                         │
          ▼                         ▼
datos históricos             precio
```

Están relacionados, pero no deberían tratarse como la misma función.

La ruta de precio del mercado es específicamente:

```text
00482930 → 00482B...
```

mientras que la ruta de contabilidad económica periódica está centrada alrededor de:

```text
006859C0
```


# MAPA 30 — SISTEMA DE PRÉSTAMOS / INTERESES

Función:

```text
00523400
```

Nombre propuesto:

```text
CalcularInteresPrestamo
```

Responsabilidades:

```text
cálculo del interés del préstamo
interés base
interés mínimo
```

El interés base vanilla está asociado con:

```text
LOAN_BASE_INTEREST
```

Una sección previamente identificada corresponde a la lógica del interés mínimo / 1%.

Los cambios experimentales del interés base deben tratarse separadamente del sistema de precios del mercado.


# MAPA 31 — ÍNDICE DE FUNCIONES DEL MERCADO / ECONOMÍA

```text
┌────────────┬───────────────────────────────────────────────────┐
│ Dirección  │ Función / Rol                                    │
├────────────┼───────────────────────────────────────────────────┤
│ 0068BF00   │ ActualizarGestorEconomicoCompleto                │
│ 00520150   │ CalcularDistribucionEconomica                    │
│ 006859C0   │ ProcesarTickEconomicoMensual                     │
│ 004808D0   │ ProcesarMercadoYDistribucionBienes               │
│ 00482930   │ ActualizarSuministro                             │
│ 00482B...  │ ActualizarPrecio                                 │
│ 00487410   │ ProcesarSuministroYDemandaDelBien                │
│ 0047DC20   │ AcumularValorIndexadoBuffer                      │
│ 0047DCA0   │ RestarStockpileArtesanoFabrica                   │
│ 0047DE60   │ Buffer_EscalarValoresEnRango                     │
│ 0047D9E0   │ Limitar                                           │
│ 0047E3E0   │ Mercado_CalcularProductoPuntoEscalado             │
│ 0043A880   │ redimensionar_vector                              │
│ 004DD470   │ Multiplicar bienes + limitar 0..99999            │
│ 00485E40   │ Actualización económica diaria de POP             │
│ 00523400   │ Interés de préstamos                              │
│ 0054C600   │ intro_sort                                         │
└────────────┴───────────────────────────────────────────────────┘
```


# PARTE VII — SISTEMA DE CARGA / INICIALIZACIÓN DEL JUEGO

## MAPA 32 — `FUN_00662010`

Nombre propuesto:

```text
FinalizarCargaJuegoYEntrarEnPartida
```

Conclusión actual:

```text
FINALIZACIÓN DE CARGA DE UNA SOLA VEZ / INICIALIZACIÓN DEL JUEGO
```

Esta función parece ejecutarse después de la carga/inicialización y antes de que el juego entre en el gameplay normal.

No debe confundirse con el tick económico recurrente.


## MAPA 33 — ESTADO DE CARGA

Al entrar:

```asm
MOV dword ptr [EBX + 0x1E08],0x3
```

Interpretación de trabajo:

```text
EBX + 0x1E08
    ↓
fase de carga / inicialización
```

Nombre propuesto:

```text
m_FaseCarga
```

Los valores exactos de la enumeración aún no están confirmados.


## MAPA 34 — INICIALIZACIÓN DE PANTALLA / RESOLUCIÓN

La función lee campos relacionados con la resolución de objetos alrededor de:

```text
ESI + 0x64
ESI + 0x68
```

y almacena valores en:

```text
EBX + 0x1E10
EBX + 0x1E14
EBX + 0x1E18
```

Nombres de trabajo:

```text
EBX + 0x1E10 → m_AnchoPantalla
EBX + 0x1E14 → m_AltoPantalla
EBX + 0x1E18 → m_RelacionAspectoEscalada
```

Si los objetos de resolución esperados no están disponibles, la función recurre a leer datos de configuración desde un stream.


## MAPA 35 — INICIALIZACIÓN DE VINCULACIONES DE ENTRADA / EVENTOS

La función llama repetidamente a:

```text
ResolverORegistrarEvento
```

utilizando diferentes claves de cadena.

Esto parece resolver/registrar vinculaciones configurables de entrada o eventos.

Los nombres exactos de los eventos/claves todavía se están reconstruyendo.


## MAPA 36 — RESTABLECIMIENTO DEL ESTADO DE ENTIDADES

La función itera sobre entidades/edificios y limpia un campo de estado:

```asm
*(EDI + 0x0C) = 0
```

Conceptualmente:

```text
PARA CADA ENTIDAD
    |
    ▼
RESTABLECER BANDERA DE EJECUCIÓN
```

Esto es consistente con restaurar/reconstruir el estado de ejecución después de cargar.


## MAPA 37 — CADENA DE INICIALIZACIÓN DE SUBSISTEMAS

Se realiza una larga secuencia de llamadas de inicialización sobre el mismo objeto principal.

Funciones observadas:

```text
FUN_00521560
FUN_0050E540
FUN_005068F0
FUN_00521FD0
FUN_0050EA30
FUN_00530E40
FUN_0052FCD0
FUN_0051C890
FUN_005143B0
FUN_00517AF0
FUN_0051EB40
```

Actualmente deben tratarse como:

```text
CADENA DE INICIALIZACIÓN DE SUBSISTEMAS
```

Sus funciones individuales exactas todavía deben mapearse.


## MAPA 38 — REPARACIÓN DE ID / INTEGRIDAD DE ENTIDADES

La función comprueba un campo de entidad alrededor de:

```text
+0x34
```

y puede asignar un nuevo valor si es cero.

El valor resultante está limitado a:

```text
0x186A0
```

que equivale a:

```text
100000
```

Conceptualmente:

```text
ID DE ENTIDAD
   │
   ├── ya válido → conservar
   │
   └── cero → asignar nuevo valor
                 │
                 ▼
              limitar
              100000
```

Esto parece ser un mecanismo de integridad/reconstrucción posterior a la carga.


## MAPA 39 — CACHÉ DE CONFIGURACIÓN

El último bloque grande construye repetidamente claves de cadena y realiza búsquedas.

Los objetos de configuración resultantes se almacenan en caché en campos del objeto principal.

Offsets de destino observados incluyen ejemplos como:

```text
EBX + 0x11C8
EBX + 0x1268
EBX + 0x12B8
EBX + 0x1308
...
```

Conceptualmente:

```text
CLAVE DE CADENA
    │
    ▼
BÚSQUEDA DE CONFIGURACIÓN
    │
    ▼
OBJETO DE CONFIGURACIÓN
    │
    ▼
GUARDAR PUNTERO EN CACHÉ DE EBX
```

Probablemente esto existe para evitar búsquedas repetidas basadas en cadenas durante la ejecución.


## MAPA 40 — SINCRONIZACIÓN DE TOGGLES DEL JUEGO

La función lee un campo de bits alrededor de:

```text
EBX + 0x7E0
```

y utiliza el resultado para seleccionar/configurar diferentes opciones.

Se utilizan varios offsets adyacentes:

```text
+0x4
+0x8
+0xC
+0x10
+0x14
...
```

Nombre de trabajo:

```text
m_BanderasToggleGameplay
```

Estas banderas se sincronizan con objetos de configuración.

Los nombres semánticos exactos de cada bit siguen pendientes.


## MAPA 41 — OBJETO GRANDE DE UI / OVERLAY

La función asigna un objeto de aproximadamente:

```text
0x3C0 bytes
```

y lo inicializa utilizando el estado de configuración.

Un campo alrededor de:

```text
+0x3B8
```

se lee como booleano/toggle.

Hipótesis de trabajo:

```text
controlador de minimapa / overlay / cámara
```

Esto sigue sin estar confirmado.


## MAPA 42 — REGISTRO EN CUADRÍCULA ESPACIAL

Cuando no se está ejecutando en el modo headless relevante, las entidades se registran en una estructura espacial.

Estado importante:

```text
DAT_012588E8 + 0xD11
```

Si el modo relevante está inactivo:

```text
por cada entidad
    |
    +-- entity->0x1D0 = EBX
    |
    +-- FUN_00407B10
    |
    +-- FUN_0068F390
```

`FUN_0068F390` es particularmente interesante porque también apareció en procesamiento económico/de entidades anterior.

Interpretación de trabajo:

```text
ENTIDAD
   ↓
REGISTRO ESPACIAL / BUCKET
   ↓
CUADRÍCULA DE SIMULACIÓN / RENDERIZADO
```


## MAPA 43 — MEDICIÓN DEL TIEMPO DE CARGA

La función realiza una resta de timestamps:

```text
FLD
FSUB
```

y escribe el valor resultante en un stream/log.

Esto es consistente con:

```text
TIEMPO DE CARGA
```


## MAPA 44 — ENTRAR EN GAMEPLAY

Cerca del final:

```text
FUN_006480A0(EBX)
FUN_00648040(EBX,0xB,-1)
```

Se produce una transición de estado a:

```text
0xB
```

Interpretación de trabajo:

```text
CARGA / INICIALIZACIÓN
        ↓
ESTADO = 0xB
        ↓
GAMEPLAY
```

El nombre exacto del enum de estado aún no está confirmado.


## MAPA 45 — CALLBACKS DE INICIO DE SUBSISTEMAS

Un bucle final procesa aproximadamente 32 slots de callbacks:

```text
for ESI = 0; ESI < 0x20; ESI += 4
```

Cada subsistema registrado se obtiene mediante:

```text
EBX + 0xD80 + ESI
```

y ejecuta un callback virtual alrededor de:

```text
vtable + 0x24
```

Conceptualmente:

```text
EL JUEGO ENTRA EN GAMEPLAY
        │
        ▼
32 SLOTS DE SUBSISTEMAS
        │
        ├── callback
        ├── callback
        ├── callback
        ├── ...
        └── callback
```

Esto se parece a un mecanismo de broadcast:

```text
AlIniciarJuego
AlCargarNivel
```

pero el nombre exacto del evento aún no está confirmado.


# PARTE VIII — FUNCIONES DE UTILIDAD / HELPERS RENOMBRADAS

```text
FUN_0043AB60
    CopiarMemoriaSuperpuesta
    → zero_struct_array
    → parece específica para arrays int64

FUN_00AAD56B
    ValidarTamañoMemoria
    → posible operator new / helper de asignación

FUN_0041A160
    InicializarEstructuraConValoresPredeterminados
    → ctor_with_MTTH
    → probablemente constructor de eventos

FUN_0096BBF0
    ConstruirSingleton
    → create_string_with_length("null_pop",8)
    → vtable.CAddAIStrategyEffect.138
    → posiblemente relacionado con la IA de países

thunk_FUN_00AB4D81
    ComprobarEstadoStream
    → __ptmbcinfo
    → comprueba MBCS / página de códigos local

FUN_0047DB00
    CopiarYRedimensionarBuffer
    → constructor de copia CGoodsPool

fcn.004F50C0
    DecaimientoFabricaSinInsumos
    → disminución del nivel de fábrica cuando faltan insumos
```


# PARTE IX — ESTRUCTURA GENERAL DEL MOTOR

```text
00AB0F91
  ENTRADA
    |
    v
009DF550
  BUCLE PRINCIPAL
    |
    v
009796B0
  WINMAIN / MOTOR CLAUSEWITZ
    |
    +-- TIEMPO
    |     |
    |     +-- 00685620
    |     +-- 00682BD0
    |
    +-- ECONOMÍA
    |     |
    |     +-- 0068BF00
    |     +-- 00520150
    |     +-- 006859C0
    |     +-- 00482930
    |     +-- 00482B...
    |
    +-- MERCADO
    |     |
    |     +-- SUMINISTRO
    |     +-- DEMANDA
    |     +-- PRECIO
    |     +-- STOCKPILES
    |
    +-- IA
    |     |
    |     +-- ComprobarUmbralSimpleIA
    |     +-- SISTEMA_DE_EVENTOS
    |
    +-- CONSOLA
    |     |
    |     +-- console_commands
    |
    +-- RENDERIZADO / NIEBLA DE GUERRA
    |     |
    |     +-- FUN_0099da20
    |     +-- FUN_006592f0
    |
    +-- PRÉSTAMOS
    |     |
    |     +-- 00523400
    |
    +-- CARGA DEL JUEGO
    |     |
    |     +-- 00662010
    |
    +-- HILOS
    |     |
    |     +-- 00A7AED0
    |     +-- 00A7B0C0
    |     +-- 00A7B090
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
          +-- Renderizado
```


# PARTE X — CONCLUSIONES IMPORTANTES DE INGENIERÍA INVERSA

## ECONOMÍA

La economía no es una única función.

Está compuesta por múltiples capas:

```text
GESTOR ECONÓMICO
       │
       ├── distribución económica
       │
       ├── reconstrucción de listas económicas
       │
       ├── procesamiento del mercado
       │
       ├── suministro/demanda
       │
       ├── cálculo de precios
       │
       ├── contabilidad periódica
       │
       ├── actualizaciones económicas de POPs
       │
       └── procesamiento de entradas económicas
```

La ruta de precio de mercado confirmada más importante continúa siendo:

```text
SUMINISTRO
  ↓
DEMANDA
  ↓
COMPARACIÓN
  ↓
DIVISIÓN DE INT64 CON SIGNO
  ↓
MULTIPLICADOR DE SUMINISTRO
  ↓
PRECIO
  ↓
LÍMITES MÍNIMO/MÁXIMO
```


## STOCKPILES

Los bienes utilizan una combinación de:

```text
bitflags / índices posicionales
+
vector de stockpile de 64 bits
```

El vector de stockpile utiliza:

```text
entradas de 8 bytes
```

y, por lo tanto, permite cantidades grandes más allá de una representación simple de entero de 32 bits.


## MODIFICACIÓN DE PRECIOS

La estrategia de modificación más segura es:

```text
NO REEMPLAZAR:
Suministro
Demanda
Comparación
División
Multiplicador

MODIFICAR SOLAMENTE:
Límite mínimo
Límite máximo
```

Deseado:

```text
0.2 → 0.1
5.0 → 10.0
```


## PROCESAMIENTO ECONÓMICO PERIÓDICO

`FUN_006859C0` parece ser una rutina periódica de contabilidad económica/calendario.

Nombre de trabajo:

```text
ProcesarTickEconomicoMensual
```

pero el período exacto todavía requiere una confirmación final del calendario.

Parece realizar:

```text
determinar período del calendario
        ↓
procesar entidades económicas
        ↓
acumular categorías económicas
        ↓
actualizar informe económico histórico
```


## INICIALIZACIÓN DE CARGA

`FUN_00662010` parece ser una rutina de una sola ejecución:

```text
FinalizarCargaJuegoYEntrarEnPartida
```

Realiza:

```text
transición del estado de carga
configuración de resolución
carga de configuración
registro de entrada/eventos
restablecimiento de entidades
inicialización de subsistemas
reparación de integridad de entidades
caché de configuración
registro espacial
medición del tiempo de carga
transición al estado de gameplay
callbacks de subsistemas
```

No debe confundirse con el procesamiento recurrente de economía/ticks.


## MULTIHILO

El ejecutable ya contiene un framework genérico de workers:

```text
CreateThread
    ↓
FUN_00A7AED0
    ↓
FUN_00A7B0C0
    ↓
FUN_00A7B090
    ↓
cuerpo virtual del worker
```

Sin embargo, el procesamiento económico contiene acumuladores compartidos.

Por lo tanto:

```text
EXISTENCIA DE UN SISTEMA DE HILOS
        ≠
LA ECONOMÍA YA ES PARALELA
```

y:

```text
AÑADIR HILOS DIRECTAMENTE A LA ECONOMÍA
        ↓
PROBABLEMENTE PRODUCIRÁ CONDICIONES DE CARRERA
```

Los acumuladores privados seguidos de una combinación/merge son el diseño seguro a largo plazo.


# NOTAS

```text
+-- Los nombres de las funciones de eventos siguen siendo tentativos hasta
|   confirmar completamente sus XREFs.
|
+-- 008A67B0 parece estar relacionado con la carga/gestión de recursos de
|   eventos, pero todavía no está confirmado como el punto principal de
|   ejecución de eventos.
|
+-- ComprobarUmbralSimpleIA parece estar relacionado con comprobaciones que
|   pueden interactuar con el sistema de eventos.
|
+-- Eliminar llamadas del sistema de eventos permitió que algunas batallas
|   comenzaran, pero el juego posteriormente se bloqueó después de varios días.
|
+-- Por lo tanto, el procesamiento de eventos probablemente participa en
|   mantenimiento/procesamiento posterior.
|
+-- La economía debe conservar:
|      Suministro → Demanda → Comparación → División →
|      Multiplicador → Precio → Límites
|
+-- console_commands está confirmado empíricamente como el dispatcher central
|   de la consola. Deshabilitarlo elimina todos los comandos de consola.
|
+-- El comando "fow" alterna DAT_013f080c, pero cambiar solamente la bandera
|   global no es suficiente para forzar la Niebla de Guerra permanentemente
|   desactivada.
|
+-- Los parches directos JZ→NOP en las funciones de renderizado rompen sus
|   respectivas capas de renderizado.
|
+-- FUN_006592f0 requiere una inspección adicional de la condición anterior
|   alrededor de 0x6594B4 antes de intentar un parche final de Niebla de Guerra.
|
+-- Helpers genéricos como Buffer_EscalarValoresEnRango,
|   Mercado_CalcularProductoPuntoEscalado y las rutinas de limitación son
|   ampliamente reutilizados y no deberían considerarse automáticamente
|   específicos del mercado.
|
+-- 00487410 está confirmado como una función del lado de la demanda en la
|   ruta inspeccionada.
|
+-- 0047DCA0 confirma la relación entre los bitflags de bienes y el vector
|   de stockpile de 64 bits.
|
+-- 00520150 contiene acumuladores económicos compartidos y, por lo tanto,
|   no debería paralelizarse de forma ingenua.
|
+-- FUN_00969760 realiza acumulación económica compartida y actualmente se
|   considera insegura para ejecución concurrente sobre el mismo objeto.
|
+-- El framework de workers existe, pero el cuerpo real y costoso del worker
|   todavía se está rastreando mediante el objeto ubicado en [ESI+0x18].
|
+-- FUN_006859C0 se entiende actualmente como una rutina periódica de
|   procesamiento económico/calendario. "Mensual" sigue siendo un nombre
|   de trabajo.
|
+-- FUN_00662010 se entiende actualmente como una rutina de finalización de
|   carga del juego y entrada al gameplay ejecutada una sola vez.
|
+-- La estructura de informe económico de 0x70 bytes y el significado de
|   cada una de sus categorías siguen pendientes de reconstrucción campo
|   por campo.
|
+-- Los parches experimentales deben mantenerse claramente separados del
|   comportamiento vanilla en la documentación.
```
Portuges:

# VICTORIA II — DOCUMENTAÇÃO DE ENGENHARIA REVERSA

Documento consolidado com todos os mapas de sistemas reunidos até o momento.


# PARTE I — SISTEMA DE VELOCIDADE DO JOGO

## MAPA 1 — SISTEMA DE VELOCIDADE DO JOGO (VISÃO GERAL)

```text
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│                         VICTORIA II — SISTEMA DE VELOCIDADE DO JOGO                          │
└──────────────────────────────────────────────────────────────────────────────────────────────┘


                                  COMANDOS DE VELOCIDADE
                                            │
                         ┌──────────────────┼──────────────────┐
                         │                  │                  │
                         ▼                  ▼                  ▼
                  0072EE90            0072EFE0            0064E608
               Aumentar velocidade  Diminuir velocidade   gamespeed_max
                         │                  │                  │
                         └──────────────┬───┘                  │
                                        ▼
                                  B28 = B28 ± 1
                                  Limite: 0..4
                                        │
                                        ▼
                              DAT_012588E8 + 0xB28
                              ÍNDICE DE VELOCIDADE
                                        │
                         ┌──────────────┼──────────────┐
                         │              │              │
                         ▼              ▼              ▼
                      B28=0          B28=1          B28=2
                         │              │              │
                         ▼              ▼              ▼
                  VELOCIDADE_MÍNIMA VELOCIDADE_LENTA VELOCIDADE_NORMAL
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
                   VELOCIDADE_RÁPIDA            VELOCIDADE_MÁXIMA
                         │                             │
                         ▼                             ▼
                     00F09578                     00F0957C
                       0.04f                         0.06f
                         │                             │
                         └──────────────┬──────────────┘
                                        │
                                        ▼
                         ┌─────────────────────────────┐
                         │  CONTROLE DO TEMPO DE      │
                         │      ATUALIZAÇÃO           │
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
                         SELECIONAR FLOAT DE CONTROLE
                                        │
                                        ▼
                              XMM0 = TABELA[B28]
                                        │
                                        ▼
                              × DAT_013F2AE8
                                        │
                                        ▼
                         DAT_012588F0 + 1.0
                                        │
                                        ▼
                              LIMIAR TEMPORAL
                                        │
                                        ▼
                              COMPARAÇÃO TEMPORAL
                                        │
                         ┌──────────────┴──────────────┐
                         │                             │
                         ▼                             ▼
                    NÃO ALCANÇADO                  ALCANÇADO
                         │                             │
                         ▼                             ▼
                       RET                 CALL vtable + 0x100
                                                        │
                                                        ▼
                                      ProcessarMensagensEAtualizar
                                             009DF2B0
                                                        │
                                                        ▼
                                               CICLO DE ATUALIZAÇÃO


                         ╔══════════════════════════════════╗
                         ║      SEGUNDO USO DE B28          ║
                         ╚════════════════╦═════════════════╝
                                          │
                                          ▼
                                     FUN_00682BD0
                              ProcessarAvancoTempoJogo
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
                                  TABELA DE ESCALA
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
                            TABELA COMPLETA DA VERSÃO VANILLA
                                          │
                                          ▼
                         4.0 / 2.0 / 1.0 / 0.5 / 0.0004
```

## MAPA 1A — TABELA VANILLA DO CONTROLE DO TEMPO DE ATUALIZAÇÃO

A primeira tabela começa em:

```text
DAT_00F0956C
```

É acessada através de:

```asm
MOV EAX,[EDI+0xB28]
MOVSS XMM0,[EAX*4 + DAT_00F0956C]
```

Isso significa:

```text
B28 = índice da tabela
```

Cada entrada ocupa 4 bytes.

### Tabela completa

```text
┌─────┬────────────┬────────────────┬──────────────────┐
│ B28 │ Endereço   │ Valor Vanilla  │ Velocidade UI     │
├─────┼────────────┼────────────────┼──────────────────┤
│  0  │ 00F0956C   │ 0.03f          │ MÍNIMA           │
│  1  │ 00F09570   │ 0.03f          │ LENTA            │
│  2  │ 00F09574   │ 0.03f          │ NORMAL           │
│  3  │ 00F09578   │ 0.04f          │ RÁPIDA           │
│  4  │ 00F0957C   │ 0.06f          │ MÁXIMA           │
└─────┴────────────┴────────────────┴──────────────────┘
```

### Bytes vanilla

```text
0.03f = 8F C2 F5 3C
0.04f = 0A D7 23 3D
0.06f = 8F C2 75 3D
```

Distribuição em memória:

```text
00F0956C → 8F C2 F5 3C
00F09570 → 8F C2 F5 3C
00F09574 → 8F C2 F5 3C
00F09578 → 0A D7 23 3D
00F0957C → 8F C2 75 3D
```

## MAPA 1B — CONTROLE DO TEMPO DE ATUALIZAÇÃO

```text
                         CONTROLE DO TEMPO DE ATUALIZAÇÃO
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
                                      TABELA[B28]
                                           │
                              ┌────────────┴────────────┐
                              │                         │
                              ▼                         ▼
                           B28=0..2                  B28=3..4
                           0.03f                    0.04f/0.06f
                              │                         │
                              └────────────┬────────────┘
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
                                    LIMIAR TEMPORAL
                                           │
                                           ▼
                                  COMPARAÇÃO TEMPORAL
                                           │
                            ┌──────────────┴──────────────┐
                            │                             │
                            ▼                             ▼
                       NÃO ALCANÇADO                  ALCANÇADO
                            │                             │
                            ▼                             ▼
                           RET                     vtable + 0x100
                                                          │
                                                          ▼
                                      ProcessarMensagensEAtualizar
                                               009DF2B0
                                                          │
                                                          ▼
                                             ATUALIZAÇÃO DO JOGO
```

## MAPA 1C — FÓRMULA DO CONTROLE DO TEMPO DE ATUALIZAÇÃO

Sequência relevante:

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

`DOUBLE_00E45580 = 1.0`

Portanto:

```text
TABELA[B28]
      │
      ▼
× DAT_013F2AE8
      │
      ▼
× (DAT_012588F0 + 1.0)
      │
      ▼
LIMIAR TEMPORAL
```


# MAPA 2 — SEGUNDO SISTEMA: FUN_00682BD0

```text
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│                 FUN_00682BD0 — PROCESSAR AVANÇO DO TEMPO DO JOGO                            │
└──────────────────────────────────────────────────────────────────────────────────────────────┘

FUN_00682BD0
│
├── 1. Acumula tempo
│      │
│      └── [ESI+0xB14] += XMM0
│
├── 2. Verifica [ESI+0xB20]
│      │
│      └── se != 0 → RETORNO
│
├── 3. Lê B28
│      │
│      └── MOV EAX,[ESI+0xB28]
│
├── 4. Constrói tabela temporal
│      │
│      ├── B28=0 → 4.0f
│      ├── B28=1 → 2.0f
│      ├── B28=2 → 1.0f
│      ├── B28=3 → 0.5f
│      └── B28=4 → 0.0004f
│
├── 5. Seleciona TABELA[B28]
│
├── 6. Compara [ESI+0xB14]
│      com o valor selecionado
│
├── 7. Continua o processamento temporal
│
├── 8. Processa lógica de calendário/data
│
└── 9. Modifica DAT_012588F0
```

## MAPA 2A — CONSTRUÇÃO DA TABELA

```text
00682C1F
MOVSS XMM0,[DAT_00F17B58]
→ [EBP-0x24] = 4.0f

00682C32
MOVSS XMM0,[DAT_00F17B54]
→ [EBP-0x20] = 2.0f

00682C3F
MOVSS XMM0,[DAT_00F092FC]
→ [EBP-0x1C] = 1.0f

00682C4C
MOVSS XMM0,[DAT_00F17898]
→ [EBP-0x18] = 0.5f

00682C59
MOVSS XMM0,[DAT_00E45BB8]
→ [EBP-0x14] = 0.0004f
```

## MAPA 2B — ORDEM EXATA DA TABELA

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

## MAPA 2C — TABELA VANILLA COMPLETA

```text
┌─────┬────────────┬────────────┬──────────────────────────┐
│ B28 │ LOCAL      │ DAT        │ VALOR VANILLA            │
├─────┼────────────┼────────────┼──────────────────────────┤
│  0  │ EBP-0x24   │ 00F17B58   │ 4.0f                     │
│  1  │ EBP-0x20   │ 00F17B54   │ 2.0f                     │
│  2  │ EBP-0x1C   │ 00F092FC   │ 1.0f                     │
│  3  │ EBP-0x18   │ 00F17898   │ 0.5f                     │
│  4  │ EBP-0x14   │ 00E45BB8   │ 0.0004f                  │
└─────┴────────────┴────────────┴──────────────────────────┘
```

IEEE-754:

```text
4.0f      = 00 00 80 40
2.0f      = 00 00 00 40
1.0f      = 00 00 80 3F
0.5f      = 00 00 00 3F
0.0004f   = 17 B7 D1 38
```

## MAPA 2D — COMPARAÇÃO DO ACUMULADOR

```text
                    [ESI+0xB14]
                          │
                          ▼
                       ACUMULADOR
                          │
                          │ comparar
                          ▼
                       TABELA[B28]
                          │
              ┌───────────┴───────────┐
              │                       │
              ▼                       ▼
          NÃO ALCANÇADO            ALCANÇADO
              │                       │
              ▼                       ▼
       continuar / retorno       processamento temporal
```


# MAPA 3 — BARREIRAS DO PROCESSAMENTO TEMPORAL

## BARREIRA 1 — [ESI+0xB20]

```text
FUN_00682BD0
      │
      ▼
CMP [ESI+0xB20]
      │
      ├── != 0 → RETORNO
      │
      └── == 0 → CONTINUAR
```

## BARREIRA 2 — [ESI+0xBB8]

Vanilla:

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

Patch experimental:

```text
90 90 90 90 90 90
```

Isso foi confirmado experimentalmente como uma barreira real de processamento.

O patch NOP **não faz parte do comportamento vanilla**.


# MAPA 4 — ESTADOS GLOBAIS TEMPORAIS

`FUN_00682BD0` modifica:

```text
DAT_012588E6
DAT_012588EC
DAT_012588F0
```

Relação:

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
                    ControleTempoAtualizacao
                              │
                              ▼
                         LIMIAR TEMPORAL
```

## MAPA 4A — DAT_012588F0

Operações observadas incluem:

```text
DAT_012588F0 × 0.95
DAT_012588F0 × 0.9
DAT_012588F0 + 0.5
```

Também existe lógica relacionada a diferenças de datas.

Portanto:

```text
FUN_00682BD0
      │
      ▼
DAT_012588F0
      │
      ▼
ControleTempoAtualizacao
      │
      ▼
LIMIAR
```

Esta é uma conexão importante entre ambos os sistemas temporais.


# MAPA 5 — DAT_00E45BB8

```text
┌─────────────────────────────────────────────────────────┐
│ DAT_00E45BB8                                            │
├─────────────────────────────────────────────────────────┤
│ Endereço: 00E45BB8                                     │
│ Valor vanilla: 0.0004f                                 │
│ Bytes: 17 B7 D1 38                                      │
│ Uso de velocidade: B28=4                               │
└─────────────────────────────────────────────────────────┘
```

Correspondência:

```text
B28=4
   ↓
DAT_00E45BB8
   ↓
0.0004f
```

Importante:

```text
MUDAR DAT_00E45BB8
        ≠
MUDAR SOMENTE A VELOCIDADE DO JOGO
```

Possui múltiplas XREFs.


# MAPA 6 — DAT_00F092FC

```text
┌─────────────────────────────────────────────────────────┐
│ DAT_00F092FC                                            │
├─────────────────────────────────────────────────────────┤
│ Endereço: 00F092FC                                     │
│ Valor vanilla: 1.0f                                    │
│ Bytes: 00 00 80 3F                                     │
│ Uso de velocidade: B28=2                               │
└─────────────────────────────────────────────────────────┘
```

Em `FUN_00682BD0`:

```text
B28=2
   ↓
DAT_00F092FC
   ↓
1.0f
```

Também aparece em:

```text
FUN_00475150
```

com:

```asm
0047527C
MOVSS XMM0,[DAT_00F092FC]

00475286
MOVSS [EDI+0x178],XMM0
```

Portanto:

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


# MAPA 7 — VISUALIZAÇÃO DE VELOCIDADE / INTERFACE

```text
                              B28
                               │
                  ┌────────────┴────────────┐
                  │                         │
                  ▼                         ▼
             00715DE5                  0070DFE0
                  │                         │
                  ▼                         ▼
          TABELA DE NOMES DE           Ler B28
             VELOCIDADE                    │
                  │                       ▼
     ┌────────────┼────────────┐     ADD EAX,2
     │            │            │            │
     ▼            ▼            ▼            ▼
   B28=0        B28=2        B28=4     [ESP+0x30]
  MÍNIMA        NORMAL       MÁXIMA        │
     │            │            │            ▼
     └────────────┼────────────┘     LÓGICA DE UI / ESTADO
                  │
                  ▼
       00E11040 → VELOCIDADE_MÍNIMA
       00E11050 → VELOCIDADE_LENTA
       00E1105C → VELOCIDADE_NORMAL
       00E1106C → VELOCIDADE_RÁPIDA
       00E11078 → VELOCIDADE_MÁXIMA
```


# MAPA 8 — RELAÇÃO ENTRE AS DUAS TABELAS

```text
                         B28 = 0..4
                              │
                ┌─────────────┴─────────────┐
                │                           │
                ▼                           ▼
        TABELA 1 — CONTROLE            TABELA 2 — TEMPORAL
        DAT_00F0956C                   FUN_00682BD0
                │                           │
       0.03/0.03/0.03/0.04/0.06     4.0/2.0/1.0/0.5/0.0004
                │                           │
                └─────────────┬─────────────┘
                              │
                              ▼
                       SISTEMA TEMPORAL
```

As tabelas não contêm os mesmos valores e não realizam exatamente a mesma função.

Compartilham diretamente:

```text
B28
```


# MAPA 9 — MAPEAMENTO COMPLETO DE B28

```text
┌─────┬──────────────────┬──────────────┬──────────────────────┬──────────────┐
│ B28 │ VELOCIDADE       │ INTERFACE    │ CONTROLE ATUALIZAÇÃO │ TEMPORAL     │
├─────┼──────────────────┼──────────────┼──────────────────────┼──────────────┤
│  0  │ VELOCIDADE_MÍNIMA│ MÍNIMA       │ 0.03f                │ 4.0f         │
│  1  │ VELOCIDADE_LENTA │ LENTA        │ 0.03f                │ 2.0f         │
│  2  │ VELOCIDADE_NORMAL│ NORMAL       │ 0.03f                │ 1.0f         │
│  3  │ VELOCIDADE_RÁPIDA│ RÁPIDA       │ 0.04f                │ 0.5f         │
│  4  │ VELOCIDADE_MÁXIMA│ MÁXIMA       │ 0.06f                │ 0.0004f      │
└─────┴──────────────────┴──────────────┴──────────────────────┴──────────────┘
```


# MAPA 10 — FLUXO COMPLETO DO SISTEMA

```text
                         Aumentar / Diminuir Velocidade
                                      │
                                      ▼
                                 B28 = 0..4
                                      │
             ┌────────────────────────┼────────────────────────┐
             │                        │                        │
             ▼                        ▼                        ▼
       VELOCIDADE UI         ControleTempoAtualizacao    FUN_00682BD0
       00715DE5 /                00685620                    │
       0070DFE0                     │                        │
             │                      │                        ▼
             │                      │                MOV EAX,[ESI+0xB28]
             │                      │                        │
             │                      │                        ▼
             │                      │                 TABELA TEMPORAL
             │                      │                        │
             │                      │                        ▼
             │                      │                 ACUMULADOR B14
             │                      │                        │
             │                      │                        ▼
             │                      │                    B20 / BB8
             │                      │                        │
             │                      │                        ▼
             │                      │                 LÓGICA TEMPORAL
             │                      │                        │
             │                      │                        ▼
             │                      │                 DAT_012588F0
             │                      │                        │
             │                      ▼                        │
             │                DAT_00F0956C                    │
             │                      │                         │
             │                      ▼                         │
             │                0.03/0.04/0.06                  │
             │                      │                         │
             │                      ▼                         │
             │               × DAT_013F2AE8                    │
             │                      │                         │
             │                      ▼                         │
             │            × (DAT_012588F0 + 1)                │
             │                      │                         │
             │                      ▼                         │
             │                 LIMIAR TEMPORAL                 │
             │                      │                         │
             │                      ▼                         │
             │              COMPARAÇÃO TEMPORAL               │
             │                      │                         │
             │                      ▼                         │
             │       ProcessarMensagensEAtualizar ◄────────────┘
             │                  009DF2B0
             │                      │
             └──────────────────────┴─────────────────────────►
                                      ATUALIZAÇÃO DO JOGO
```


# MAPA 11 — PONTOS IMPORTANTES PARA MODDING

```text
┌────────────────────────────────────────────────────────────────┐
│                    PONTOS DE INTERESSE                          │
├────────────────────┬───────────────────────────────────────────┤
│ 00685620           │ ControleTempoAtualizacao                  │
│ 00682BD0           │ ProcessarAvancoTempoJogo                  │
│ 00F0956C           │ Início da tabela de atualização            │
│ 00F0957C           │ Entrada B28=4 → 0.06f                     │
│ 00F17B58           │ Entrada B28=0 → 4.0f                      │
│ 00F17B54           │ Entrada B28=1 → 2.0f                      │
│ 00F092FC           │ Entrada B28=2 → 1.0f                      │
│ 00F17898           │ Entrada B28=3 → 0.5f                      │
│ 00E45BB8           │ Entrada B28=4 → 0.0004f                   │
│ 012588F0           │ Fator temporal compartilhado               │
│ [ESI+0xB14]        │ Acumulador temporal                        │
│ [ESI+0xB20]        │ Estado que pode interromper a função      │
│ [ESI+0xBB8]        │ Condição/barreira temporal                 │
│ 009DF2B0           │ ProcessarMensagensEAtualizar               │
└────────────────────┴───────────────────────────────────────────┘
```


# MAPA 12 — CONCLUSÃO

O sistema de velocidade de Victoria II utiliza:

```text
                         B28 = 0..4
                              │
                ┌─────────────┴─────────────┐
                │                           │
                ▼                           ▼
       CONTROLE DO TEMPO DE           AVANÇO TEMPORAL
          ATUALIZAÇÃO                    00682BD0
             00685620                      │
                │                          │
                ▼                          ▼
       0.03/0.03/0.03/0.04/0.06    4.0/2.0/1.0/0.5/0.0004
                │                          │
                ▼                          ▼
       DAT_013F2AE8                [ESI+0xB14]
                │                          │
                ▼                          ▼
       DAT_012588F0                [ESI+0xB20]
                │                          │
                │                     [ESI+0xBB8]
                │                          │
                └──────────────┬───────────┘
                               │
                               ▼
                         ATUALIZAÇÃO DO JOGO
```

A conclusão atual é que **B28 é o índice central de velocidade**, enquanto Victoria II utiliza duas tabelas diferentes para controlar aspectos distintos do processamento temporal.

As modificações experimentais como:

```text
4.0f através de code cave
testes com 5.0f usando DAT_00F092FC
0.000001f em DAT_00E45BB8
NOPs em 00682D0C
```

devem ser consideradas **patches experimentais**, não comportamento vanilla.


# PARTE II — ESTRUTURA GERAL DO MOTOR, ECONOMIA, CONSOLE E NEBLINA DE GUERRA

```text
00AB0F91
  ENTRADA
    |
    v
009DF550
  LOOP PRINCIPAL
    |
    +-- 009796B0
    |     WINMAIN / MOTOR CLAUSEWITZ
    |
    +-- 0068BF00
    |     ECONOMIA
    |
    +-- IA
    |     |
    |     +-- VerificarLimiarSimplesIA
    |             |
    |             v
    |         SISTEMA DE EVENTOS
    |           008A67B0
    |
    +-- COMANDOS DE CONSOLE
    |     |
    |     +-- console_commands (00420eb0)
    |
    +-- RENDERIZAÇÃO / NEBLINA DE GUERRA
    |     |
    |     +-- FUN_0099da20
    |     +-- FUN_006592f0
    |
    +-- EMPRÉSTIMOS
    |     |
    |     +-- 00523400
    |
    +-- OUTROS SISTEMAS DE TICK
          |
          +-- Atualizações de países
          +-- Atualizações de POPs
          +-- Atualizações de IA
          +-- Atualizações econômicas
          +-- Atualizações de eventos
          +-- Atualizações de guerras
          +-- Atualizações do mundo
```

## FLUXO ECONÔMICO DETALHADO

```text
0068BF00
  ATUALIZAR_ECONOMIA
    |
    v
ATUALIZAR MERCADO MUNDIAL (00484060)
    |
    v
00482930
  ATUALIZAR SUPRIMENTO
    |
    +-- SUPRIMENTO
    +-- DEMANDA
    +-- COMPARAÇÃO DE 64 BITS
    +-- DIVIDIR_INTEIRO64_COM_SINAL
    +-- CALCULAR_MULTIPLICADOR_SUPRIMENTO
    |
    v
00482B...
  ATUALIZAR PREÇO
    |
    +-- PREÇO BASE
    +-- MULTIPLICADOR
    +-- LIMITE MÍNIMO
    |     DAT_00E45C30
    |     ×0.2 VANILLA
    |
    +-- LIMITE MÁXIMO
    |     DAT_00E45C28
    |     ×5.0 VANILLA
    |
    v
  PREÇO FINAL
```

## FLUXO DE EVENTOS

```text
VERIFICAR_LIMIAR_SIMPLES_IA
    |
    +-- Verifica condições
    +-- Verifica limiares
    +-- Realiza chamadas relacionadas a eventos
    |
    v
008A67B0
  SISTEMA DE EVENTOS
```


## SISTEMA_DE_EVENTOS

```text
008A67B0
SISTEMA DE RECURSOS / GERENCIADOR DE EVENTOS
        |
        +-- FUN_008A5AC0
        |     INICIALIZAR GERENCIADOR DE EVENTOS
        |
        +-- FUN_008A5C70
        |     INICIALIZAR ESTRUTURA DE EVENTO
        |
        +-- FUN_009A1440
        |     INICIALIZAR OBJETO DE EVENTO
        |
        +-- FUN_008A6010
        |     OBTER NOME DO EVENTO PRINCIPAL
        |
        +-- FUN_008A60F0
        |     OBTER NOME DO EVENTO SECUNDÁRIO
        |
        +-- FUN_008A67B0
              CARREGAR RECURSOS DE EVENTOS
```

## CONSOLE

`console_commands` foi identificado anteriormente como `FUN_00420EB0`.

Recebe a entrada de console tokenizada e realiza uma cascata de comparações através de cadeias de comandos.

Resultado empírico:

```text
DESABILITAR console_commands
        ↓
DESAPARECEM TODOS OS COMANDOS DE CONSOLE
```

O comando `"fow"` foi confirmado como responsável por alternar:

```text
DAT_013f080c
```

e refletir o valor em:

```text
[DAT_01258a74 + 0x6bc44]
```

## NEBLINA DE GUERRA

Estruturas importantes:

```text
DAT_01258a74
    ↓
singleton do dispositivo gráfico/renderização

DAT_013f080c
    ↓
estado global da Neblina de Guerra
```

`FUN_0099da20` participa da inicialização/restauração gráfica.

`FUN_006592f0` é executada na rota de renderização por frame.

Os patches experimentais diretos JZ→NOP foram confirmados como causadores de quebra em:

```text
FUN_0099da20 → renderização de texto/UI
FUN_006592f0 → texturas do terreno/mapa
```

Portanto, os patches diretos de saltos condicionais **não são patches finais seguros para a Neblina de Guerra**.

A condição anterior em torno de:

```text
0x6594B4
```

ainda precisa ser compreendida antes de implementar um patch limpo e permanente para desativar a Neblina de Guerra.


# PARTE III — SISTEMA DO GERADOR DE NÚMEROS ALEATÓRIOS (RNG)

```text
                         v2game.exe+0xb0ecf0
                       LISTA DE NÚMEROS ALEATÓRIOS
                                  │
                                  ▼
                         v2game.exe+0xb0f6b0
                        ÍNDICE ATUAL DA LISTA
                                  │
                                  ▼
                          fun_009b7610
                    FUNÇÃO QUE OBTÉM UM NÚMERO
                                  │
                    ┌─────────────┴─────────────┐
                    │                           │
                    ▼                           ▼
             ÍNDICE + 1                  LISTA ESGOTADA?
                    │                           │
                    ▼                           ▼
          RETORNA O NÚMERO                fun_009b7700
                                               │
                                               ▼
                                      GERA UMA NOVA LISTA
                                      USANDO MERSENNE TWISTER
```

O estado da lista utiliza:

```text
v2game.exe+0xb0ecf0
```

Índice atual:

```text
v2game.exe+0xb0f6b0
```

`fun_009b7610` obtém o próximo número.

Quando a lista se esgota, `fun_009b7700` regenera a lista.

A regeneração utiliza a família **Mersenne Twister / MT19937**.


# PARTE IV — CALLBACKS DE BOTÕES

| Função | Função | Estado |
|---|---|---|
| `FUN_006dfe80` | Callback ao pressionar o botão Ocidentalizar | Confirmado |
| `FUN_00541b90` | Condição para determinar se o botão Ocidentalizar pode ser pressionado | Confirmado |
| `FUN_00772300` | Callback do botão Jogar | Provável |
| Outras funções de botões | Identificadas anteriormente | Pendente de recuperação |

A distinção exata entre os callbacks de Jogar SP/MP continua sem solução.


# PARTE V — SUBTRAÇÃO DO STOCKPILE DE ARTESÃOS/FÁBRICAS

## MAPA 13 — `SubtrairStockpileArtesaoFabricaDoStockpileESI` — 0x0047DCA0

Esta função fornece evidências importantes sobre como os bens e os stockpiles são representados.

```text
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│       SubtrairStockpileArtesaoFabricaDoStockpileESI (0x0047dca0)                             │
└──────────────────────────────────────────────────────────────────────────────────────────────┘

Para cada bem:

artisan/factory.good_bit_flags[idx]
                │
                ▼
          O bem está presente?
                │
          ┌─────┴─────┐
          │           │
         NÃO         SIM
          │           │
          ▼           ▼
       OMITIR    Verificar destino ESI
                         │
                  ┌──────┴──────┐
                  │             │
             ausente          presente
                  │             │
                  ▼             ▼
          criar entrada    subtrair int64
          com -quantidade  diretamente
```

Campos importantes:

```text
[0x12587f4]
    quantidade_de_bens

[entity + 0x08 + idx]
    bitflag / índice posicional do bem

[entity + 0x48]
    início do vetor de stockpile

[entity + 0x4C]
    fim do vetor de stockpile
```

As entradas do stockpile são:

```text
8 bytes
=
inteiro de 64 bits
=
2 × int32
```

O tamanho do vetor é obtido através de:

```text
(end - begin) >> 3
```

Quando o destino não possui uma entrada:

```text
quantidade do artesão/fábrica
        ↓
NEG valor de 64 bits
        ↓
push_back no vetor de stockpile ESI
```

Quando o destino já possui uma entrada:

```text
stockpile ESI
        -
stockpile artesão/fábrica
        ↓
SUB + SBB de 64 bits
```

Portanto, conceitualmente:

```text
ESI.stockpile[bem]
    -=
artesão/fábrica.stockpile[bem]
```

### Descoberta importante

O byte localizado em:

```text
entity + 0x08 + índice_do_bem
```

atua como estrutura de presença/índice.

A quantidade real é armazenada no vetor de stockpile em:

```text
entity + 0x48
```

com entradas de 8 bytes.

Isso é importante para compreender a representação de bens utilizada pelo sistema de mercado.


# PARTE VI — SISTEMA DETALHADO DE MERCADO / ECONOMIA

## MAPA 14 — FLUXO COMPLETO DO GERENCIADOR ECONÔMICO

O gerenciador econômico é consideravelmente maior do que a rota simples de `AtualizarMercadoMundial`.

Estrutura consolidada atual:

```text
0068BF00
AtualizarGerenciadorEconomicoCompleto
   |
   +--> 00520150
   |    CalcularDistribuicaoEconomica
   |       |
   |       +--> grandes loops aninhados
   |       |
   |       +--> entradas econômicas
   |       |
   |       +--> acumuladores compartilhados
   |       |
   |       +--> acumuladores por bem
   |
   +--> ReconstruirListasEconomicas (0068d250)
   |
   +--> 00482930
   |    AtualizarSuprimento
   |       |
   |       +--> SUPRIMENTO
   |       +--> DEMANDA
   |       +--> comparação de 64 bits
   |       +--> DividirInteiro64ComSinal
   |       +--> CalcularMultiplicadorSuprimento
   |       |
   |       v
   |    00482B...
   |    AtualizarPreco
   |       |
   |       +--> PREÇO BASE
   |       +--> MULTIPLICADOR
   |       +--> PREÇO MÍNIMO
   |       +--> PREÇO MÁXIMO
   |       +--> PREÇO FINAL
   |
   +--> 004808D0
   |    ProcessarMercadoEDistribuicaoBens
   |
   +--> PrepararAtualizacaoEconomica (0068d950)
   |
   +--> AtualizarEconomia(...,0)
   +--> AtualizarEconomia(...,1)
   +--> AtualizarEconomia(...,2)
   +--> AtualizarEconomia(...,3)
   +--> AtualizarEconomia(...,4)
   |
   +--> ProcessarEntradasEconomicas (0068dc70)
```

O significado semântico exato das cinco passagens de `AtualizarEconomia (00489990)` continua sob investigação.

Não obstante, o fluxo geral está claramente centrado na distribuição econômica, nos cálculos de mercado e no processamento econômico periódico.


## MAPA 15 — PIPELINE SUPRIMENTO / DEMANDA / PREÇO

A rota de mercado mais importante reconstruída atualmente é:

```text
                    MERCADO
                      │
                      ▼
              00482930
           AtualizarSuprimento
                      │
          ┌───────────┴───────────┐
          │                       │
          ▼                       ▼
      SUPRIMENTO                DEMANDA
          │                       │
          └───────────┬───────────┘
                      ▼
              COMPARAÇÃO DE 64 BITS
                      │
                      ▼
             DividirInteiro64ComSinal
                      │
                      ▼
          CalcularMultiplicadorSuprimento (00482610)
                      │
                      ▼
                00482B...?
              AtualizarPreco
                      │
          ┌───────────┴───────────┐
          │                       │
          ▼                       ▼
      PREÇO BASE              MULTIPLICADOR
          │                       │
          └───────────┬───────────┘
                      ▼
                LIMITES DE PREÇO
                 /        \
                /          \
               ▼            ▼
           MÍNIMO         MÁXIMO
          ×0.2 vanilla    ×5.0 vanilla
               │            │
               └─────┬──────┘
                     ▼
                PREÇO FINAL
```

Este fluxo vanilla deve ser preservado ao modificar o sistema de preços.


## MAPA 16 — LIMITES DE PREÇO

Vanilla:

```text
PREÇO MÍNIMO
    =
PREÇO BASE × 0.2
```

Endereço:

```text
DAT_00E45C30
```

Máximo:

```text
PREÇO MÁXIMO
    =
PREÇO BASE × 5.0
```

Endereço:

```text
DAT_00E45C28
```

Limites modificados desejados:

```text
MÍNIMO = PREÇO BASE × 0.1
MÁXIMO = PREÇO BASE × 10.0
```

Objetivo:

```text
Suprimento
  ↓
Demanda
  ↓
Comparação
  ↓
Divisão de 64 bits
  ↓
Multiplicador de suprimento
  ↓
Cálculo de preço
  ↓
NOVOS LIMITES
  ↓
Preço final
```

O cálculo vanilla de suprimento/demanda **não deve ser substituído**.

Modificações experimentais anteriores que substituíram demais da lógica vanilla produziram comportamentos patológicos como:

```text
suprimento > demanda → preço ≈ 0.01
suprimento < demanda → preço ≈ 1000
```

Portanto, a abordagem correta é modificar apenas os limites.


## MAPA 17 — OBJETIVOS DO PATCH DE LIMITES DE PREÇO

A instrução do limite inferior foi identificada próximo a:

```text
00482C46
```

com:

```asm
FLD qword ptr [DAT_00E45C30]
```

Patch previsto:

```text
DAT_00E45C30
    0.2
      ↓
    0.1
```

Limite superior:

```text
DAT_00E45C28
    5.0
      ↓
    10.0
```

Estes são os pontos de patch preferidos porque preservam o cálculo anterior de suprimento/demanda.


## MAPA 18 — AGREGAÇÃO DE DEMANDA DO MERCADO

### `FUN_00487410`

Nome proposto:

```text
ProcessarSuprimentoEDemandaDoBem
```

Estado:

```text
CONFIRMADO — ROTA DE DEMANDA
```

A função foi inspecionada detalhadamente e confirmou-se que modifica a demanda e não o suprimento.

Instrução relevante:

```asm
004877B1
LEA EAX,[EDX+EAX*8]
```

Interpretação:

```text
EDX
 ↓
contêiner real_demand

EAX
 ↓
índice dentro de real_demand
```

Conceitualmente:

```text
BEM
 │
 ▼
real_demand[bem]
 │
 ▼
ADICIONAR DEMANDA REAL
```

Isso é importante porque uma função que pelo nome parece lidar tanto com "suprimento quanto demanda" foi determinada experimentalmente como pertencente ao lado da demanda nesta rota.


## MAPA 19 — CONTRIBUIÇÃO DO STOCKPILE ÀS ESTATÍSTICAS DE MERCADO

Função:

```text
AcumularValorIndexadoBuffer
```

Endereço provável:

```text
0047DC20
```

Instruções importantes:

```asm
0047DC56
MOV EDI,[ECX+EDX*8]

0047DC59
ADD [EAX],EDI
```

Interpretação:

```text
ECX + EDX*8
        ↓
quantidade do stockpile

EDI
        ↓
quantidade

[EAX]
        ↓
acumulador global de suprimento/demanda
```

Dependendo do contexto de chamada, `[EAX]` representa o acumulador de mercado correspondente.

Isso conecta os stockpiles individuais com estatísticas de mercado de nível superior.


## MAPA 20 — HELPERS GENÉRICOS DE MERCADO / BUFFER

Várias funções foram identificadas durante a investigação do mercado.

### `FUN_0047E3E0`

Nome proposto:

```text
Mercado_CalcularProdutoEscalarEscalonado
```

Uso observado:

```text
~58 locais
```

Conclusão atual:

```text
Provavelmente utilidade matemática genérica.
Não confirmado como específico do mercado.
```

### `FUN_0047DE60`

Nome proposto:

```text
Buffer_EscalarValoresNoIntervalo
```

Alias:

```text
multiplicar_valores_em_vetor
```

Uso observado:

```text
~53 locais
```

Opera sobre vetores / blocos de memória contíguos.

Conclusão atual:

```text
Helper genérico de vetor/buffer.
```

### `FUN_0043A880`

```text
redimensionar_vetor
```

Rotina genérica para redimensionar vetores.

### `0x0047D9E0`

```text
limitar_0_a_arg8h_e_argch
```

Rotina genérica de limitação.

### `FUN_004DD470`

Nome proposto:

```text
MultiplicarBensELimitar0_99999
```

Constante importante:

```text
0xC34F8000
```

que corresponde à representação em ponto fixo de aproximadamente:

```text
99999
```

Esta função multiplica quantidades relacionadas a bens e limita o resultado ao intervalo esperado.


## MAPA 21 — ATUALIZAÇÃO ECONÔMICA POR POP

Função:

```text
AtualizarContribuicoesEconomicasPOP (00485E40)
```

Nome proposto:

```text
AtualizarDinheiroDiarioPOP
```

Responsabilidades observadas incluem:

```text
dinheiro do POP
necessidades do POP
necessidades satisfeitas
valores relacionados a banco / poupança
outros estados econômicos diários
```

Esta função provavelmente se encontra a jusante do gerenciador econômico geral e representa o processamento econômico por POP, em vez do cálculo global do mercado.


## MAPA 22 — DISTRIBUIÇÃO ECONÔMICA

### `00520150 — CalcularDistribuicaoEconomica`

Esta função contém uma estrutura de grandes loops aninhados.

Loop importante:

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

O processamento interno pode se repetir:

```text
005208E4
CMP [EBP-0x5C],0

005208E8
JNZ 00520630
```

antes de avançar a iteração externa.

Avanço do loop externo:

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

Portanto:

```text
índice externo
    ↓
[EBP-0x44] += 0x10
    ↓
processamento econômico interno
    ↓
acumuladores compartilhados
    ↓
próxima entrada econômica
```


## MAPA 23 — ACUMULADORES ECONÔMICOS COMPARTILHADOS

O loop de distribuição econômica escreve em campos compartilhados como:

```text
this + 0x8D8 + i*8
this + 0x900 + i*8
```

utilizando aritmética de 64 bits:

```text
ADD
ADC
```

Outros estados compartilhados observados:

```text
this + 0x13E8
this + 0x13EC
```

e:

```text
[EDI+0x274] + 0x28
```

com valores relacionados a:

```text
[EDI+0x58]
```

Também existem acumuladores locais de 64 bits:

```text
[EBP-0x34]
[EBP-0x30]
```

Estas observações indicam que a função não é simplesmente uma iteração de somente leitura sobre entradas independentes.


## MAPA 24 — MULTITHREAD / AVISO DE CONDIÇÃO DE CORRIDA
### (EM DESENVOLVIMENTO — NÃO FINALIZADO)

O loop de distribuição econômica **não é atualmente seguro para uma paralelização ingênua**.

Conceitualmente:

```text
CPU0 ──┐
CPU1 ──┤
CPU2 ──┤──► ACUMULADORES COMPARTILHADOS
CPU3 ──┘
```

Várias iterações podem modificar os mesmos:

```text
this + 0x8D8 + i*8
this + 0x900 + i*8
this + 0x13E8
this + 0x13EC
```

Portanto, uma abordagem ingênua:

```text
uma thread = uma iteração externa
```

poderia produzir condições de corrida e totais econômicos corrompidos.

Arquitetura preferida:

```text
CPU0 → ACUMULADORES PRIVADOS
CPU1 → ACUMULADORES PRIVADOS
CPU2 → ACUMULADORES PRIVADOS
CPU3 → ACUMULADORES PRIVADOS
                │
                ▼
             COMBINAR
                │
                ▼
       ACUMULADORES ESI COMPARTILHADOS
```

Os atômicos de granularidade fina em torno de cada `ADD/ADC` provavelmente seriam custosos demais para uma simulação que executa continuamente.

Portanto, o primeiro experimento seguro de multithread deveria ser um teste inofensivo de worker thread antes de mover o trabalho econômico para workers paralelos.


## MAPA 25 — HELPER ECONÔMICO `FUN_00969760`

`FUN_00969760` foi investigada como possível worker/helper econômico.

Nomes em português propostos:

```text
AcumularDadosEconomicosElemento
```

ou:

```text
AcumularDadosEconomicos
```

A função realiza muitas operações `+=` sobre o mesmo objeto/estado compartilhado.

Conclusão atual:

```text
NÃO É SEGURA para ser executada concorrentemente sobre o mesmo objeto
sem separar os acumuladores ou utilizar sincronização.
```

Esta é outra indicação de que a economia não pode se tornar multithread simplesmente duplicando as chamadas existentes.


## MAPA 26 — SISTEMA DE WORKERS / THREADS
### (EM DESENVOLVIMENTO — INCOMPLETO)

Foi identificado um mecanismo separado de workers dentro do executável.

### `FUN_00A7AED0`

Nome proposto:

```text
CriarThreadWorker
```

Utiliza a importação:

```text
CreateThread
```

Endereço de importação:

```text
00C8A1A8
```

Parâmetros padrão observados:

```text
lpThreadAttributes = 0
dwStackSize        = 0
lpStartAddress     = FUN_00A7B0C0
lpParameter        = bloco alocado de 8 bytes contendo this
dwCreationFlags    = 0
lpThreadId         = &ESI+4
```

O HANDLE resultante da thread é armazenado em:

```text
[ESI+0x08]
```

e:

```text
[ESI+0x1C]
```

participa do estado de prioridade/controle da thread.


### `FUN_00A7B0C0`

Nome proposto:

```text
EntradaThreadWorker
```

A função:

```text
1. libera o bloco de parâmetros
2. obtém a vtable do objeto worker
3. chega à função de despacho do worker
```

Slot virtual importante:

```text
vtable + 0x14
```

Aponta para:

```text
FUN_00A7B090
```


### `FUN_00A7B090`

Este é o wrapper/despachante do worker.

```asm
00A7B090  PUSH ESI
00A7B091  MOV ESI,ECX
00A7B093  CALL [GetCurrentThreadId]

00A7B099  CMP EAX,[ESI+0x0C]
00A7B09C  JNZ 00A7B0A2

00A7B09E  XOR EAX,EAX
00A7B0A0  POP ESI
00A7A0A1  RET

LAB_00A7B0A2:

00A7B0A2  MOV ECX,[ESI+0x18]
00A7B0A5  MOV EAX,[ECX]
00A7B0A7  MOV EDX,[EAX+0x4]
00A7B0AA  CALL EDX

00A7B0AC  MOV EAX,1
00A7B0B1  POP ESI
00A7B0B2  RET
```

Observação importante:

```text
[ESI+0x18]
       ↓
objeto que contém outra vtable
       ↓
vtable + 0x04
       ↓
CORPO REAL DO WORKER
```

Portanto, `FUN_00A7B090` em si não é necessariamente a função custosa do worker.


### Vtable do worker

Em:

```text
00E439F8
```

entradas observadas:

```text
+0x00 → 00A7AED0
+0x04 → 005A9600
+0x08 → 00A7B030
+0x0C → 00A7B040
+0x10 → 00A7B060
+0x14 → 00A7B090
+0x18 → 00A7AE80
```

`FUN_00A7AE80` parece se encarregar de limpeza/espera/destruição.

O corpo exato do worker ainda precisa ser identificado.


## MAPA 27 — TICK ECONÔMICO PERIÓDICO

### `FUN_006859C0`

Nome proposto:

```text
ProcessarTickEconomicoMensal
```

Alternativa:

```text
ExecutarAtualizacaoPeriodicaEconomicaCidade
```

A evidência atual indica fortemente que esta função é uma atualização econômica/de calendário recorrente e não uma rotina de inicialização executada uma única vez.

### Evidência temporal/calendário

Código observado:

```c
iVar14 = (*(int *)(param_1 + 0xb0c) + -43800000) / 0x18;
```

A função utiliza dados relacionados ao calendário e tabelas paralelas:

```text
DAT_00F1027C
DAT_00F10280
```

junto com cálculos de anos bissextos / duração do ano.

Isso sugere fortemente que a função determina um período do calendário como:

```text
dia
mês
estação
```

para o processamento econômico periódico.

### Evidência RNG

Estado observado:

```text
DAT_00F0F6B0
```

com:

```text
DAT_00F0F6B0 =
    (DAT_00F0F6B0 + 1) % 0x270
```

e:

```text
0x270 = 624
```

o que corresponde ao tamanho de estado associado ao MT19937.

A função também gera muitos valores temporários em:

```text
auStack_1090
```

Isso sugere que o processamento econômico periódico pode utilizar valores pseudoaleatórios para variações econômicas ou outros cálculos relacionados à simulação.

### Iteração de entradas econômicas

A função itera sobre uma estrutura/lista associada a:

```text
param_1 + 0xADC
param_1 + 0xAE0
```

e acessa campos em torno de:

```text
0xE78
0xE7C
0xE80
0xE84
0xE88
```

Múltiplos acumuladores de 64 bits são mantidos.

Acumuladores locais observados:

```text
uStack_98
uStack_A8
uStack_60
uStack_58
uStack_50
uStack_68
uStack_B0
```

Isso representa ao menos várias categorias econômicas independentes.

O significado semântico exato de todas as categorias ainda não está confirmado.

### Relatório econômico histórico

A função atualiza:

```text
DAT_00F20BFC
```

e utiliza:

```text
iVar18 = DAT_00F20BFC * 0x70;
```

O stride de `0x70` bytes sugere fortemente um registro de relatório econômico de tamanho fixo.

Área global relevante:

```text
DAT_012624E8
```

com estruturas próximas em torno de:

```text
DAT_012624A8
...
DAT_012624F4
```

Hipótese atual:

```text
g_HistoricoRelatorioEconomico[2]
```

e:

```text
g_SlotRelatorioEconomicoAtivo
```

para:

```text
DAT_00F20BFC
```

Isso parece consistente com um snapshot de histórico econômico duplamente armazenado / alternado.

### Fluxo econômico

Conceitualmente:

```text
CALENDÁRIO / TEMPO
      │
      ▼
DETERMINAR PERÍODO
      │
      ▼
ITERAR ENTRADAS ECONÔMICAS
      │
      ├── categoria A
      ├── categoria B
      ├── categoria C
      ├── categoria D
      ├── categoria E
      ├── categoria F
      └── categoria G
      │
      ▼
ACUMULAÇÃO DE 64 BITS
      │
      ▼
RELATÓRIO ECONÔMICO
      │
      ▼
REGISTRO DE 0x70 BYTES
      │
      ▼
BUFFER HISTÓRICO
```

O significado exato de cada categoria ainda precisa ser estabelecido rastreando os campos de origem nos offsets correspondentes.

### Chamadas relacionadas

A função foi observada no contexto de chamadas como:

```text
AtualizarEconomia (00489990)
ReconstruirListasEconomicas (0068d250)
ControleTempoAtualizacao (00685620)
```

Isso reforça a conclusão de que pertence à camada de atualização econômica/periódica da simulação.

### Conclusão atual

`FUN_006859C0` deve ser tratada atualmente como:

```text
ATUALIZAÇÃO ECONÔMICA / DE CALENDÁRIO PERIÓDICA
```

com o nome de trabalho:

```text
ProcessarTickEconomicoMensal
```

A palavra "mensal" continua sendo uma hipótese de trabalho até confirmar completamente as transições do calendário.


# MAPA 28 — ESTRUTURA DO RELATÓRIO ECONÔMICO

Hipótese atual:

```text
DAT_012624E8
       │
       ▼
HISTÓRICO DE RELATÓRIOS ECONÔMICOS
       │
       ├── SLOT 0
       │
       └── SLOT 1
```

Cada registro parece ocupar:

```text
0x70 bytes
```

O slot ativo é controlado por:

```text
DAT_00F20BFC
```

e o offset selecionado:

```text
DAT_00F20BFC * 0x70
```

Interpretação potencial:

```text
RelatorioEconomico
{
    categoria_0;
    categoria_1;
    categoria_2;
    categoria_3;
    categoria_4;
    categoria_5;
    categoria_6;
    ...
}
```

O significado exato dos campos continua pendente.

Importante:

```text
OS NOMES DAS CATEGORIAS AINDA NÃO ESTÃO CONFIRMADOS
```

Não deveriam ser rotulados prematuramente como impostos, salários, comércio, juros, etc., até que os campos de origem e seus consumidores sejam rastreados.


# MAPA 29 — TICK ECONÔMICO PERIÓDICO VS MERCADO MUNDIAL

A investigação atual distingue ao menos duas camadas econômicas:

```text
                 SISTEMA ECONÔMICO
                       │
          ┌────────────┴────────────┐
          │                         │
          ▼                         ▼
TICK ECONÔMICO PERIÓDICO      MERCADO MUNDIAL
       006859C0                   00482930
          │                         │
          ▼                         ▼
calendário / contabilidade    suprimento / demanda
          │                         │
          ▼                         ▼
relatório econômico           multiplicador
          │                         │
          ▼                         ▼
dados históricos              preço
```

Estão relacionados, mas não deveriam ser tratados como a mesma função.

A rota de preço do mercado é especificamente:

```text
00482930 → 00482B...
```

enquanto a rota de contabilidade econômica periódica está centrada em torno de:

```text
006859C0
```


# MAPA 30 — SISTEMA DE EMPRÉSTIMOS / JUROS

Função:

```text
00523400
```

Nome proposto:

```text
CalcularJurosEmprestimo
```

Responsabilidades:

```text
cálculo do juro do empréstimo
juro base
juro mínimo
```

O juro base vanilla está associado a:

```text
LOAN_BASE_INTEREST
```

Uma seção previamente identificada corresponde à lógica do juro mínimo / 1%.

As mudanças experimentais do juro base devem ser tratadas separadamente do sistema de preços do mercado.


# MAPA 31 — ÍNDICE DE FUNÇÕES DO MERCADO / ECONOMIA

```text
┌────────────┬───────────────────────────────────────────────────┐
│ Endereço   │ Função / Papel                                    │
├────────────┼───────────────────────────────────────────────────┤
│ 0068BF00   │ AtualizarGerenciadorEconomicoCompleto            │
│ 00520150   │ CalcularDistribuicaoEconomica                    │
│ 006859C0   │ ProcessarTickEconomicoMensal                     │
│ 004808D0   │ ProcessarMercadoEDistribuicaoBens                │
│ 00482930   │ AtualizarSuprimento                              │
│ 00482B...  │ AtualizarPreco                                   │
│ 00487410   │ ProcessarSuprimentoEDemandaDoBem                 │
│ 0047DC20   │ AcumularValorIndexadoBuffer                      │
│ 0047DCA0   │ SubtrairStockpileArtesaoFabrica                  │
│ 0047DE60   │ Buffer_EscalarValoresNoIntervalo                 │
│ 0047D9E0   │ Limitar                                           │
│ 0047E3E0   │ Mercado_CalcularProdutoEscalarEscalonado          │
│ 0043A880   │ redimensionar_vetor                               │
│ 004DD470   │ Multiplicar bens + limitar 0..99999               │
│ 00485E40   │ Atualização econômica diária de POP               │
│ 00523400   │ Juros de empréstimos                              │
│ 0054C600   │ intro_sort                                         │
└────────────┴───────────────────────────────────────────────────┘
```


# PARTE VII — SISTEMA DE CARREGAMENTO / INICIALIZAÇÃO DO JOGO

## MAPA 32 — `FUN_00662010`

Nome proposto:

```text
FinalizarCarregamentoJogoEEntrarNaPartida
```

Conclusão atual:

```text
FINALIZAÇÃO DE CARREGAMENTO ÚNICA / INICIALIZAÇÃO DO JOGO
```

Esta função parece ser executada após o carregamento/inicialização e antes de o jogo entrar no gameplay normal.

Não deve ser confundida com o tick econômico recorrente.


## MAPA 33 — ESTADO DE CARREGAMENTO

Ao entrar:

```asm
MOV dword ptr [EBX + 0x1E08],0x3
```

Interpretação de trabalho:

```text
EBX + 0x1E08
    ↓
fase de carregamento / inicialização
```

Nome proposto:

```text
m_FaseCarregamento
```

Os valores exatos da enumeração ainda não estão confirmados.


## MAPA 34 — INICIALIZAÇÃO DE TELA / RESOLUÇÃO

A função lê campos relacionados à resolução de objetos em torno de:

```text
ESI + 0x64
ESI + 0x68
```

e armazena valores em:

```text
EBX + 0x1E10
EBX + 0x1E14
EBX + 0x1E18
```

Nomes de trabalho:

```text
EBX + 0x1E10 → m_LarguraTela
EBX + 0x1E14 → m_AlturaTela
EBX + 0x1E18 → m_ProporcaoDeAspectoEscalada
```

Se os objetos de resolução esperados não estiverem disponíveis, a função recorre à leitura de dados de configuração a partir de um stream.


## MAPA 35 — INICIALIZAÇÃO DE VINCULAÇÕES DE ENTRADA / EVENTOS

A função chama repetidamente:

```text
ResolverOuRegistrarEvento
```

utilizando diferentes chaves de string.

Isso parece resolver/registrar vinculações configuráveis de entrada ou eventos.

Os nomes exatos dos eventos/chaves ainda estão sendo reconstruídos.


## MAPA 36 — REDEFINIÇÃO DO ESTADO DE ENTIDADES

A função itera sobre entidades/edifícios e limpa um campo de estado:

```asm
*(EDI + 0x0C) = 0
```

Conceitualmente:

```text
PARA CADA ENTIDADE
    |
    ▼
REDEFINIR FLAG DE EXECUÇÃO
```

Isso é consistente com restaurar/reconstruir o estado de execução após o carregamento.


## MAPA 37 — CADEIA DE INICIALIZAÇÃO DE SUBSISTEMAS

Uma longa sequência de chamadas de inicialização é realizada sobre o mesmo objeto principal.

Funções observadas:

```text
FUN_00521560
FUN_0050E540
FUN_005068F0
FUN_00521FD0
FUN_0050EA30
FUN_00530E40
FUN_0052FCD0
FUN_0051C890
FUN_005143B0
FUN_00517AF0
FUN_0051EB40
```

Atualmente devem ser tratadas como:

```text
CADEIA DE INICIALIZAÇÃO DE SUBSISTEMAS
```

Suas funções individuais exatas ainda precisam ser mapeadas.


## MAPA 38 — REPARO DE ID / INTEGRIDADE DE ENTIDADES

A função verifica um campo de entidade em torno de:

```text
+0x34
```

e pode atribuir um novo valor se for zero.

O valor resultante é limitado a:

```text
0x186A0
```

que equivale a:

```text
100000
```

Conceitualmente:

```text
ID DE ENTIDADE
   │
   ├── já válido → manter
   │
   └── zero → atribuir novo valor
                 │
                 ▼
              limitar
              100000
```

Isso parece ser um mecanismo de integridade/reconstrução pós-carregamento.


## MAPA 39 — CACHE DE CONFIGURAÇÃO

O último bloco grande constrói repetidamente chaves de string e realiza buscas.

Os objetos de configuração resultantes são armazenados em cache em campos do objeto principal.

Offsets de destino observados incluem exemplos como:

```text
EBX + 0x11C8
EBX + 0x1268
EBX + 0x12B8
EBX + 0x1308
...
```

Conceitualmente:

```text
CHAVE DE STRING
    │
    ▼
BUSCA DE CONFIGURAÇÃO
    │
    ▼
OBJETO DE CONFIGURAÇÃO
    │
    ▼
SALVAR PONTEIRO NO CACHE DE EBX
```

Provavelmente isso existe para evitar buscas repetidas baseadas em strings durante a execução.


## MAPA 40 — SINCRONIZAÇÃO DE TOGGLES DO JOGO

A função lê um campo de bits em torno de:

```text
EBX + 0x7E0
```

e utiliza o resultado para selecionar/configurar diferentes opções.

Vários offsets adjacentes são utilizados:

```text
+0x4
+0x8
+0xC
+0x10
+0x14
...
```

Nome de trabalho:

```text
m_FlagsToggleGameplay
```

Essas flags são sincronizadas com objetos de configuração.

Os nomes semânticos exatos de cada bit continuam pendentes.


## MAPA 41 — OBJETO GRANDE DE UI / OVERLAY

A função aloca um objeto de aproximadamente:

```text
0x3C0 bytes
```

e o inicializa utilizando o estado de configuração.

Um campo em torno de:

```text
+0x3B8
```

é lido como booleano/toggle.

Hipótese de trabalho:

```text
controlador de minimapa / overlay / câmera
```

Isso continua sem confirmação.


## MAPA 42 — REGISTRO EM GRADE ESPACIAL

Quando não está em execução no modo headless relevante, as entidades são registradas em uma estrutura espacial.

Estado importante:

```text
DAT_012588E8 + 0xD11
```

Se o modo relevante estiver inativo:

```text
para cada entidade
    |
    +-- entity->0x1D0 = EBX
    |
    +-- FUN_00407B10
    |
    +-- FUN_0068F390
```

`FUN_0068F390` é particularmente interessante porque também apareceu em processamento econômico/de entidades anterior.

Interpretação de trabalho:

```text
ENTIDADE
   ↓
REGISTRO ESPACIAL / BUCKET
   ↓
GRADE DE SIMULAÇÃO / RENDERIZAÇÃO
```


## MAPA 43 — MEDIÇÃO DO TEMPO DE CARREGAMENTO

A função realiza uma subtração de timestamps:

```text
FLD
FSUB
```

e escreve o valor resultante em um stream/log.

Isso é consistente com:

```text
TEMPO DE CARREGAMENTO
```


## MAPA 44 — ENTRAR NO GAMEPLAY

Perto do final:

```text
FUN_006480A0(EBX)
FUN_00648040(EBX,0xB,-1)
```

Ocorre uma transição de estado para:

```text
0xB
```

Interpretação de trabalho:

```text
CARREGAMENTO / INICIALIZAÇÃO
        ↓
ESTADO = 0xB
        ↓
GAMEPLAY
```

O nome exato do enum de estado ainda não está confirmado.


## MAPA 45 — CALLBACKS DE INÍCIO DE SUBSISTEMAS

Um loop final processa aproximadamente 32 slots de callbacks:

```text
for ESI = 0; ESI < 0x20; ESI += 4
```

Cada subsistema registrado é obtido através de:

```text
EBX + 0xD80 + ESI
```

e executa um callback virtual em torno de:

```text
vtable + 0x24
```

Conceitualmente:

```text
O JOGO ENTRA NO GAMEPLAY
        │
        ▼
32 SLOTS DE SUBSISTEMAS
        │
        ├── callback
        ├── callback
        ├── callback
        ├── ...
        └── callback
```

Isso se parece com um mecanismo de broadcast:

```text
AoIniciarJogo
AoCarregarNivel
```

mas o nome exato do evento ainda não está confirmado.


# PARTE VIII — FUNÇÕES DE UTILIDADE / HELPERS RENOMEADAS

```text
FUN_0043AB60
    CopiarMemoriaSobreposta
    → zero_struct_array
    → parece específica para arrays int64

FUN_00AAD56B
    ValidarTamanhoMemoria
    → possível operator new / helper de alocação

FUN_0041A160
    InicializarEstruturaComValoresPadrao
    → ctor_with_MTTH
    → provavelmente construtor de eventos

FUN_0096BBF0
    ConstruirSingleton
    → create_string_with_length("null_pop",8)
    → vtable.CAddAIStrategyEffect.138
    → possivelmente relacionado à IA de países

thunk_FUN_00AB4D81
    VerificarEstadoStream
    → __ptmbcinfo
    → verifica MBCS / página de códigos local

FUN_0047DB00
    CopiarERedimensionarBuffer
    → construtor de cópia CGoodsPool

fcn.004F50C0
    DecaimentoFabricaSemInsumos
    → diminuição do nível de fábrica quando faltam insumos
```


# PARTE IX — ESTRUTURA GERAL DO MOTOR

```text
00AB0F91
  ENTRADA
    |
    v
009DF550
  LOOP PRINCIPAL
    |
    v
009796B0
  WINMAIN / MOTOR CLAUSEWITZ
    |
    +-- TEMPO
    |     |
    |     +-- 00685620
    |     +-- 00682BD0
    |
    +-- ECONOMIA
    |     |
    |     +-- 0068BF00
    |     +-- 00520150
    |     +-- 006859C0
    |     +-- 00482930
    |     +-- 00482B...
    |
    +-- MERCADO
    |     |
    |     +-- SUPRIMENTO
    |     +-- DEMANDA
    |     +-- PREÇO
    |     +-- STOCKPILES
    |
    +-- IA
    |     |
    |     +-- VerificarLimiarSimplesIA
    |     +-- SISTEMA_DE_EVENTOS
    |
    +-- CONSOLE
    |     |
    |     +-- console_commands
    |
    +-- RENDERIZAÇÃO / NEBLINA DE GUERRA
    |     |
    |     +-- FUN_0099da20
    |     +-- FUN_006592f0
    |
    +-- EMPRÉSTIMOS
    |     |
    |     +-- 00523400
    |
    +-- CARREGAMENTO DO JOGO
    |     |
    |     +-- 00662010
    |
    +-- THREADS
    |     |
    |     +-- 00A7AED0
    |     +-- 00A7B0C0
    |     +-- 00A7B090
    |
    +-- OUTROS SISTEMAS
          |
          +-- Guerra
          +-- POPs
          +-- Países
          +-- Pesquisa
          +-- Diplomacia
          +-- Eventos
          +-- Mercado
          +-- Renderização
```


# PARTE X — CONCLUSÕES IMPORTANTES DE ENGENHARIA REVERSA

## ECONOMIA

A economia não é uma única função.

É composta por múltiplas camadas:

```text
GERENCIADOR ECONÔMICO
       │
       ├── distribuição econômica
       │
       ├── reconstrução de listas econômicas
       │
       ├── processamento do mercado
       │
       ├── suprimento/demanda
       │
       ├── cálculo de preços
       │
       ├── contabilidade periódica
       │
       ├── atualizações econômicas de POPs
       │
       └── processamento de entradas econômicas
```

A rota de preço de mercado confirmada mais importante continua sendo:

```text
SUPRIMENTO
  ↓
DEMANDA
  ↓
COMPARAÇÃO
  ↓
DIVISÃO DE INT64 COM SINAL
  ↓
MULTIPLICADOR DE SUPRIMENTO
  ↓
PREÇO
  ↓
LIMITES MÍNIMO/MÁXIMO
```


## STOCKPILES

Os bens utilizam uma combinação de:

```text
bitflags / índices posicionais
+
vetor de stockpile de 64 bits
```

O vetor de stockpile utiliza:

```text
entradas de 8 bytes
```

e, portanto, permite quantidades grandes além de uma representação simples de inteiro de 32 bits.


## MODIFICAÇÃO DE PREÇOS

A estratégia de modificação mais segura é:

```text
NÃO SUBSTITUIR:
Suprimento
Demanda
Comparação
Divisão
Multiplicador

MODIFICAR SOMENTE:
Limite mínimo
Limite máximo
```

Desejado:

```text
0.2 → 0.1
5.0 → 10.0
```


## PROCESSAMENTO ECONÔMICO PERIÓDICO

`FUN_006859C0` parece ser uma rotina periódica de contabilidade econômica/calendário.

Nome de trabalho:

```text
ProcessarTickEconomicoMensal
```

mas o período exato ainda requer uma confirmação final do calendário.

Parece realizar:

```text
determinar período do calendário
        ↓
processar entidades econômicas
        ↓
acumular categorias econômicas
        ↓
atualizar relatório econômico histórico
```


## INICIALIZAÇÃO DE CARREGAMENTO

`FUN_00662010` parece ser uma rotina de execução única:

```text
FinalizarCarregamentoJogoEEntrarNaPartida
```

Realiza:

```text
transição do estado de carregamento
configuração de resolução
carregamento de configuração
registro de entrada/eventos
redefinição de entidades
inicialização de subsistemas
reparo de integridade de entidades
cache de configuração
registro espacial
medição do tempo de carregamento
transição ao estado de gameplay
callbacks de subsistemas
```

Não deve ser confundida com o processamento recorrente de economia/ticks.


## MULTITHREAD

O executável já contém um framework genérico de workers:

```text
CreateThread
    ↓
FUN_00A7AED0
    ↓
FUN_00A7B0C0
    ↓
FUN_00A7B090
    ↓
corpo virtual do worker
```

No entanto, o processamento econômico contém acumuladores compartilhados.

Portanto:

```text
EXISTÊNCIA DE UM SISTEMA DE THREADS
        ≠
A ECONOMIA JÁ É PARALELA
```

e:

```text
ADICIONAR THREADS DIRETAMENTE À ECONOMIA
        ↓
PROVAVELMENTE PRODUZIRÁ CONDIÇÕES DE CORRIDA
```

Os acumuladores privados seguidos de uma combinação/merge são o design seguro a longo prazo.


# NOTAS

```text
+-- Os nomes das funções de eventos continuam sendo tentativos até
|   confirmar completamente seus XREFs.
|
+-- 008A67B0 parece estar relacionado ao carregamento/gerenciamento de
|   recursos de eventos, mas ainda não está confirmado como o ponto
|   principal de execução de eventos.
|
+-- VerificarLimiarSimplesIA parece estar relacionado a verificações que
|   podem interagir com o sistema de eventos.
|
+-- Remover chamadas do sistema de eventos permitiu que algumas batalhas
|   começassem, mas o jogo posteriormente travou após vários dias.
|
+-- Portanto, o processamento de eventos provavelmente participa de
|   manutenção/processamento posterior.
|
+-- A economia deve preservar:
|      Suprimento → Demanda → Comparação → Divisão →
|      Multiplicador → Preço → Limites
|
+-- console_commands está confirmado empiricamente como o dispatcher
|   central do console. Desabilitá-lo elimina todos os comandos de console.
|
+-- O comando "fow" alterna DAT_013f080c, mas mudar somente a flag
|   global não é suficiente para forçar a Neblina de Guerra
|   permanentemente desativada.
|
+-- Os patches diretos JZ→NOP nas funções de renderização quebram suas
|   respectivas camadas de renderização.
|
+-- FUN_006592f0 requer uma inspeção adicional da condição anterior
|   em torno de 0x6594B4 antes de tentar um patch final de Neblina de
|   Guerra.
|
+-- Helpers genéricos como Buffer_EscalarValoresNoIntervalo,
|   Mercado_CalcularProdutoEscalarEscalonado e as rotinas de limitação
|   são amplamente reutilizados e não deveriam ser considerados
|   automaticamente específicos do mercado.
|
+-- 00487410 está confirmado como uma função do lado da demanda na
|   rota inspecionada.
|
+-- 0047DCA0 confirma a relação entre os bitflags de bens e o vetor
|   de stockpile de 64 bits.
|
+-- 00520150 contém acumuladores econômicos compartilhados e, portanto,
|   não deveria ser paralelizada de forma ingênua.
|
+-- FUN_00969760 realiza acumulação econômica compartilhada e
|   atualmente é considerada insegura para execução concorrente sobre
|   o mesmo objeto.
|
+-- O framework de workers existe, mas o corpo real e custoso do worker
|   ainda está sendo rastreado através do objeto localizado em
|   [ESI+0x18].
|
+-- FUN_006859C0 é entendida atualmente como uma rotina periódica de
|   processamento econômico/calendário. "Mensal" continua sendo um
|   nome de trabalho.
|
+-- FUN_00662010 é entendida atualmente como uma rotina de finalização
|   de carregamento do jogo e entrada no gameplay executada uma única
|   vez.
|
+-- A estrutura de relatório econômico de 0x70 bytes e o significado
|   de cada uma de suas categorias continuam pendentes de reconstrução
|   campo por campo.
|
+-- Os patches experimentais devem ser mantidos claramente separados
|   do comportamento vanilla na documentação.
```

