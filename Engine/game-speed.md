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
