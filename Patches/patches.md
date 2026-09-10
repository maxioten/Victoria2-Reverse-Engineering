````markdown
# Patches — Master List

> Dedicated registry of binary patches and experimental modifications.
>
> This file is intentionally separate from the narrative reverse-engineering
> documentation. It records patch locations, original/replacement bytes,
> delivery method, status, and dependencies.
>
> ## Projects
>
> - **V2DLL** — native DLL mod (`V2TechButton.cpp`) loaded as a `lua51.dll` proxy.
> - **Victoria II** — external static EXE patches.
> - **Master EXE Mod Collection** — static `exemods` patches, including economic,
>   reinforcement and version modifications.
>
> **IMPORTANT:** These projects may target different Victoria II executable
> builds. Addresses and offsets must NOT be assumed interchangeable.

---

# 1. Patching Rules

## 1.1 Address types

Ghidra addresses are **Virtual Addresses (VA)**.

They are not automatically file offsets.

Before editing `v2game.exe`:

1. Start from the Ghidra VA.
2. Convert the VA to the correct file offset.
3. Verify the original bytes.
4. Apply only the documented replacement bytes.
5. Re-read the modified location.
6. Test the patch independently.

For V2DLL runtime patches:

```text
Runtime Address = g_base + RVA
````

For static EXE patches:

```text
Ghidra VA → File Offset → v2game.exe
```

---

# 2. V2DLL

## 2.1 Static Byte Patches

Applied by `InstallExePatches()`.

Each patch verifies its expected original bytes before modification.

| #  | Name                                          | Address    | Type        | Before              | After               | Status    |
| -- | --------------------------------------------- | ---------- | ----------- | ------------------- | ------------------- | --------- |
| 1  | `always_add_wargoals`                         | `0x137EFF` | File Offset | `00`                | `02`                | Confirmed |
| 2  | `land_reinforce`                              | `0x1C809B` | File Offset | `89 4C 24 20`       | `90 90 90 90`       | Confirmed |
| 3  | `naval_reinforce`                             | `0x1C7F1C` | File Offset | `89`                | `8B`                | Confirmed |
| 4  | `max_relative_price`                          | `0xA45C28` | RVA         | `~10x`              | `~20x`              | Confirmed |
| 5  | `consciousness_plurality_growth`              | `0x10C5DE` | RVA         | `03`                | `8B`                | Confirmed |
| 6  | `allied_reinforce_150`                        | `0x1D74BE` | RVA         | `B8 E8 03 00 00`    | `B8 DC 05 00 00`    | Confirmed |
| 7  | `build_factory_ignore_colonial_1`             | `0xD0C57`  | RVA         | `0F 94 C1`          | `B1 01 90`          | Confirmed |
| 8  | `build_factory_ignore_colonial_2`             | `0x12FA4E` | RVA         | `0F 94 C0`          | `B0 01 90`          | Confirmed |
| 9  | `build_factory_button_enable_ignore_colonial` | `0x12E977` | RVA         | `7F 5F`             | `90 90`             | Confirmed |
| 10 | `local_supply_factory_ignore_colonial`        | `0xD0E9D`  | RVA         | `7E 35`             | `EB 35`             | Confirmed |
| 11 | `build_factory_ignore_uncivilized_button`     | `0x12E96E` | RVA         | `74 68`             | `90 90`             | Confirmed |
| 12 | `build_factory_checklist_uncivilized_own`     | `0x12EA67` | RVA         | `8A 86 D0 12 00 00` | `B0 01 90 90 90 90` | Confirmed |
| 13 | `build_factory_checklist_uncivilized_other`   | `0x12F0D4` | RVA         | `74 0C`             | `90 90`             | Confirmed |
| 14 | `build_factory_ignore_uncivilized_can_build`  | `0x12CA3E` | RVA         | `75 08`             | `EB 08`             | Confirmed |

### Factory Civilization Dependency

If any of:

```text
#9
#11
#12
#13
#14
```

is enabled, `CivilizeNullCheck` must also be enabled.

Otherwise the game can crash when a country becomes civilized after
having factories enabled by these patches.

---

# 3. V2DLL Vtable Hooks

These modify function pointers rather than instruction bytes.

| Target            | Vtable RVA |       Slot | Method    | Replacement         |
| ----------------- | ---------: | ---------: | --------- | ------------------- |
| `CTechnologyView` | `0xA17FA4` |         11 | `Update`  | `Update0`           |
| `CBudgetView`     | `0xA059F0` |         10 | Tooltip   | `Tip1`              |
| `CProductionView` | `0xA0FECC` |         10 | Tooltip   | `Tip2`              |
| `CPoliticsView`   | `0xA0E458` |         10 | Tooltip   | `Tip3`              |
| `CDecision`       | `0xA29B54` | 6 / `0x18` | `IsValid` | `MyDecisionIsValid` |

---

# 4. V2DLL Code-Cave Hooks

These allocate executable memory with `VirtualAlloc`, write a trampoline,
replay overwritten instructions, and return to the original code.

| Name                     |                             Hook RVA | Overwritten |        Cave |                  Resume | Status              |
| ------------------------ | -----------------------------------: | ----------: | ----------: | ----------------------: | ------------------- |
| `PriceDelta`             |                            `0x82BA9` |         5 B |       128 B |               `0x82BAE` | Confirmed           |
| `OccupiedReinforceSplit` |                           `0x1D751B` |         5 B |        64 B | `0x1D7526` / `0x1D74C5` | Confirmed           |
| `AllyOwnerCheck`         | `0x1D7544` / `0x1D754E` / `0x1D7558` |    6 B each | 64 B shared |                multiple | Confirmed           |
| `CivilizeNullCheck`      |                           `0x14248B` |         7 B |        32 B | `0x142492` / `0x142555` | Confirmed           |
| `GraphPointClamp`        |                           `0x5E0FD6` |        13 B |        48 B | `0x5E0FE3` / `0x5E1159` | Confirmed           |
| `VersionLabel`           |                           `0x233826` |        12 B |        64 B |              `0x233832` | Confirmed           |
| `PopDisplay` topbar      |                           `0x310A32` |         6 B |        64 B |                `hook+6` | Disabled by default |
| `PopDisplay` diplomacy   |                           `0x22880F` |         6 B |        64 B |                `hook+6` | Disabled by default |
| `PopDisplay` lobby       |                           `0x36DFBB` |         6 B |        64 B |                `hook+6` | Disabled by default |

---

# 5. V2DLL Static Trampoline Hooks

These jump directly to already-compiled functions inside the DLL.

| Name                     |   Hook RVA | Overwritten | Resume                  | Status    |
| ------------------------ | ---------: | ----------: | ----------------------- | --------- |
| `ProdListVisibilityHook` | `0x2F424B` |        10 B | `0x2F4255` / `0x2F42DE` | Confirmed |
| `ProdTypeGateHook`       |  `0xD04BC` |        10 B | `0xD04D3` / `0xD04C8`   | Confirmed |

---

# 6. V2DLL Runtime UI Hooks

These are runtime subscriptions, not EXE patches.

| Function                  | Target                           | Purpose                            |
| ------------------------- | -------------------------------- | ---------------------------------- |
| `SetupButtons`            | `CTechnologyView`, `CBudgetView` | Adds decision buttons              |
| `SetupHideColonialButton` | `CProductionView`                | Controls colonial-state visibility |

---

# 7. Victoria II RE 

Static file-offset patches applied by an external launcher.

## 7.1 Confirmed Patches

### World Market Throttle

* VA: `00484309`
* Action: remove/NOP call
* Status: **CONFIRMED**

Purpose:

```text
Remove World Market throttle call.
```

---

### AI Civilization Restriction

* VA: `00859755`
* Original:

```text
0F 84 B5 05 00 00
```

* Instruction:

```asm
JZ LAB_00859D10
```

* Patch:

```text
90 90 90 90 90 90
```

* Status: **CONFIRMED**

Purpose:

```text
Remove civilization-based restriction from AI technology processing.
```

---

### Uncivilized Player Technology

* VA: `007AA757`
* Original:

```text
75 5A
```

* Instruction:

```asm
JNZ LAB_007AA7B3
```

* Patch:

```text
EB 5A
```

* Status: **CONFIRMED**

Purpose:

```text
Allow uncivilized countries to follow the normal player technology
research path.
```

This does not remove:

```text
date checks
technology-state checks
prerequisite checks
```

---

### Price Limits

#### Minimum

```text
DAT_00E45C30
Vanilla:   0.2
Modified:  0.1
```

#### Maximum

```text
DAT_00E45C28
Vanilla:   5.0
Modified:  10.0
```

Status:

```text
Values located and modification tested.
```

The preferred approach is to modify only the final limits while preserving
the vanilla supply/demand calculation pipeline.

---

# 8. Victoria II RE Experimental Patches

These are NOT considered final confirmed patches.

## 8.1 AI Technology Experimental

```text
00859755
90 90 90 90 90 90
```

Observed:

```text
AI continues through technology processing.
```

Status:

```text
EXPERIMENTAL
```

---

## 8.2 Technology JZ Experiment

```text
007AA757

75 5A → 74 5A
```

Observed:

```text
UNCIVILIZED → can research
CIVILIZED   → cannot research
```

Conclusion:

```text
The instruction controls the civilization-dependent branch,
but 74 5A is NOT the final patch.
```

---

## 8.3 Technology List/UI Experiment

Inside:

```text
GenerarListaTecnologias
FUN_007A9700
```

Changing selected:

```text
PUSH 3
PUSH 4
```

to:

```text
PUSH 1
```

produced:

```text
Technology list → visually available
Start Research → still disabled
```

Conclusion:

```text
UI/list state only.
Not the actual research-start gate.
```

---

# 9. Game Speed / Temporal Experiments

## 9.1 Vanilla Update-Time Throttle

```text
DAT_00F0956C
```

Values:

```text
Speed 0 = 0.03
Speed 1 = 0.03
Speed 2 = 0.03
Speed 3 = 0.04
Speed 4 = 0.06
```

These are the documented vanilla throttle values.

---

## 9.2 Temporal Barrier

VA:

```text
00682D0C
```

Original:

```text
0F 84 4B 01 00 00
```

Experimental:

```text
90 90 90 90 90 90
```

Status:

```text
EXPERIMENTAL
```

This was confirmed to be a real temporal-processing barrier.

---

## 9.3 Experimental Code Caves

Tests included:

```text
4.0f via code cave
5.0f involving DAT_00F092FC
0.000001f in DAT_00E45BB8
```

Important:

```text
DAT_00F0956C
```

and:

```text
FUN_00682BD0
```

must be treated as separate temporal systems.

Changing:

```text
DAT_00E45BB8
```

may affect multiple systems because it has multiple XREFs.

---

# 10. Fog of War

## Confirmed Observation

The console command:

```text
fow
```

toggles:

```text
DAT_013F080C
```

and mirrors its value into:

```text
[DAT_01258A74 + 0x6BC44]
```

## Unsafe Experiments

Direct `JZ → NOP` experiments broke rendering layers.

Affected functions:

```text
FUN_0099DA20 → text/UI rendering
FUN_006592F0 → terrain/map textures
```

Therefore:

```text
NO SAFE FINAL FOW PATCH YET
```

Condition requiring further analysis:

```text
0x6594B4
```

Status:

```text
EXPERIMENTAL / UNSAFE
```

---

# 11. Economy / Market Reverse Engineering

Located functions:

| Function                          |    Address | Description         |
| --------------------------------- | ---------: | ------------------- |
| `ActualizarSuministro`            | `00482930` | Supply update       |
| `CalcularMultiplicadorSuministro` | `00482610` | Supply multiplier   |
| `FUN_004808D0`                    | `004808D0` | Under investigation |
| `EconomyManager_UpdateFull`       | `0068BF00` | Full economy update |

Preferred price pipeline:

```text
Supply
  ↓
Demand
  ↓
Comparison
  ↓
Division
  ↓
Supply Multiplier
  ↓
Price
  ↓
Final Limits
```

Do not replace large portions of this pipeline when only the price limits
are required.

---

# 12. Master EXE Mod Collection — v3.05

These are static `exemods` patches.

## 12.1 Exponential Price Change

Hook VA:

```text
00482BA9
```

File offset:

```text
81FA9
```

Cave VA:

```text
00429257
```

Cave file offset:

```text
28657
```

Hook:

```text
81FA9 = E9 A9 66 FA FF
```

Cave:

```text
C1 FA 0F 89 C7 0F AC CF 08
89 3D E0 B9 25 01
89 CF C1 FF 07
89 3D E4 B9 25 01
89 C7
2B 3D E0 B9 25 01
E9 30 99 05 00
```

Status:

```text
DOCUMENTED
```

---

# 13. Master EXE Mod — No Minimum Interest

VA:

```text
005237D2 - 005237E6
```

File offsets:

```text
122BD2
122BDA
```

Patches:

```text
122BD2 = 90 90 90 90 90
```

and:

```text
122BDA = 90 90 90 90 90 90 90 90 90 90 90 90 90
```

Status:

```text
DOCUMENTED
```

Purpose:

```text
Remove minimum interest restriction.
```

---

# 14. Master EXE Mod — Aristocrat Income Share

VA:

```text
004EEA26 - 004EEA41
```

File offsets:

```text
EDE2B - EDE41
```

Modified bytes:

```text
EDE2B = 11
EDE2E = 11
```

NOP regions:

```text
EDE32-EDE35
EDE37-EDE39
EDE3C-EDE41
```

Status:

```text
DOCUMENTED
```

---

# 15. Master EXE Mod — Absolute Price Limits

## Constants

Minimum price:

```text
File Offset: A45028

41 20 00 00 00 00 00 00
```

Maximum price:

```text
File Offset: A45030

40 A0 00 00 00 00 00 00
```

## Logic

VA:

```text
00482B3F - 00482B98
```

File offset:

```text
81F3F - 81F98
```

The patch replaces the original price-limit logic with custom handling and
NOP padding.

Status:

```text
DOCUMENTED
```

---

# 16. Master EXE Mod — Naval Reinforcement Fix

VA:

```text
005C8B1C
```

File offset:

```text
1C7F1C
```

Patch:

```text
89 → 8B
```

Status:

```text
DOCUMENTED / CONFIRMED
```

---

# 17. Master EXE Mod — Land Brigade Reinforcement Fix

VA:

```text
005C8C9B - 005C8C9E
```

File offset:

```text
1C809B - 1C809E
```

Patch:

```text
90 90 90 90
```

Status:

```text
DOCUMENTED / CONFIRMED
```

---

# 18. Master EXE Mod — Version String

Target string:

```text
"V2 v3.05"
```

VA:

```text
00E07653 - 00E07658
```

File offset:

```text
A05C53 - A05C58
```

Documented patch:

```text
A05C53 = 35
```

Status:

```text
DOCUMENTED
```

---

# 19. Code Caves — Victoria II RE

Primary experimental cave:

```text
VA  00C8911A
```

Secondary:

```text
VA  00C89130
```

## Rule

Do not reuse the same cave for incompatible modifications.

A previous speed/throttle experiment reused the same cave and caused
conflicts/crashes.

Each independent code-cave modification should have:

```text
Hook
↓
Cave
↓
Custom logic
↓
Replay overwritten instructions
↓
Resume address
```

---

# 20. VA → File Offset Records

Known conversions for the RE build:

| Ghidra VA  | File Offset           |
| ---------- | --------------------- |
| `00F0956C` | `v2game.exe + B06F6C` |
| `00685691` | `v2game.exe + 284A91` |
| `00685698` | `v2game.exe + 284AA8` |

Additional known mapping:

```text
00F0956C
Imagebase-relative offset: +B0956C
.data-relative offset:     +1756C
```

---

# 21. Checksum System

Function:

```text
FUN_004A1290
```

Status:

```text
WIP
```

Current objective:

```text
Determine checksum initialization, calculation, validation and
possible interaction with modified executable/data.
```

No final checksum bypass patch is documented yet.

---

# 22. Engine Shutdown

Function:

```text
FUN_0067D940
```

Status:

```text
Located / WIP
```

No final patch documented.

---

# 23. Create Substate

Goal:

```text
Create a console command/function analogous to create_vassal,
but producing a substate.
```

Status:

```text
WIP
```

No final binary patch documented.

---

# 24. Patch Status Legend

| Status          | Meaning                                                                                                       |
| --------------- | ------------------------------------------------------------------------------------------------------------- |
| 🟢 CONFIRMED    | Tested and confirmed to produce the intended result                                                           |
| 🟡 EXPERIMENTAL | Tested, but not considered final/safe                                                                         |
| 🔴 WIP          | Investigation still in progress                                                                               |
| ⚪ DOCUMENTED    | Patch is documented from the external patch collection but has not necessarily been independently revalidated |
| ❌ UNSAFE        | Known to break functionality or cause crashes                                                                 |

---

# 25. Important Historical Issues

## Shared Code Cave

Reusing:

```text
00C8911A
```

for incompatible speed/throttle modifications caused conflicts.

Use separate caves for independent hooks.

---

## Factory Colonial Supply Patch

A previously miscalculated patch started at the `JLE` instead of the correct
`CMP` location.

Because other branches shared the same return path, this broke unrelated
branches that jumped to the same `return false`.

Always calculate the complete instruction range before replacing bytes.

---

## ProdTypeGateThunk

A previous implementation with nested push/pop handling caused crashes while
loading saves.

The corrected implementation uses a single ECX save/restore around the
branching logic.

---

## Factory Scan

Expanding the memory scan from:

```text
MEM_PRIVATE
```

to:

```text
MEM_IMAGE / MEM_MAPPED
```

caused:

```text
Failed to create a graphics device
```

The scan was reverted to:

```text
MEM_PRIVATE only
```

---

# 26. Final Safety Checklist

Before applying any patch:

```text
[ ] Identify executable build/version
[ ] Confirm whether address is VA, RVA or file offset
[ ] Convert VA → file offset when editing EXE
[ ] Verify original bytes
[ ] Apply only documented bytes
[ ] Re-read modified bytes
[ ] Test patch independently
[ ] Record result
[ ] Separate confirmed and experimental patches
[ ] Do not reuse incompatible code caves
[ ] Check dependencies before enabling related patches
```

---

# 27. Build Separation Warning

The following must NOT automatically be mixed:

```text
V2DLL addresses
Victoria II RE addresses
Master EXE Collection addresses
```

Even when two patches appear to target the same function, the executable
build must be verified first.

Example:

```text
V2DLL:
0x82BA9 RVA

RE / Master Collection:
VA 0x00482BA9
File Offset 0x81FA9
```

These may refer to related code, but the address conventions and executable
builds are different.

Always verify the actual bytes in the target executable before combining
patches.

```

Además, hay una **corrección importante** respecto al documento anterior: el parche de `007AA757 → EB 5A` ya debe figurar como **CONFIRMED**, porque en la nueva lista lo marcaste explícitamente así. Los cambios `74 5A`, los `PUSH 3/4 → PUSH 1` y los experimentos de velocidad quedan separados como **experimentales**.

También mantendría **Master EXE Mod Collection v3.05 separado de V2DLL**, aunque algunos parches sean funcionalmente equivalentes, porque ahí sí tenemos riesgo de mezclar offsets de builds diferentes.
```
