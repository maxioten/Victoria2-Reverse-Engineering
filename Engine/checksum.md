# Victoria II Runtime Checksum Documentation

## Overview

This document describes the checksum-related behavior investigated in
the Victoria II executable (`v2game.exe`) using static reverse
engineering in Ghidra.

The investigation identified two different checksum systems:

1.  **The file/history checksum**, used while loading and hashing game
    files.
2.  **The runtime/game-state checksum**, which is involved in
    synchronization or state consistency checks during gameplay and
    transitions.

The important result is that the checksum change observed after clicking
**Resign** and returning to the main menu was not caused by the
file/history checksum routine. It was traced to a counter increment
performed while loading the interface/backend screen.

------------------------------------------------------------------------

## 1. Two Different Checksum Systems

### 1.1 File/history checksum

The file checksum path begins in:

``` text
InitializeHistoryDatabase
VA: 0x006377A0
```

The relevant call chain is:

``` text
InitializeHistoryDatabase
    └── LoadHistoryDirectoryRecursive
          └── FUN_009DA400 (CalculateFileChecksum)
                └── FUN_009939A0 (CalculateFileStreamChecksum)
```

The strings associated with this system include:

``` text
"Checksum is "
"Creating checksum for all files took "
```

Relevant data:

``` text
DAT_00E07D2C = "Checksum is "
DAT_00E07CFC = "Creating checksum for all files took "
```

### 1.2 File checksum algorithm

`FUN_009939A0` reads file data through `PHYSFS_read` and calculates a
Fletcher-style checksum.

The algorithm maintains two accumulators:

``` text
sum1
sum2
```

For every byte:

``` text
sum1 = sum1 + byte
sum1 = sum1 modulo 0xFFFF

sum2 = sum2 + sum1
sum2 = sum2 modulo 0xFFFF
```

The final value is assembled as:

``` text
checksum = (sum1 << 16) | sum2
```

The final combination occurs around:

``` text
VA: 0x00993A5F
VA: 0x00993A64
```

The instruction at `0x00993A64` was originally:

``` asm
OR EAX, EBX
```

It was experimentally changed to:

``` asm
XOR EAX, EAX
```

This forced the return value toward zero, but the checksum observed
after returning to the menu still changed.

### Conclusion

The file/history checksum is not the checksum responsible for the
observed transition-related change.

------------------------------------------------------------------------

## 2. Runtime Checksum / State Consistency Path

A second checksum-related path was found in:

``` text
FUN_00682EC0
```

This function was provisionally named:

``` text
ActualizarMundoYAvanzarTiempo
```

The string:

``` text
DAT_00E0AA1C = "Checksum: "
```

is referenced from this area.

The function compares vectors using:

``` text
FUN_0068F340
```

`FUN_0068F340` is a vector equality/comparison routine. It does not
appear to generate the checksum itself.

A relevant comparison/logging block is located around:

``` text
VA: 0x00683180
```

Representative instructions:

``` asm
MOV EDI, [EBP-0x30]
MOV EAX, [EBP+0x08]
MOV EAX, [EAX+0xB74]
MOV ECX, [EBP+0x0C]
MOV EDX, [ECX]
...
CMP EAX, [EDI+EDX]
JZ  ...
MOV EBX, 0x00E0AA18
```

The branch at:

``` text
VA: 0x006831A0
```

was originally:

``` asm
JZ  ...
```

and was experimentally changed from:

``` text
74 05
```

to:

``` text
EB 05
```

This suppressed the conditional path associated with the
mismatch/logging block, but the checksum still changed.

### Conclusion

The branch at `0x006831A0` is not the root cause. It detects or handles
a difference; it does not prevent the underlying state change that
affects the checksum.

------------------------------------------------------------------------

## 3. Investigation of the Resign Button

The UI command string was identified as:

``` text
DAT_00E0A0AC = "RESIGN"
```

It is referenced by:

``` text
FUN_00676500
FUN_006766A0
```

Another related string is:

``` text
DAT_00E09B88 = "menu_resign_button"
```

However, this string had no useful direct references in the inspected
code.

### `FUN_00676500`

This function compares a command string stored inside an object against
`"RESIGN"`.

If the command matches, it executes:

``` c
(**(code **)(**(int **)(param_1 + 8) + 0x114))();
```

Then it sets:

``` c
*(byte *)(param_1 + 0x64) = 1;
```

Conceptually:

``` text
command == "RESIGN"
    └── call context_object->vtable[0x114 / 4]
    └── mark command as handled
```

The important detail is that the virtual call uses:

``` text
[param_1 + 8]
```

Therefore, the function at `vtable + 0x114` belongs to the **context
object**, not necessarily to the command handler object's own vtable.

### Vtable investigation

`FUN_00676240` initializes an object with:

``` text
DAT_00E0A7E4
```

as its vtable.

One entry was:

``` text
DAT_00E0A7E4 + 0x114 = DAT_00E0A8F8
DAT_00E0A8F8 = 0x009C4300
```

This made `FUN_009C4300` a possible candidate, but it was not proven to
be the actual Resign implementation because the call in `FUN_00676500`
uses the vtable of `[param_1+8]`.

### Conclusion

The Resign handler was identified at the command-dispatch level, but the
actual implementation behind the indirect `vtable + 0x114` call was not
conclusively resolved.

------------------------------------------------------------------------

## 4. The Results Screen and the `EXIT` Button

The observed sequence is:

``` text
Gameplay
    └── Resign
          └── Results/statistics screen
                └── EXIT
                      └── Main menu
```

The results screen displays information such as:

``` text
The World in 1924
```

and includes an:

``` text
EXIT
```

button.

A string search found:

``` text
DAT_00E13C5C = "exit_button"
```

This is much more relevant than system/runtime strings such as:

``` text
"ExitProcess"
"ExitThread"
"CorExitProcess"
"FatalExit"
```

Those system strings are unrelated to the in-game EXIT button.

The results screen introduced an important possibility: the checksum
might change at one of several stages:

``` text
Resign
    └── create final/results screen
          └── display statistics
                └── press EXIT
                      └── return to menu
```

Possible locations included:

1.  Immediately when Resign is activated.
2.  During creation of the results screen.
3.  During screen loading.
4.  When EXIT is pressed.
5.  During cleanup or transition back to the main menu.

The final investigation identified a concrete state mutation during
screen loading.

------------------------------------------------------------------------

## 5. Confirmed Bug: Screen-Load Counter Modifies the Checksum

The confirmed bug is located in the constructor of:

``` text
CBackEndIdler / CReloadDispatcher
```

This class is associated with loading:

``` text
interface/backend.gui
```

It is therefore executed during interface transitions, including
transitions between gameplay, the results screen, and the main menu.

The relevant decompiled statement is:

``` c
*(int *)(param_4 + 0x30) =
    *(int *)(param_4 + 0x30) + 1;
```

The object:

``` text
param_4
```

is the checksum accumulator/context object.

The field:

``` text
param_4 + 0x30
```

is the counter being modified.

### Exact assembly

The exact instruction sequence is:

``` asm
005F8262: MOV ECX, [EBP+0x14]
005F8265: MOV EAX, [ECX+0x30]
005F8268: INC EAX
005F8269: MOV [ECX+0x30], EAX
```

Equivalent C code:

``` c
int value = *(int *)(param_4 + 0x30);
value++;
*(int *)(param_4 + 0x30) = value;
```

The critical instruction is:

``` asm
005F8268: INC EAX
```

Opcode:

``` text
40
```

This is the instruction that increments the checksum-related counter.

### Why this changes the checksum

The counter at:

``` text
[param_4 + 0x30]
```

is part of the data used by the runtime checksum/state accumulator.

Every time the backend interface is loaded, the counter is incremented:

``` text
backend.gui load
    └── param_4->field_0x30++
          └── runtime checksum changes
```

This explains why returning to the menu can produce a different checksum
even when the underlying game state has not meaningfully changed.

The screen transition itself causes another load, and the load counter
becomes different.

------------------------------------------------------------------------

## 6. Why the Bug Was Initially Misleading

The observed behavior looked like:

``` text
Resign → results screen → EXIT → menu → checksum changed
```

That made the Resign command or the results screen appear to be the
direct cause.

However, the actual cause is more indirect:

``` text
Resign/menu transition
    └── interface/backend.gui is loaded
          └── CBackEndIdler/CReloadDispatcher constructor runs
                └── [param_4 + 0x30] is incremented
                      └── checksum changes
```

Therefore, the bug is not necessarily that Resign itself modifies the
checksum. The transition caused by Resign loads interface resources, and
the loader increments a field that contributes to the checksum.

------------------------------------------------------------------------

## 7. Safe Patch

The smallest patch is to remove only the increment.

### Original

``` asm
005F8268: INC EAX
```

Bytes:

``` text
40
```

### Patched

``` asm
005F8268: NOP
```

Bytes:

``` text
90
```

The resulting sequence is:

``` asm
005F8262: MOV ECX, [EBP+0x14]
005F8265: MOV EAX, [ECX+0x30]
005F8268: NOP
005F8269: MOV [ECX+0x30], EAX
```

This preserves the original instruction length and leaves the read/write
structure intact.

Equivalent behavior after patching:

``` c
int value = *(int *)(param_4 + 0x30);
*(int *)(param_4 + 0x30) = value;
```

The counter is no longer incremented by this constructor.

### Why `NOP` is preferred

`INC EAX` is one byte, so replacing it with one-byte `NOP`:

``` text
40 → 90
```

does not disturb any following instruction addresses or control flow.

Do not replace the entire block unless further testing proves that the
read/write operations themselves are harmful.

------------------------------------------------------------------------

## 8. File Offset Conversion

The Ghidra address is a virtual address:

``` text
VA: 0x005F8268
```

For this executable, the previously established conversion is:

``` text
file offset = VA - 0x00400000
```

Therefore:

``` text
0x005F8268 - 0x00400000 = 0x001F8268
```

Patch table:

  Item                                   Value
  ------------------------ -------------------
  Ghidra virtual address          `0x005F8268`
  File offset                     `0x001F8268`
  Original byte                           `40`
  New byte                                `90`
  Assembly change            `INC EAX` → `NOP`

Before applying the patch, verify directly in the executable's
hexadecimal view that:

``` text
file offset 0x001F8268 = 40
```

If the byte is not `40`, do not apply the patch until the PE section
mapping and offset conversion are rechecked.

------------------------------------------------------------------------

## 9. Recommended Test Procedure

Test the patch in isolation.

1.  Restore a clean/original `v2game.exe`.

2.  Apply only:

    ``` text
    file offset 0x001F8268: 40 → 90
    ```

3.  Start a game.

4.  Record the checksum.

5.  Click **Resign**.

6.  On the results screen, click **EXIT**.

7.  Return to the main menu.

8.  Check the checksum again.

### Expected result

The checksum component affected by:

``` text
[param_4 + 0x30]++
```

should no longer change because of this specific screen-load counter
increment.

The complete checksum may still change if other independent fields or
transition events also contribute to it.

This patch does not disable the checksum system globally. It only
removes one confirmed unwanted increment.

------------------------------------------------------------------------

## 10. Current Knowledge and Remaining Unknowns

### Confirmed

-   The file/history checksum uses a Fletcher-style algorithm.
-   The file/history checksum is not the checksum observed changing
    after returning to the menu.
-   `FUN_00682EC0` contains runtime checksum/state comparison logic.
-   `FUN_006831A0` is not the root cause of the observed change.
-   `"RESIGN"` is handled by `FUN_00676500`.
-   The actual Resign action is reached through an indirect virtual call
    at `vtable + 0x114`.
-   The results screen contains an in-game `"exit_button"` identifier.
-   The constructor of `CBackEndIdler/CReloadDispatcher` increments
    `[param_4 + 0x30]`.
-   The exact increment is located at `VA 0x005F8268`.
-   The minimal patch is `40 → 90`.

### Not conclusively resolved

-   The exact concrete function behind the Resign handler's indirect
    `vtable + 0x114` call.
-   Whether additional checksum-affecting fields are modified during the
    results-screen transition or menu cleanup.
-   Whether the full checksum becomes completely stable after the
    counter patch or only its first affected component becomes stable.
-   The complete structure and purpose of every field in the runtime
    checksum accumulator.

------------------------------------------------------------------------

## 11. Suggested Patch Name

Recommended identifier:

``` text
CBackEndIdler_ChecksumLoadCounterFix
```

Short description:

``` text
Removes the increment of the runtime checksum accumulator's
screen-load counter in CBackEndIdler/CReloadDispatcher.

Original:
VA 0x005F8268: INC EAX
Bytes: 40

Patched:
VA 0x005F8268: NOP
Bytes: 90

File offset:
0x001F8268
```

------------------------------------------------------------------------

## Final Summary

The checksum change observed after returning to the main menu was traced
to a screen-loading side effect.

The important chain is:

``` text
Menu/game transition
    └── load interface/backend.gui
          └── construct CBackEndIdler/CReloadDispatcher
                └── read [param_4 + 0x30]
                └── increment it
                └── write it back
                      └── runtime checksum changes
```

The confirmed bug is:

``` asm
005F8268: INC EAX
```

The minimal fix is:

``` asm
005F8268: NOP
```

with the file-offset patch:

``` text
0x001F8268: 40 → 90
```

This is a targeted fix for the unwanted screen-load counter
contribution, not a global checksum bypass.
