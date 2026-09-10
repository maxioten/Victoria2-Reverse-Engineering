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
