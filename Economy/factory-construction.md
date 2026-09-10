# Factory Construction Functions

This section documents the functions involved in Victoria II's factory construction checks. The construction system uses multiple independent validation layers: the UI button state, the actual construction gate, state/type availability checks, and production-type restrictions.

## `FUN_0052E960` — `CanBuildFactory`

**Address:** `0x0052E960`

**Purpose:**  
Determines whether the factory construction button should be enabled for the current country and state.

The function returns a boolean value in `AL`:

- `AL = 1` — construction is allowed
- `AL = 0` — construction is blocked

### Main checks

The function performs the following checks:

1. Country civilization status:
   ```asm
   CMP byte ptr [EDI + 0x12D0], 0
   JZ  LAB_0052E9D8
   ```

2. Colonial state restriction:
   ```asm
   CMP dword ptr [EAX + 0x84], 0
   JG  LAB_0052E9D8
   ```

3. Factory limit:
   ```asm
   CMP dword ptr [EAX + 0x68], 8
   JGE LAB_0052E9D8
   ```

4. Additional production/type restrictions through:
   ```asm
   CALL FUN_0052FB40
   ```

5. Additional country/state permissions through fields such as `+0xB20` and `+0xB60`.

### Confirmed patches

The civilization and colonial checks can be bypassed independently.

```cpp
// Allow uncivilized countries to use the factory construction button.
{ "build_factory_ignore_uncivilized_button", 0, 0x12E96E, 2,
    { 0x74, 0x68 },
    { 0x90, 0x90 }, true },

// Allow factory construction in colonial states.
{ "build_factory_button_enable_ignore_colonial", 0, 0x12E977, 2,
    { 0x7F, 0x5F },
    { 0x90, 0x90 }, true },
```

These patches only remove the corresponding early-return conditions. The remaining construction checks are preserved.

---

## `FUN_0052C9B0` — `CanBuildFactoryNow`

**Address:** `0x0052C9B0`

**Purpose:**  
This is the main construction gate used when the game actually evaluates whether a factory can be built.

Unlike `FUN_0052E960`, which primarily determines the state of the `build_factory_button` widget, this function performs the complete construction validation.

### Validation chain

```text
FUN_0052C9B0
│
├── FUN_0052E960
│   └── Basic factory construction/button conditions
│
├── FUN_0052CA30
│   └── State/type availability
│
└── FUN_004DA720
    └── Cost / money validation
```

The function returns:

- `AL = 1` — factory construction is allowed
- `AL = 0` — factory construction is denied

The function therefore represents the actual "can construct now" decision rather than merely the UI state.

---

## `FUN_0052CA30` — `CanBuildFactoryTypeInState`

**Address:** `0x0052CA30`

**Purpose:**  
Checks whether the selected factory/production type is available for construction in the specified state.

The function first performs an independent civilization check:

```asm
CMP byte ptr [EDI + 0x12D0], 0
JNZ LAB_0052CA48

XOR AL, AL
RET 0x8
```

Thus, in the original executable, an uncivilized country fails this check before `FUN_004D04B0` is reached.

### State/type checks

The function then examines the state's production structures through:

```text
state + 0x60
production structure + 0x18
production structure + 0x20
production structure + 0x224
```

It also checks state/type-specific data involving:

```text
country + 0xBCC
+ 0x2FC
state + 0x130
```

Finally, it delegates the general production-type validation to:

```asm
CALL FUN_004D04B0
```

### Confirmed patch

The independent civilization gate can be bypassed:

```cpp
// Allow uncivilized countries to pass the factory construction
// type/state validation.
{ "build_factory_ignore_uncivilized_can_build", 0, 0x12CA3E, 2,
    { 0x75, 0x08 },
    { 0xEB, 0x08 }, true },
```

The original conditional jump:

```asm
CMP byte ptr [EDI + 0x12D0], 0
JNZ LAB_0052CA48
```

is changed to:

```asm
CMP byte ptr [EDI + 0x12D0], 0
JMP LAB_0052CA48
```

This forces both civilized and uncivilized countries onto the same subsequent validation path.

---

## `FUN_0052FB40` — `CheckProductionCountryRequirement`

**Address:** `0x0052FB40`

**Purpose:**  
Performs an additional country/production-type compatibility check used by `FUN_0052E960`.

The function does not appear to be the general factory construction gate. Instead, it validates a specific relationship between the country attempting construction and another country associated with the selected production type.

### Conditions

The function requires:

```text
[EDX + 0x31] != 0
```

The associated country must then satisfy:

```text
[EAX + 0x31] == 0
[EAX + 0x12D0] != 0
[EAX + 0xB60] != 0
```

Finally, a related production record must have:

```text
[record + 0x34] == 0
```

Only when all conditions pass does the function return:

```asm
MOV AL, 1
```

Otherwise it returns:

```asm
XOR EAX, EAX
```

### Important distinction

The civilization check inside this function is **not the same check** as the one in `FUN_0052E960` or `FUN_0052CA30`.

There are two different country objects involved:

```text
EDI / EDX
└── country attempting construction

EAX
└── country associated with the selected production type
```

Therefore, the check:

```asm
CMP byte ptr [EAX + 0x12D0], 0
JZ LAB_0052FB92
```

should not automatically be removed when enabling factories for uncivilized countries. Its exact purpose depends on the identity and role of the second country object.

---

## Construction validation overview

```text
                    Factory Construction
                           │
                           ▼
                 CanBuildFactoryNow()
                    FUN_0052C9B0
                           │
             ┌─────────────┴─────────────┐
             ▼                           ▼
     CanBuildFactory()        CanBuildFactoryTypeInState()
       FUN_0052E960                    FUN_0052CA30
             │                           │
      ┌──────┼──────┐                    ▼
      │      │      │             CanUseProductionType()
      │      │      │                 FUN_004D04B0
      │      │      │
 civilization  colonial          production availability
      │      │
      │      └── factory limit
      │
      └── additional restrictions
             │
             ▼
      FUN_0052FB40
```

This demonstrates that factory construction is not controlled by a single civilization check. Multiple independent functions perform their own validation, which is why removing the first civilization gate alone does not make uncivilized countries fully capable of constructing factories.