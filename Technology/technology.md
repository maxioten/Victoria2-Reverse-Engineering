# Victoria II Technology Research System

Static reverse-engineering map of the Victoria II technology research system, based on `v2game.exe` analysis in Ghidra.

## 1. System Overview

Technology research is split across several components rather than being controlled by one function:

- technology-list generation;
- technology visual state;
- `"start"` action processing;
- availability checks;
- blocking-reason generation;
- AI research processing;
- country rank/classification.

The main field used to distinguish civilized and uncivilized countries is:

```text
country + 0x12D0
```

Identified as:

```text
is_civilised
```

Values:

```text
0 = Uncivilized
1 = Civilized
```

## 2. Main Functions

| VA | Name | Role |
|---|---|---|
| `00569920` | `ComprobarDisponibilidadTecnologia` | Checks whether a technology is available |
| `005699B0` | `GenerarMotivoBloqueoTecnologia` | Generates/formats blocking reasons |
| `007AA580` | `ActualizarEstadoTecnologiaUI` | Builds technology UI states/messages |
| `007AA890` | `ProcesarAccionTecnologia` | Processes technology-view actions, including `"start"` |
| `007A9700` | `GenerarListaTecnologias` | Generates/processes technology entries |
| `007A9950` | `ActualizarEstadoTecnologia` | Processes technology-state information |
| `005467E0` | `GenerarTextoTecnologia` | Generates technology-related text |
| `005379E0` | `ObtenerRangoPais` | Determines country rank/classification |
| `00859710` | `ProcesarInvestigacionIA` | Processes AI technology research |
| `00859610` | `ActualizarInvestigacionIA` | AI research updater/scheduler |
| `0058AD00` | `InicializarSistemaTecnologias` | Technology-system initialization |

## 3. Technology Availability

`FUN_00569920` returns its result through `AL`:

```text
AL = 0 → unavailable
AL = 1 → available
```

It checks normal technology requirements.

### Date requirement

```asm
CMP [ESI+0x340],EDX
JLE ...
```

`ESI + 0x340` is associated with the technology's temporal requirement.

### Technology state

```asm
MOV EAX,[ESI+0x2E4]
MOV ECX,[EDI+0x2B8]
CMP dword ptr [ECX+EAX*4],1
```

This checks the current technology state.

### Prerequisites

The function also accesses:

```text
ESI + 0x2EC
```

and invokes a virtual function before checking the corresponding state again.

### Important

`FUN_00569920` does **not** directly contain the `is_civilised` check. It should therefore not be treated simply as an "uncivilized-country lock."

It is a general technology-availability function and has multiple callers:

```text
FUN_007A9700
FUN_007A9950
FUN_007AA580
FUN_007AA890
FUN_00859710
```

A global patch there could therefore affect multiple systems.

## 4. Player Research Flow

`FUN_007AA890` processes technology-view actions, including:

```text
"start"
```

Conceptual flow:

```text
ProcessTechnologyAction
        ↓
      "start"
        ↓
Technology selected?
        ↓
Valid state?
        ↓
Normal checks
        ↓
CheckTechnologyAvailability
        ↓
Available?
   ┌────┴────┐
   NO        YES
   ↓          ↓
 BLOCK      CONTINUE
              ↓
      Start research
```

### Selected technology

```asm
007AA993 MOV ESI,[EDI+0x5C]
007AA996 CMP ESI,EBX
007AA998 JZ 007AAA83
```

This checks whether a technology is selected.

### Technology state

```asm
007AA99E MOV EAX,[EDX+0xBCC]
007AA9A4 MOV ECX,[ESI+0x2E4]
007AA9AA MOV EAX,[EAX+0x2B8]
007AA9B0 CMP [EAX+ECX*4],EBX
007AA9B3 JZ 007AAA83
```

## 5. Player Civilization Gate

At:

```text
007AAA83
```

the game checks:

```asm
007AAA83 CMP byte ptr [EDX+0x12D0],BL
007AAA89 JNZ LAB_007AAB5E
```

Because:

```text
EDX + 0x12D0 = is_civilised
BL = 0
```

the branch is civilization-dependent.

The next important location is:

```text
007AAB5E
```

where the normal availability check is called:

```asm
007AAB66 MOV ECX,[EBP-0x30]
007AAB69 MOV EDI,[ECX+0xBCC]
007AAB6F CALL FUN_00569920
007AAB74 TEST AL,AL
007AAB76 JZ 007AAC1A
```

Thus the civilization gate and the normal availability system are separate.

## 6. Player UI State

`FUN_007AA580` contains another civilization check:

```asm
007AA751 CMP byte ptr [ESI+0x12D0],BL
007AA757 JNZ LAB_007AA7B3
```

Original bytes:

```text
75 5A
```

Changing:

```text
75 5A → 74 5A
```

changes `JNZ` to `JZ`.

Observed result:

```text
Uncivilized → can research
Civilized   → cannot research
```

This proves that the conditional controls the civilization-dependent branch, but simply inverting it is not the desired solution.

The final documented player patch is:

```text
75 5A → EB 5A
```

`EB` is an unconditional short jump, so both country types use the same path.

## 7. AI Research Flow

`FUN_00859710` is the AI technology-research path.

The relevant sequence is:

```asm
00859747 MOV EAX,[EDI+0x38]
0085974A MOV EAX,[EDX+EAX*4]
0085974D MOV AL,[EAX+0x12D0]
00859753 TEST AL,AL
00859755 0F 84 B5 05 00 00
         JZ 00859D10
```

The AI also reads:

```text
country + 0x12D0
```

### AI patch

At `00859755`, the original six-byte conditional jump is:

```text
0F 84 B5 05 00 00
```

The documented patch is:

```text
90 90 90 90 90 90
```

This removes the jump and lets the AI continue through the processing path.

## 8. Player vs AI Patch

### Player

```text
VA: 007AA757
75 5A → EB 5A
```

Type:

```text
conditional jump → unconditional jump
```

### AI

```text
VA: 00859755
0F 84 B5 05 00 00
↓
90 90 90 90 90 90
```

Type:

```text
conditional jump → removed
```

These are independent gates.

## 9. Technology List Experiment

`FUN_007A9700` calls `FUN_00569920` and passes technology-state values.

An experiment changing:

```text
PUSH 3
PUSH 4
```

to:

```text
PUSH 1
```

made technologies appear visually available/blue.

However:

```text
Technology list → available-looking
Start Research → still disabled
```

Conclusion: this path affects list/UI state and does not unlock the real research action.

## 10. Country Rank

`FUN_005379E0` determines country classification using:

```text
country + 0x12D0
country + 0x31
country + 0x1404
```

Documented result:

```text
0 = Great Power
1 = Secondary Power
2 = Civilized
3 = Uncivilized
```

The initial check is:

```asm
005379E0 CMP byte ptr [ECX+0x12D0],0
005379E7 JNZ 005379EF
005379E9 MOV EAX,3
```

This confirms the relationship between `+0x12D0` and civilization status, but this function has **not** been demonstrated to be the direct research lock.

## 11. Research Goal

The intended modification is specifically:

```text
remove the civilization restriction
```

while preserving:

```text
✓ date requirements
✓ prerequisites
✓ technology state
✓ already-researched state
✓ other normal technology rules
```

The current model is:

```text
PLAYER
  ↓
Technology action
  ↓
Civilization gate
  ↓
Normal availability
  ↓
Date / state / prerequisites
  ↓
Research

AI
  ↓
AI research processing
  ↓
Civilization gate
  ↓
Continue
```

## 12. Binary Patch Reminder

The addresses above are Ghidra virtual addresses.

Do **not** assume:

```text
VA = file offset
```

For each binary modification:

1. obtain the VA;
2. convert VA → file offset;
3. verify the original bytes;
4. write only the documented patch bytes;
5. verify the result.

See [Patch Registry](patches.md) for the consolidated patch list.
