# v2probe — read-only in-process hooks

Small The Grand Loader plugin that observes the AI job in a running game and resolves live object
types through MSVC RTTI. It does **not** change game state: each hook saves everything, logs, and
`jmp`s to the original, so stack and return value are untouched.

## Why this exists

Static reading leaves questions that only a live process answers: which class a pointer field really
holds, whether a byte is zero at runtime, how many times a path runs. RTTI on a live object settles
them without guessing from offsets, which is unreliable — the same displacement is reused by
different classes.

## What it hooks

| mask | site | target | function |
| --- | --- | --- | --- |
| `0x01` | `0x81EA9B` | `0x821190` | `AI_DecisionUpdate` (this in `ECX`) |
| `0x02` | `0x81EA58` | `0x820DF0` | `AI_ProcessPendingProposals_ForCountry` |
| `0x04` | `0x81EA8E` | `0x81E5B0` | per-country mille computation + list walk |
| `0x08` | `0x81EA94` | `0x81E280` | per-country province pass |
| `0x10` | `0x685B64` | `0x685620` | `UpdateTimeThrottle` (mechanism check) |

Each site is verified before patching: the byte must be `E8` and its `rel32` must resolve to the
expected target, otherwise the hook is skipped.

## RTTI resolution

For any pointer, the plugin reads `vtable[-1]` (Complete Object Locator), then `COL+0x0C`
(TypeDescriptor), then the decorated name at `+8`, and only accepts it if it is printable ASCII. That
is how `CState`, `CCulture`, `CArmy` and `CTechnologyStatus` were confirmed on live objects.

## Build and install

```bash
./build.sh                                   # needs i686-w64-mingw32-gcc
# copy v2probe.dll to <game>/mod/v2probe/ and v2probe.ini to <game>/mod/
```

`v2probe.ini` selects the hooks (`probe = 31`) and how many distinct countries are dumped
(`max_countries`).

Requires The Grand Loader (`dinput8.dll`) in the game directory to load `mod/*.ini` plugins.

## Output

Lines prefixed `[probe]` in `the_grand_loader.log`. A country dump looks like:

```text
[probe] pais idx=2 c=25c92668 lista7b4=43aa77e8 nodos=4 tail=43a9b508 cnt=26 flag=0
        e64=1f8cbb90(.?AVCCulture@@) bcc=1f589de0(.?AVCTechnologyStatus@@) ...
[probe]   tipo(elem)=.?AVCArmy@@ tipo(cA0)=.?AVCArmy@@
[probe]     id=13 prov=20fd9780 f188=3bbe0328 f18c=00000000 f384=00000000 t188=.?AVCState@@
```
