# Victoria 2 — Event System (Reverse-Engineering Notes)

**Status:** work in progress. Everything below comes from Ghidra listings of the 32-bit Victoria II executable
(MSVC build, fixed image base, no ASLR). Nothing was run under a debugger yet, so every behavioural claim is
tagged with how sure we are.

## Conventions

| Tag | Meaning |
|---|---|
| **[C]** | Confirmed by reading the disassembly directly |
| **[I]** | Inferred from context, naming, or usage — plausible but not proven |
| **[?]** | Unknown / not analysed |

- All addresses are virtual addresses (VA).
- `std::string` is the MSVC layout: 0x1C bytes = 16-byte buffer/pointer, size at `+0x10`, capacity at `+0x14`
  (small-string capacity `0xF`).
- **(user)** = name assigned by the user in Ghidra, translated to English (the original Spanish names are listed in §9). **(proposed)** = name suggested in this document. Functions with
  neither keep their `FUN_xxxxxxxx` address name.
- "Country key" / "event key" means a `(type, id)` pair of two dwords.

---

## 1. Big picture

```
LOAD TIME
  LoadingStartScreen (loading screen)
    └─ EventManager_LoadResources (0x008A67B0)
         ├─ physfs_find_files_by_extension     list event files
         ├─ load_resource_from_physfs          open a file, create the tokenizer/reader
         ├─ InitializeEventObject (0x009A1440)   read the 3 header tokens
         ├─ EventManager_Initialize (0x008A5AC0)  construct the event object (0x1C4 bytes)
         │    └─ EventManager_InitializeEventRegistry (0x008A5C70)
         ├─ event->vtable[3]                   parse the event body (not analysed)
         └─ GetMainEventName / GetSecondaryEventName   validation + error logging

RUN TIME (once per game "day" tick — see caveats in §3.2)
  Economy_ProcessMonthlyTick (user name; only known caller)
    └─ FUN_008A7CD0   (proposed: EventManager_DailyScan)
         ├─ trigger:    [ev+0x30]->vtable[0x18](ctx)
         ├─ MTTH:       FUN_008AE380
         ├─ dice:       Mersenne-Twister, rand % 1,000,000 < probability
         ├─ fired-once: FUN_009C1D40 on world+0xB64
         └─ FUN_008A8120   (proposed: Event_Fire)
              ├─ AI country → FUN_008AEB00 (ai_chance) → FUN_00907D40 (option command)
              ├─ Player     → FUN_008A8F30 (EventWindow_Construct) → FUN_006480E0 (show window)
              └─ always     → [ev+0x74]->vtable[0x2C]   (immediate effect block)

EFFECT-DRIVEN EVENTS (country_event / province_event used inside effects)
  FUN_008E7F80          parse the effect statement
  Spawn_event (0x0088D370)
    ├─ FUN_009C1D40      look the event up by (0x27, id) in registry DAT_01258A98
    ├─ delay <= 0  →     FUN_008A8120   fire immediately
    └─ delay  > 0  →     FUN_00540A70   schedule on the country
  ProcessSpawnEvent (0x0088D460)   builds the tooltip text of that effect [I]
```

---

## 2. Data structures

### 2.1 Global objects

| Address | What it is |
|---|---|
| `DAT_012588E8` | World / game state singleton. `+0xACC` province pointer array; `+0xAEC..+0xAF0` per-country vector (non-zero entry = human-controlled **[I]**); `+0xB0C` current date; `+0xB24` UI / window manager **[I]**; `+0xB64` fired-once hash table |
| `DAT_012587E4` | Country manager. `+0x00` country count, `+0x04` pointer to array of country pointers |
| `DAT_0125870C` | Object whose vtable slot `0x24` returns the province count **[I]** |
| `DAT_01258A98` / `DAT_01258A94` | Object registries. `FUN_009C16D0` picks `A94` when type > `0x1268`, otherwise `A98`. Event objects are stored under type `0x27` in `A98` **[C]** (used by `Spawn_event`) |
| `DAT_01268FEC` / `DAT_01268FF0` | Globals copied into `event+0x08/+0x0C` when an event object is constructed **[I]: the key of the event being parsed** |
| `DAT_012586E0` | Table holding search-path information used by `EventManager_LoadResources` (`+0x48`, `+0x4C`) **[I]** |
| `DAT_0131BB34` | Lazily created 0x188-byte database singleton (constructor `FUN_0041A160`, registered with `FUN_00423700`). Supports lookup by name (`FUN_005C2AD0`) and has a vector at `+0xC/+0x10` whose length matches the per-province array stride, so it is probably the pop-type database **[I]** |
| `DAT_00F0ECF0` / `DAT_00F0F6B0` | Mersenne-Twister state array (624 words) and current index **[C]** |
| `DAT_00F20C18` / `DAT_00F20C14` | Lazily created RNG engine object (vtable `DAT_00E38B28`) and a call counter **[C]** |

### 2.2 Event manager (argument of `EventManager_LoadResources`)

| Offset | Content |
|---|---|
| `+0x00 .. +0x0B` | `std::vector<Event*>` receiving events whose first token type is `0x3FF` **[C]** |
| `+0x20 .. +0x2B` | `std::vector<Event*>` receiving events whose first token type is `0x400` **[C]** |

`0x3FF` / `0x400` are very likely `country_event` / `province_event` **[I]**. To confirm it, follow the pointer table
that references the strings at `0xE22D98` / `0xE22D88` (see §6).

### 2.3 Event object (size 0x1C4, built by `EventManager_Initialize`)

| Offset | Content | Tag |
|---|---|---|
| `+0x00` | vtable `DAT_00E2C834`. Slot 3 (`+0xC`) = body parser, called by the loader | C |
| `+0x04` | constant `0x18D` (397); meaning unknown | ? |
| `+0x08`, `+0x0C` | event key `(type, id)`; used as hash key | I |
| `+0x30` | **trigger block**, vtable `DAT_00DF9994`; slot 6 (`+0x18`) = `bool Evaluate(ctx)` | C |
| `+0x4C` | sub-object "registry" (vtable `DAT_00E2C818`), initialised by `EventManager_InitializeEventRegistry`. It contains nested blocks at `+0x54` (vtable `DAT_00E2CECC`, purpose unknown) and `+0x74` (vtable `DAT_00DFA6EC`) | C |
| `+0x74` | **immediate effect block**; slot `0x2C` is executed every time the event fires | C |
| `+0xB0 .. +0xB8` | vector of option pointers; option `+0x08` = AI-chance block | C |
| `+0xC0` | **MTTH block**, vtable `DAT_00E2CEB0` (`+0x08` base value, `+0x0C..+0x10` vector of modifiers) | C |
| `+0xDC, +0xF8, +0x114, +0x130, +0x14C, +0x168, +0x184` | seven `std::string` members | C |
| `+0x1A0`, `+0x1A1` | boolean flags (initialised to 0) | C |
| `+0x1A2`, `+0x1A3` | boolean flags (initialised together as a word) | C |
| `+0x1A4` | boolean flag, **not** initialised by the constructor (probably set by the parser) | I |
| `+0x1A8` | `std::string` (last member; `0x1A8 + 0x1C = 0x1C4`) | C |

Behaviour of the flags, as seen in code:

- `+0x1A3` — if non-zero, the event is inserted into the **fired-once table** when it fires, and skipped by the daily
  scan if it is already there. Almost certainly `fire_only_once` **[C behaviour / I name]**.
- `+0x1A1` — in `Event_Fire`, when it is 0 an extra UI check (`UIManager->vtable[0xF4](event)`) can suppress the
  window **[C behaviour / ? meaning]**.
- `+0x1A2` — selects a window variant in the window constructor **[C behaviour / ? meaning]**.
- `+0x1A4` — selects the "full window" branch of the window constructor **[C behaviour / ? meaning]**.

### 2.4 Option object

| Offset | Content |
|---|---|
| `+0x08` | AI-chance block: `+0x08` base factor, `+0x0C..+0x10` vector of modifiers, `+0x1C` final multiplier |
| modifier | `+0x08..+0x0C` vector of condition objects (each with `vtable[6] = bool Evaluate(ctx)`), `+0x20` factor |

### 2.5 MTTH block (`event+0xC0`)

`+0x08` base value; `+0x0C..+0x10` vector of modifier objects. Each modifier has `vtable[6] = bool Evaluate(ctx)`
and its factor at `+0x20`. Fixed-point scale is 1000. **[C]**

### 2.6 File wrapper, reader and token (load time)

| Object | Layout |
|---|---|
| **File wrapper** (0x360 bytes) | vtable `DAT_00E38524` (slot 0 = `FUN_009A0C80`, destructor), `+0x1C` reader pointer, `+0x20` token 1, `+0x124` token 2, `+0x228` token 3 (its string starts at `+0x22C`), `+0x32C` `std::string` (file path), `+0x348..+0x350` vector, `+0x358` byte, `+0x35C` dword |
| **Reader** (0x114 bytes) | vtable `DAT_00E37C3C` (slot 1 = `FUN_00990930`, "read next token"), `+0x08` last result, `+0x0C` **current token**, `+0x110` "primed" flag |
| **Token** (0x104 bytes) | First dword = token type. Copied around with `rep movsd` of `0x41` dwords. Type `0x13` = end of file (also forced when a read fails). Types `0x3FF` / `0x400` = event keywords |

### 2.7 Context structure (0x48 bytes, copied by `FUN_008A88D0`)

| Offset | Content | Tag |
|---|---|---|
| `+0x08`, `+0x0C` | country key (`country+0x1C`, `country+0x20`) | C |
| `+0x10` | province index (province branch of the daily scan) | C |
| `+0x18` | index into the country / province arrays | I |
| `+0x2C`, `+0x30` | a pair that `FUN_008A8DC0` rewrites (date / offset) | I |

### 2.8 Hash registry (`FUN_009C1D40`)

```
struct HashTable { int count; uint bucketCount; Node** buckets; }   // count at +0, buckets at +8
struct Node      { Entry* entry; Node* next; }
Entry key:  type at entry+0x08, id at entry+0x0C
hash      = (type << 16) + id            // 32-bit
bucket    = hash % bucketCount
```

Chained hash table, O(1) on average **[C]**. The insertion code seen in `Event_Fire` (fired-once table) prepends a node
and increments `count` with **no duplicate check and no rehash** **[C]**, so a fixed small `bucketCount` would make
chains grow with the number of entries.

---

## 3. Function reference

### 3.1 Loading

#### `EventManager_LoadResources` — 0x008A67B0 (user)
`stdcall`, one argument: the event manager. Called from `LoadingStartScreen`.

1. Reads two path strings from `DAT_012586E0` (`string_assign_substring_from_table_entry` and `_alt`). **[C]**
2. Runs `physfs_find_files_by_extension` on each root with the extension string at `DAT_00DFA554`, which starts
   with `.` (probably `.txt`). The second root is skipped when `[DAT_012586E0+0x48] == 1`. The two listings are merged
   without duplicates (`find_string_in_vector`, `vector_emplace_back_or_insert`). **[C]** Probably "base game folder +
   mod folder". **[I]**
3. Builds full paths (`dir` + `/` + `file`) into a third vector. **[C]**
4. For every path: allocates the 0x360-byte file wrapper and the 0x114-byte reader (`load_resource_from_physfs`),
   stores the path in the wrapper. **[C]**
5. Main loop: primes the reader, copies the current token, and stops on type `0x13` (EOF). Otherwise calls
   `InitializeEventObject`, then looks at the token type at `wrapper+0x20`:
   - `0x3FF` or `0x400` → allocates `0x1C4` bytes, calls `EventManager_Initialize`, pushes the pointer into the
     manager vector (`0x3FF` → `manager+0x00`, `0x400` → `manager+0x20`), then calls `event->vtable[3](wrapper)`
     to parse the body. **[C]**
   - anything else → logs message `0xC6` (flags `0x10004`) with the file name. **[C]**
6. Validation after each parsed event (the event is **kept** even if any check fails): **[C]**
   - main name empty (`GetMainEventName` length == 0) → message `0x9F`
   - secondary name empty (`GetSecondaryEventName`) → message `0xA1`
   - option vector empty (`event+0xB0 .. +0xB4`) → message `0xA4`

   Each message prints the event key (`[event+0x0C]`) and the file path.
7. At EOF: calls the wrapper destructor (`vtable[0](1)`), logs message `0xCA` with the file path and calls
   `stream_flush_and_sync`. **[C]**

#### `InitializeEventObject` — 0x009A1440 (user)
`stdcall`, one argument: the file wrapper. Makes sure the reader is primed, then reads up to three consecutive tokens
(`reader->vtable[1]`, copy `reader+0x0C` → `wrapper+0x20`, `+0x124`, `+0x228`). The 2nd token is only accepted when
its type is `1`. **[C]** The three tokens are probably `country_event`, `=`, `{`. **[I]**

#### `EventManager_Initialize` — 0x008A5AC0 (user)
`stdcall`, one argument: raw memory of the event object. Sets the vtable `DAT_00E2C834` (after a temporary
`DAT_00E3A544`), constants `0x18D`, the key from `DAT_01268FEC/FF0`, the trigger vtable `DAT_00DF9994` at `+0x30`, calls
`EventManager_InitializeEventRegistry(this+0x4C)`, initialises the option vector, the MTTH block (`+0xC0`, vtable
`DAT_00E2CEB0`, `+0xC4 = 0x18D`, `+0xC8 = 0x3E8`), eight `std::string` members and the flag bytes. Returns `this`. **[C]**

#### `EventManager_InitializeEventRegistry` — 0x008A5C70 (user)
Initialises the sub-object at `event+0x4C`: vtable `DAT_00E2C818`, `0x18D`/`0x3E8` constants, a nested block at `+0x08`
(vtable `DAT_00E2CECC`) and at `+0x28` (vtable `DAT_00DFA6EC`, i.e. `event+0x74`), two empty vectors, one empty
`std::string` at `+0x48`. Also called from `FUN_008A6280` (0x008A6345), which is another event-related constructor. **[C]**

#### `GetMainEventName` — 0x008A6010 (user)
Returns a `std::string` with the event's main name; custom convention (event pointer on the stack, output buffer in
`ESI`). Eight callers: `FUN_00468210`, `ProcessSpawnEvent`, `FUN_0088D7A0`, `EventManager_LoadResources`,
`FUN_008A8F30` (three call sites), `FUN_00907E00`. **[C]**

#### `GetSecondaryEventName` — 0x008A60F0 (user)
Same shape, returns the secondary name. Used by `EventManager_LoadResources` and `FUN_008A8F30`. **[C]**

#### `FUN_008A6070` and `FUN_008ADBE0`
`FUN_008A6070` is a third per-event string getter (used by the window constructor at 0x008A92C1). `FUN_008ADBE0`
post-processes the string returned by these getters (probably localisation) before it is written into a widget. **[I]**

#### `ResolveOrRegisterEvent` — address not captured (user)
Takes a string and returns an object; called by `ProcessSpawnEvent` and by the window constructor. The exact
purpose of the resolved object is unknown. **[?]**

### 3.2 Daily scan

#### `Economy_ProcessMonthlyTick` (user name)
The only caller of `FUN_008A7CD0`. The name says *monthly*, but the day-parity gate inside the scan only makes
sense if it is called **once per day**. Count calls per game day before trusting either reading. **[?]**

#### `FUN_008A7CD0` — 0x008A7CD0 (proposed: `EventManager_DailyScan`)
`stdcall`, one argument (game state, forwarded to `Event_Fire`). **[C]**

1. Builds the context (`FUN_009B7950(0x20, 0)` then `FUN_008A8650`). **[C]**
2. **Day gate:** `days = (world+0xB0C − 0x29C55C0) / 24` (signed, truncating).
   - `days` odd → **country branch**
   - otherwise → **province branch** (label `0x008A7F42`)
   The unit of the date value is unknown; the code divides by 24. **[C]**
3. **Country branch** — countries indexed from 1 (index 0 skipped):
   - skip when `country+0x20 == 0`, or when the vector `country+0x9D8..0x9DC` is empty **[C]**
   - candidate events = vector at `country+0x08..+0x0C` **[C]** (who fills it: unknown **[?]**)
   - fills `ctx+8/+0xC` with `country+0x1C/+0x20`
4. **Province branch:** count from `DAT_0125870C->vtable[0x24]`; skip provinces with `[prov+0x12C] == 0`; candidate
   events = vector at `province+0x14..+0x18`; mode argument is `2`. **[C]**
5. **Per candidate event (same order in both branches):** **[C]**
   1. `trigger = [ev+0x30]->vtable[0x18](ctx)`; false → next candidate
   2. `p = FUN_008AE380(ev+0xC0, ctx, mode)` (mode 1 = country, 2 = province)
   3. `r = MersenneTwister() % 1,000,000` (engine `DAT_00F20C18`; regenerated by `FUN_009B7700` when the index wraps)
   4. if `r >= p` → next candidate
   5. if `[ev+0x1A3] != 0` and `FUN_009C1D40(world+0xB64, {[ev+8],[ev+0xC]})` returns this same event → already
      fired, next candidate
   6. `FUN_008A8120(ev, state, ctx)`

Because events without an MTTH have `p = 100 %` (see next function), a candidate list must never contain
`is_triggered_only` events, otherwise they would fire as soon as their trigger is true. So that filter has to be
applied when the candidate vectors are built **[I]**.

#### `FUN_008AE380` — 0x008AE380 (proposed: `Event_ComputeMTTHProbability`)
`stdcall(mtthBlock, ctx, mode)`. Returns a probability per million. **[C]**

```
v = block.base                                   // value scaled x1000
for each modifier m in block.modifiers:          // NO early exit — every modifier is evaluated
    if m.Evaluate(ctx):
        v = v * round(m.factor) / 1000
if v < 0 and block.base > 0:  return 1
if v <= 1000:                 return 1,000,000   // MTTH <= 1 day (also: no MTTH at all => base 0)
days = v / 1000
p    = mode * 1,000,000 / days
return clamp(p, 1, 1,000,000)
```

Note: `mode` multiplies the probability. With one scan every 2 days per scope, mode 1 (countries) gives an average
firing time of about 2 x MTTH days, while mode 2 (provinces) gives about 1 x MTTH. Whether that asymmetry is
intentional is unknown. **[I]**

#### `FUN_009C1D40` — 0x009C1D40 (proposed: `ObjectRegistry_HashLookup`)
Chained hash lookup, see §2.8. Register-call convention: key pointer in `EAX`, table in `ECX`, returns the entry or 0.
About 20 callers. **[C]**

#### `FUN_009C16D0` — 0x009C16D0 (proposed: `ObjectRegistry_FindByTypeAndId`)
`stdcall`, key `(type, id)` passed by value on the stack (two dwords). Selects registry `DAT_01258A94` when
`type > 0x1268`, otherwise `DAT_01258A98`; returns 0 when the registry pointer is null; otherwise calls
`FUN_009C1D40`. About 20 callers, including `ConsoleCommands` (the console commands). **[C]**

### 3.3 Firing an event

#### `FUN_008A8120` — 0x008A8120 (proposed: `Event_Fire`)
`thiscall`, `this` = event, two stack arguments (game state, context), `RET 8`. Seventeen callers: `FUN_00426570`,
`FUN_004B1A10`, `FUN_004D1FA0` (x2), `FUN_005091A0`, `FUN_00523C30` (x3), `FUN_005241F0`, `FUN_005441F0`,
`FUN_0068C660` (x2), `Spawn_event`, `FUN_0088D6B0`, `FUN_008A7CD0` (x2), `FUN_008B2680`. **[C]**

1. Resolves the target country/province indices from the context. **[C]**
2. If `[this+0x1A3] != 0`, inserts the event into the fired-once table (`world+0xB64`): hash bucket prepend,
   `count++`, no duplicate check, no rehash. **[C]**
3. **AI branch** — when the country index is inside the vector at `world+0xAEC`, its entry is 0, and
   `country+0x208 != 0`: **[C]**
   - `total = Σ w_i` with `w_i = FUN_008AEB00(option_i+8, ctx)`
   - if `total` is above a tiny threshold: `r = FUN_009B7610(state+0x40) % 100`, then for each option
     `acc += trunc(w_i / 1000 / (total / 1000 / 100))` and the first option with `r <= acc` wins
   - otherwise option 0 is chosen
   - **each weight is computed twice** (once for the total, once in the selection loop) — the value is deterministic,
     so it could be cached
   - creates a 0xB0-byte command object with `FUN_00907D40(option index, event, ctx copy)` and queues it through the
     UI/command manager (`world+0xB24`)
4. **Human branch** — otherwise: **[C]**
   - only proceeds when `UIManager->vtable[0x58]()` reports the local player's country index
   - checks `FUN_0068B610(world)+0x28` (UI ready flag)
   - when `[this+0x1A1] == 0` and `UIManager->vtable[0xF4](event)` is true, the window is suppressed
   - otherwise allocates a 0xD0-byte window object, calls `FUN_008A8F30` to construct it, then `FUN_006480E0` to show it
5. **Always:** executes the immediate effect block: `[this+0x74]->vtable[0x2C](ctx, 0)`. **[C]**

#### `FUN_008AEB00` — 0x008AEB00 (proposed: `EventOption_EvaluateAIChance`)
`stdcall(aiChanceBlock, out, ctx)`, `RET 0xC`. Pure function. **[C]**

```
v = block.base
for each modifier m:
    if all m.conditions[i].Evaluate(ctx):
        v = v * m.factor / 1000
        if v <= 0: break
*out = block.multiplier * v / 1000
```

Only used by `Event_Fire`.

#### `FUN_00907D40`
Builds the 0xB0-byte "chosen option" command object (arguments: object memory, option index, event, 0x48-byte context
copy). **[I]** Called from `Event_Fire` on the AI branch.

#### `FUN_008A8F30` — 0x008A8F30 (proposed: `EventWindow_Construct`)
Constructor of the event pop-up window, `RET 0x50` (20 dword arguments), returns `this`. Only callers:
`FUN_0041F170` (0x0041F54E) and `Event_Fire` (0x008A8476). **[C]**

- Sets vtable `DAT_00E2CDB8`, stores the event and the country's `[+0xCDC]` object, copies the 0x48-byte context
  (`FUN_008A88D0`), initialises two sub-objects (`+0x5C`, `+0x88`, vtable `DAT_00E2CDD4`), the date and a float taken
  from the UI manager. **[C]**
- Branches on the event flags (`+0x1A4` first, then `+0x1A2`) to build one of several window variants. **[C]**
- The main variant fills title/description widgets by looking widgets up by name and assigning localised strings
  (`GetMainEventName`, `GetSecondaryEventName`, `FUN_008A6070`, `FUN_008ADBE0`, `FUN_00A5ECC0`). **[C]**
- Creates one widget per option: names are built with `_` separators and integers converted by `FUN_00AB1DF7`
  (radix 10); vertical layout is accumulated in a running offset; each widget is appended to a list at
  `this+0xB8/+0xBC` (16-byte nodes). **[C]**
- If a required GUI element is missing it writes message `0x115` (event key + name) to the log. **[C]**
- Ends by notifying the UI manager (`vtable[0xF8]`, `vtable[0xC0]`). **[C]**
- **Dead loop:** between 0x008A9434 and 0x008A9562 it walks every pop of every province in the player's country
  (list at `country+0xE44` → provinces → per-pop-type list at `province+0x194` → next pop at `pop+0x27C`) and calls
  `FUN_00963D10` on each. The result is overwritten on the next iteration and never used. See patch 1. **[C]**

#### `FUN_00963D10` — 0x00963D10 (proposed: `Pop_GetCountryWeight`)
`stdcall(pop, out64)`. Pure: writes only to `*out` and locals. **[C]**
`out = pop.size (+0x58) scaled by a per-stratum factor from the country (+0xA60 block), fixed-point`; halved (or
zeroed) for pops that do not match the country's culture (`country+0xE64` vs `pop+0x6C`) depending on country flags
(`+0xB68`, `+0xB70`). The exact meaning of the number is unknown. **[I]** Other callers: `FUN_004B9CC0`, `FUN_004D11B0`,
`UpdateAndProcessAccumulatedOfE…` (user), `FUN_008AB700`.

#### `FUN_008AB700`
Called by the window constructor right after the option list is built (with the window and the event) and itself calls
`FUN_00963D10` at 0x008AC484. Not analysed. **[?]**

#### Helpers
| Function | Role |
|---|---|
| `FUN_008A88D0` | Copies the 0x48-byte context (thiscall, source in `ECX`, destination in `EAX`) **[C]** |
| `FUN_008A8650` | Builds a context from a random value **[I]** |
| `FUN_008A8DC0` | Date/offset helper returning two dwords **[I]** |
| `FUN_008A6620` | Helper used by `Spawn_event` on the immediate-fire path **[?]** |
| `FUN_006480E0` | Shows the freshly built window **[I]** |
| `FUN_0068B610` | Returns an object whose `+0x28` byte is a "UI ready" style flag **[I]** |
| `FUN_009B7610` | Draws a random integer from the LCG state at `state+0x40` **[I]** |
| `FUN_009B7700` | Regenerates the 624-word Mersenne-Twister state **[I]** |
| `FUN_009B7950` | Called once per scan with `(0x20, 0)`; purpose unknown **[?]** |
| `SignedInt64_Divide`, `MultiplicarEntero64SinSigno` | 64-bit fixed-point helpers **[C]** |
| `ConvertFloatToFloat10_interes`, `convert_float10_to_ulonglong_custom_rounding` | Float → integer rounding used by MTTH/AI code **[I]** |

### 3.4 Event effects (events fired from scripts)

#### `FUN_008E7F80` — 0x008E7F80 (proposed: `EventEffect_ParseStatement`)
`thiscall(this = effect statement, tokenHolder, keywordId)`, `RET 8`. **[C]**

- keyword `0x344` → converts token 3 through `FUN_0098FDD0` into the pair stored at `this+0x20/+0x24`.
  Because `Spawn_event` uses `+0x20` as the event id and `+0x24` as a delay in days, this pair is probably
  *(id, days)*, not just the id. **[I]**
- keywords `0xD9` and `0x1D4` → takes the string at `tokenHolder+0x22C`, looks it up (lower-cased with
  `CharLowerBuffA`) in the `DAT_0131BB34` database via `FUN_005C2AD0` and stores the result at `this+0x28`. If the
  string equals `"this"` (address `0xE22D44`), it sets `this+0x18 = 1`. If nothing resolves it logs message `0x16D1`.
  The type of the resolved object is unknown. **[C behaviour / ? meaning]**
- every other keyword → `FUN_008B33E0` (default handler). **[C]**

#### `Spawn_event` — 0x0088D370 (user)
`thiscall`, `RET 8`. Executes a `country_event` / `province_event` effect. **[C]**

1. Draws two 15-bit numbers from the LCG at `state+0x40` (multiplier `0x343FD`, increment `0x269EC3`, `>>16 & 0x7FFF`),
   multiplies them and feeds the product to `FUN_008A8650`.
2. Looks the event up with `FUN_009C1D40` in registry `DAT_01258A98`, key `(0x27, [this+0x20])`.
3. If found and `[this+0x24] <= 0` → fires immediately with `Event_Fire`.
4. If `[this+0x24] > 0` → schedules it with `FUN_00540A70(country, event, context, days)`.

#### `ProcessSpawnEvent` — 0x0088D460 (user)
`thiscall`, `RET 0x28`. Builds the descriptive text (tooltip) for the same effect: resolves the event with
`FUN_009C16D0(0x27, [this+0x20])`, reads its main name (`GetMainEventName`), wraps it in a 0x40-byte
effect descriptor (`InitializeEffectDescriptor`) and hands it to `FUN_009A9880` / `String_AssignFromObject`.
Suggested name: `EventEffect_BuildTooltip`. **[I]**

---

## 4. Constants and formulas

| Item | Value |
|---|---|
| Day gate | `((date − 0x29C55C0) / 24) % 2`; odd → countries, otherwise provinces |
| Probability | `mode × 1,000,000 / MTTH_days`, clamped to `[1, 1,000,000]`; MTTH ≤ 1 day → 1,000,000 |
| Random roll | `MT() % 1,000,000 < p` |
| AI option pick | cumulative weight in percent vs `FUN_009B7610() % 100`; fallback option 0 |
| Fixed-point scale | 1000 for weights and MTTH, `<< 15` / `1 << 16` for pop weights |
| Hash | `(type << 16) + id` modulo bucket count |
| Event registry type | `0x27` |
| Registry split | type > `0x1268` → `DAT_01258A94`, otherwise `DAT_01258A98` |
| Token types | `0x13` EOF, `0x3FF` / `0x400` event keywords, `1` accepted as 2nd header token |
| Magic sizes | event `0x1C4`, file wrapper `0x360`, reader `0x114`, token `0x104`, context `0x48`, option command `0xB0`, window `0xD0`, MTTH/AI block dword `0x18D` / `0x3E8` |

---

## 5. Log message ids seen in the event code

| Id | Where | Meaning (from context) |
|---|---|---|
| `0xC6` (flags `0x10004`) | `EventManager_LoadResources` | Unexpected first token in an event file |
| `0x9F` | `EventManager_LoadResources` | Event with empty main name |
| `0xA1` | `EventManager_LoadResources` | Event with empty secondary name |
| `0xA4` | `EventManager_LoadResources` | Event with no options |
| `0xCA` (flags `0x10000`) | `EventManager_LoadResources` | Per-file message at EOF (followed by a flush) |
| `0x16D1` | `FUN_008E7F80` | Unresolved name in an effect statement |
| `0x115` | `FUN_008A8F30` | Required GUI element missing for an event window |

---

## 6. Keyword string table at 0x00E22D44

| Address | String |
|---|---|
| `0x00E22D44` | `this` |
| `0x00E22D4C` | `relation` |
| `0x00E22D58` | `any_neighbor_country` |
| `0x00E22D70` | `any_neighbor_province` |
| `0x00E22D88` | `province_event` |
| `0x00E22D98` | `country_event` |
| `0x00E22DA8` | `cb_on_religious_enemies` |
| `0x00E22DC0` | `prestige_from_naval` |
| `0x00E22DD4` | `prestige_from_land` |
| `0x00E22DE8` | `needaccept` |
| `0x00E22DF4` | `popup` |
| `0x00E22DFC` | `onmap` |

Only the address of `this` has a known XREF (`FUN_008E7F80`). Searching memory for the little-endian bytes of
`0x00E22D88` / `0x00E22D98` should reveal the table that maps these strings to token ids (probably `0x400` / `0x3FF`).

---

## 7. Performance analysis and patches

### 7.1 What the code says about cost

- **Load time:** cost is linear in the number of event files and events. Every event error writes to the log.
- **Daily scan:** one pass over `(countries × country-event candidates)` on odd days and `(owned provinces ×
  province-event candidates)` on the other days. Per candidate the trigger is evaluated first; the MTTH block
  (which evaluates **all** its modifiers) only when the trigger is true. Cost per candidate is not constant:
  triggers containing `any_*` scopes iterate lists. **[I]**
- **Firing:** rare compared with the scan. The AI evaluates every option's `ai_chance` twice. **[C]**
- **Human pop-up:** building the window walks every pop of the player's country needlessly (dead loop). **[C]**

### 7.2 Patch 1 — remove the dead pop loop (window construction only)

| Address | Original | New |
|---|---|---|
| `0x008A9428` | `0F 84 3A 01 00 00` (`JZ 0x008A9568`) | `E9 3B 01 00 00 90` (`JMP 0x008A9568`) |

Safe because `FUN_00963D10` is pure and its result is discarded. The lazily created `DAT_0131BB34` is created on demand
elsewhere.

### 7.3 Patch 2 — skip already-fired `fire_only_once` events before evaluating them

Two entry points in `FUN_008A7CD0` jump into code caves placed in the padding at the end of `.text`
(`0x00C8911B..0x00C891FF`, all zeros — verify the block is executable).

| Site | Original bytes | New bytes | Cave | Return | Skip target |
|---|---|---|---|---|---|
| `0x008A7DDF` (countries) | `8B 53 30 8B 52 18` | `E9 3C 13 3E 00 90` | `0x00C89120` | `0x008A7DE5` | `0x008A7F01` |
| `0x008A7FC0` (provinces) | `8B 53 30 8B 52 18` | `E9 AB 11 3E 00 90` | `0x00C89170` | `0x008A7FC6` | `0x008A80E2` |

Cave A (66 bytes at `0x00C89120`):
```
80 BB A3 01 00 00 00 74 29 8B 4B 08 8B 53 0C 89
4C 24 38 89 54 24 3C 8B 4C 24 14 81 C1 64 0B 00
00 8D 44 24 38 E8 F6 8B D3 FF 85 C0 74 04 3B C3
74 0B 8B 53 30 8B 52 18 E9 88 EC C1 FF E9 9F ED
C1 FF
```

Cave B (66 bytes at `0x00C89170`):
```
80 BB A3 01 00 00 00 74 29 8B 4B 08 8B 53 0C 89
4C 24 38 89 54 24 3C 8B 4C 24 14 81 C1 64 0B 00
00 8D 44 24 38 E8 A6 8B D3 FF 85 C0 74 04 3B C3
74 0B 8B 53 30 8B 52 18 E9 19 EE C1 FF E9 30 EF
C1 FF
```

Cave A as assembly:
```asm
00C89120  CMP  byte ptr [EBX+0x1A3], 0
00C89127  JZ   0x00C89152
00C89129  MOV  ECX, [EBX+8]
00C8912C  MOV  EDX, [EBX+0xC]
00C8912F  MOV  [ESP+0x38], ECX
00C89133  MOV  [ESP+0x3C], EDX
00C89137  MOV  ECX, [ESP+0x14]        ; world pointer saved by the scan
00C8913B  ADD  ECX, 0xB64             ; fired-once table
00C89141  LEA  EAX, [ESP+0x38]
00C89145  CALL 0x009C1D40
00C8914A  TEST EAX, EAX
00C8914C  JZ   0x00C89152
00C8914E  CMP  EAX, EBX
00C89150  JZ   0x00C8915D             ; already fired -> skip
00C89152  MOV  EDX, [EBX+0x30]        ; the two replaced instructions
00C89155  MOV  EDX, [EDX+0x18]
00C89158  JMP  0x008A7DE5
00C8915D  JMP  0x008A7F01
```

Effect: events that already fired no longer pay for trigger + MTTH + dice on every scan. It also changes the
sequence of random numbers consumed, so every player of a multiplayer game must run the same patch.
**Result reported by the user: no noticeable performance improvement** (no profiler data yet).

### 7.4 Patch 3 — scan half as often, compensating the probability (only worth it if profiling shows the scan is hot)

Replaces the day gate with `days % 4`: countries on `days % 4 == 1`, provinces on `days % 4 == 2`, nothing otherwise.

| Address | Original | New |
|---|---|---|
| `0x008A7D33` (21 bytes) | `25 01 00 00 80 79 05 48 83 C8 FE 40 83 F8 01 0F 85 FA 01 00 00` | `83 E0 03 83 F8 02 0F 84 03 02 00 00 83 F8 01 0F 85 C0 03 00 00` |
| `0x008A7DF7` | `6A 01` | `6A 02` |
| `0x008A7FD8` | `6A 02` | `6A 04` |

```asm
008A7D33  AND  EAX, 3
008A7D36  CMP  EAX, 2
008A7D39  JZ   0x008A7F42            ; provinces
008A7D3F  CMP  EAX, 1
008A7D42  JNZ  0x008A8108            ; neither: leave the function
008A7D48  ...                        ; country branch, EAX must still be 1
```

`EAX = 1` on entry to the country branch is required: `0x008A7D54` uses it as the first country index (skips country 0).
Costs: each scan costs the same, only less frequent; events without MTTH can fire up to 4 days late instead of 2;
probabilities cap at 100 %; multiplayer requires all players to run it.

---

## 8. Open questions

1. Who fills the candidate vectors `country+0x08` and `province+0x14`, and where are `is_triggered_only` events filtered out?
2. What is `DAT_0131BB34` exactly (pop-type database?) and what object does `FUN_008E7F80` resolve with it?
3. Is `Economy_ProcessMonthlyTick` really called every day? What is the unit of the date at `world+0xB0C`?
4. Real meaning of the flags at `event+0x1A0 .. +0x1A4` — match them against the keywords the body parser (`event->vtable[3]`) writes.
5. Body parser (`event->vtable[3]`), trigger evaluator (`DAT_00DF9994` slot 6) and the effect executors (`DAT_00DFA6EC` slot `0x2C`) are not analysed yet.
6. Bucket count of the fired-once table (`world+0xB64`) and of registry `DAT_01258A98`; whether they ever rehash.
7. Profile a heavy late-game save to find out where the frame time really goes before writing more patches.

---

## 9. Renaming table (original Spanish names → English names used in this document)

Use this table to rename the functions in Ghidra so the database matches the document.

| Address | Original name in Ghidra | English name |
|---|---|---|
| `0x008A67B0` | `EventManager_CargarRecursos` | `EventManager_LoadResources` |
| `0x008A5AC0` | `EventManager_Inicializar` | `EventManager_Initialize` |
| `0x008A5C70` | `EventManager_InicializarRegistroEventos` | `EventManager_InitializeEventRegistry` |
| `0x009A1440` | `InicializarObjetoEvento` | `InitializeEventObject` |
| `0x008A6010` | `ObtenerNombreEventoPrincipal` | `GetMainEventName` |
| `0x008A60F0` | `ObtenerNombreEventoSecundario` | `GetSecondaryEventName` |
| `0x0088D460` | `ProcesarEventoSpawn` | `ProcessSpawnEvent` (alternative: `EventEffect_BuildTooltip`) |
| not captured | `ResolverORegistrarEvento` | `ResolveOrRegisterEvent` |
| not captured | `InicializarDescriptorEfecto` | `InitializeEffectDescriptor` |
| not captured | `ObtenerSistemaGlobal` | `GetGlobalSystem` |
| caller of `EventManager_LoadResources` | `pantalla_de_inicio_carga` | `LoadingStartScreen` |
| caller of `FUN_009C16D0` | `comandos_consola` | `ConsoleCommands` |
| truncated in the listing | `ActualizarYProcesarAcumuladosDeE…` | `UpdateAndProcessAccumulatedOfE…` |

Names that were already in English and are kept: `Spawn_event`, `Economy_ProcessMonthlyTick`, `String_AssignFromObject`.

Proposed names for functions that still only have an address name:

| Address | Proposed name |
|---|---|
| `0x008A7CD0` | `EventManager_DailyScan` |
| `0x008A8120` | `Event_Fire` |
| `0x008A8F30` | `EventWindow_Construct` |
| `0x008AE380` | `Event_ComputeMTTHProbability` |
| `0x008AEB00` | `EventOption_EvaluateAIChance` |
| `0x00963D10` | `Pop_GetCountryWeight` |
| `0x009C1D40` | `ObjectRegistry_HashLookup` |
| `0x009C16D0` | `ObjectRegistry_FindByTypeAndId` |
| `0x008E7F80` | `EventEffect_ParseStatement` |
