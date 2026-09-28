# Victoria II — Analysis Summary (Events, Daily Tick, and Patches)

Everything here comes from the Ghidra listings shared in the conversation. No debugger has been used yet.

**Marks:** **[C]** confirmed in the disassembly · **[I]** inferred · **[?]** unknown.  
Addresses are VAs (image base `0x00400000`). English names are proposed names (user names are marked *(user)*).

---

## 1. Daily tick flow **[C]**

```text
Update_World_and_Advance_Time (0x00682EC0)
  ├─ 0x00682FA5  ADD [world+0xB0C], 0x18      ← date advances 24 h per call
  └─ 0x00683AB1  CALL Economy_ProcessMonthlyTick (0x006859C0)

Economy_ProcessMonthlyTick (once per day; the name "Monthly" is misleading)
  ├─ per province (0x00685B40)  → FUN_004B1A10  (Province_DailyUpdate)
  ├─ 1000 Mersenne Twister random calls (0x00685B6B)
  ├─ per country, ESI starting at 1 (0x00685EC0) → FUN_005091A0 (Country_DailyUpdate)   ← CALL at 0x00685ED1
  └─ 0x006861E8  FUN_008A7CD0 (EventManager_DailyScan), only if [world+0xD11] == 0
```

- The date is stored in **hours**. Base `0x029C55C0` = 43,800,000 h = 5000 years × 365 × 24. Days = `(date − base)/24`; year = `days/365`; the month is obtained by subtracting the table `DAT_00F1027C` (31, 28, …).
- `world+0xB60` = player country index (confirmed by the user with Cheat Engine).
- `DAT_012588E8` = world. `DAT_012587E4` = country manager (`+0` count, `+4` array). `DAT_0131BB34` = pop-type database (0x188 bytes, lazily created).

## 2. Event system: functions

| Address | Name | Role |
|---|---|---|
| 0x008A67B0 | `EventManager_LoadResources` *(user, ES→EN)* | Loads event files with PhysFS; calls the parser (`event->vtable[3]`) |
| 0x008A5AC0 | `EventManager_Initialize` | Event constructor (0x1C4 bytes) |
| 0x008A5C70 | `EventManager_InitializeEventRegistry` | Sub-object at `event+0x4C` |
| 0x009A1440 | `InitializeEventObject` | Reads the 3 header tokens |
| 0x008A6010 / 0x008A60F0 | `GetMainEventName` / `GetSecondaryEventName` | Event names |
| 0x008E7F80 | `EventEffect_ParseStatement` | Effect statement parser (`0x344` = id/delay, `0xD9`/`0x1D4` = name → `this+0x28`) |
| 0x0088D370 | `Spawn_event` *(user)* | `country_event`/`province_event` effect: looks up `(0x27, id)` in the registry; if `[this+0x24] ≤ 0` fires immediately, otherwise schedules it with `FUN_00540A70` |
| 0x0088D460 | `ProcessSpawnEvent` *(user, ES→EN)* | Builds the tooltip text for that effect **[I]** |
| 0x008A7CD0 | `EventManager_DailyScan` | Daily MTTH scan: trigger → `FUN_008AE380` → roll → `Event_Fire` |
| 0x008AE380 | `Event_ComputeMTTHProbability` | Probability per million; `mode × 1,000,000 / days`, clamped to [1, 1,000,000] |
| 0x008A8120 | `Event_Fire` | AI: chooses an option with `FUN_008AEB00`; player: window with `FUN_008A8F30`; always executes `[event+0x74]->vtable[0x2C]` |
| 0x008AEB00 | `EventOption_EvaluateAIChance` | Option weight (pure function) |
| 0x008A8F30 | `EventWindow_Construct` | Builds the window; contains a dead loop over all pops (patch 1) |
| 0x00963D10 | `Pop_GetCountryWeight` | Pure function; its result is discarded in `EventWindow_Construct` |
| 0x009C1D40 / 0x009C16D0 | `ObjectRegistry_HashLookup` / `FindByTypeAndId` | Chained hash table, key `(type<<16)+id`; O(1) |

**Key event structure (0x1C4 bytes):** `+0x08/+0x0C` key · `+0x30` trigger (vtable slot `0x18`) · `+0x74` immediate effects (slot `0x2C`) · `+0xB0` options · `+0xC0` MTTH block · `+0x1A3` probably `fire_only_once` **[I]**.

**Three firing paths:** (a) MTTH scan; (b) delayed events: country vector `country+0x68..0x6C` in `FUN_005091A0` (0x0050B5CE) and province vector `province+0x384..0x388` in `FUN_004B1A10` (0x004B1F13), with `item+0x54` decreasing by 1 per call; (c) `on_action` pulses in `FUN_005091A0` (0x0050B1F4, 16/18/15-character strings, **[I]**).

## 3. What `FUN_005091A0` (Country_DailyUpdate) does **[C] except where marked**

1. Iterates the country's provinces and their pops. If `pop.id % month_length == day_of_month`, calls `FUN_00957EA0` (monthly pop update distributed across days **[I]**). If the pop reaches size 0, calls `FUN_004B9250` (merges it with another pop of the same type **[I]**).
2. Player only: statistics (`FUN_00966760/00966880`) **[?]**.
3. Migration **[I]**: scores by province, sorts with `FUN_0054B200` (MSVC `std::sort`), distributes with `FUN_004BA430`.
4. `country+0xBD4` list: daily roll that appears to handle leader deaths by age **[I]**.
5. Military AI blocks and lists `country+0x7B4`, `+0x149C`, `+0x148C` **[?]**.
6. O(countries²) loop (0x0050ABF0): for every country with provinces, calls `FUN_0092E290` with the `country+0xBE8[other]` relation.
7. Goods, prices, unit updates, and rank.
8. Events: `on_action` pulses and delayed events.

**`FUN_0092E290`** (`CountryRelation_DailyPurge`): purges relation lists (`+0x50`, `+0x2C`, `+0x30`, `+0x28`, `+0x20`) using a `vtable[0x18]` condition and generates messages **[I]**. Each block is skipped if its list is empty, so with little active diplomacy each pair costs roughly 5–6 null-pointer checks.

## 4. EXE patches (status)

**Patch 1 — dead pop loop in the event window** (only affects the player's window)

`0x008A9428`: `0F 84 3A 01 00 00` → `E9 3B 01 00 00 90`

**Patch 2 — skip already-fired `fire_only_once` events earlier** (two 66-byte code caves at `0x00C89120` and `0x00C89170`)

- Entry points: `0x008A7DDF`: `8B 53 30 8B 52 18` → `E9 3C 13 3E 00 90` · `0x008A7FC0`: same bytes → `E9 AB 11 3E 00 90`.
- Cave A (`0x00C89120`):
`80 BB A3 01 00 00 00 74 29 8B 4B 08 8B 53 0C 89 4C 24 38 89 54 24 3C 8B 4C 24 14 81 C1 64 0B 00 00 8D 44 24 38 E8 F6 8B D3 FF 85 C0 74 04 3B C3 74 0B 8B 53 30 8B 52 18 E9 88 EC C1 FF E9 9F ED C1 FF`
- Cave B (`0x00C89170`):
same, but `E8 A6 8B D3 FF` … `E9 19 EE C1 FF E9 30 EF C1 FF`.
- Changes the random-number sequence: in multiplayer everyone must use it.
- Status: the user applied it and **noticed no improvement**. In a later Ghidra listing both sites show the original bytes; it is worth checking whether it is still applied.

**Patch 3 — event scan every 4 days** (already visible in the `FUN_008A7CD0` listing)

- `0x008A7D33` (21 bytes): `83 E0 03 83 F8 02 0F 84 03 02 00 00 83 F8 01 0F 85 C0 03 00 00` (countries `days%4==1`, provinces `days%4==2`).
- `0x008A7DF7`: `6A 01` → `6A 02` · `0x008A7FD8`: `6A 02` → `6A 04` (compensate the probability).

Caves in use: `0x00C89120–0x00C89161` and `0x00C89170–0x00C891B1`. Free (to verify): `0x00C891B2–0x00C891FF`.

## 5. User finding: `Country_DailyUpdate` is the bottleneck

- Test: replace the `CALL` at `0x00685ED1` with `83 C4 08 90 90` (`ADD ESP,8; NOP; NOP`, correct because the function ends with `RET 8`) → **clear performance improvement**.
- Removing it entirely breaks mechanics (army movement). Goal: day 1 → all countries, day 2 → none, day 3 → all… without processing two days together.
- Loop: `0x00685EC0` processes one country, `0x00685EEF` advances to the next, `0x00685EF1` is the exit. **Decision point: `0x00685EB2`, jumping to `0x00685EF1`** (not inside the loop, otherwise countries would be alternated).
- Correct exclusions: `0x00685EAD/EB0` (`CMP EAX,4; JLE`) compares the country-list size, not a day; `UpdateTimeThrottle` (`0x00685620`) controls real-time pacing, not the calendar.
- The outstanding question was who writes `[world+0xB0C]` → see §6.

## 6. Answer: `[world+0xB0C]` is the date, in hours **[C]**

- It is written in `Update_World_and_Advance_Time`, `0x00682FA5`: `ADD dword ptr [ESI+0xB0C],0x18`. Each call adds **exactly one day**.
- `Economy_ProcessMonthlyTick` is called immediately afterward (`0x00683AB1`), so **one execution of the country loop = one game day**. No artificial counter is needed: use the parity of `(date − 0x29C55C0)/24`.

## 7. Clarifications to the user's notes

- Their "Country_DailyUpdate" is `FUN_005091A0` (2 arguments: country and random-number array; `RET 8`).
- `Economy_ProcessMonthlyTick` is **not** monthly: it is the world's daily tick.
- Launcher conversion: `VA − 0x00400000` is the convention the user uses; their example `00C8911A → 0x88851A` is incorrectly calculated: `0x00C8911A − 0x00400000 = 0x0088911A`. The other two examples (`0x285EB2`, `0x285ED1`) are correct. Earlier `VA − 0x00400C00` was given; the PE section table should be checked to confirm which convention applies to the actual EXE.

## 8. Warning: skipping every other day changes the simulation

Inside `FUN_005091A0` there is logic tied to *every* day:

- **Pops:** only pops satisfying `id % month_length == day_of_month` are updated. If that day is skipped, **that pop is not updated during the entire month** (roughly half the pops).
- **Delayed events** for countries and provinces: the counter decreases by 1 per call → delays measured in days become **twice as long**.
- **`on_action` pulses**, leader-death rolls, and other daily rolls happen half as often.
- Multiplayer: everyone must use the same patch.

Therefore it is better to **identify the expensive sub-block first** before skipping the entire function.

## 9. Design of the "every other day" patch (proposal, requires verification)

At `0x00685EB2` there is `EB 0C` (`JMP` to `0x00685EC0`) followed by 12 bytes of padding that are never executed. Replace the first 5 bytes with a jump to a cave.

- **Entry `0x00685EB2`:** `E9 09 33 60 00` (`JMP 0x00C891C0`).
- **Cave `0x00C891C0`** (uses only EAX, ECX, and EDX; preserves EBX, ESI, EDI, EBP):

```asm
8B 83 0C 0B 00 00        mov  eax,[ebx+0B0Ch]
2D C0 55 9C 02           sub  eax,029C55C0h
33 D2                    xor  edx,edx
B9 18 00 00 00           mov  ecx,18h
F7 F1                    div  ecx              ; eax = days
A8 01                    test al,1
75 05                    jnz  process         ; odd day: process all
E9 14 CD 9F FF           jmp  00685EF1h        ; even day: skip all
process:
E9 DE CC 9F FF           jmp  00685EC0h
```

Checks performed: the `rel32` values are `destination − (address+5)`; `0x00685EF1` and `0x00685EC0` are the labels from the listing; `ESI = 1` (first country) remains intact when returning to `0x00685EC0`.

**Diagnostic tests** (to identify which part is expensive; not for normal gameplay):

- Skip the relation loop: `0x0050ABFA`: `0F 8E 4E 00 00 00` → `E9 4F 00 00 00 90`.
- Skip the pop traversal: `0x00509351`: `8B 83 D8 09 00 00` → `E9 3F 01 00 00 90` (pops would stop updating).

## 10. Unresolved

1. Which sub-block of `FUN_005091A0` dominates the cost (pops, migration, relations, or something else).
2. Trigger evaluator (vtable slot `0x18` at `0x00DF9994`) and who fills `country+0x08` / `province+0x14`.
3. Event-body parser (vtable slot 3 at `0x00E2C834`) and meaning of flags `+0x1A0..+0x1A4`.
4. `FUN_00957EA0` (pop update) and unidentified country routines (`FUN_00538150`, `00507770`, `005370B0`, `00538200`, `0050C6D0`, `0053F0C0`).
5. A sampling profile of an advanced save (Very Sleepy or similar) to settle the discussion with data.
