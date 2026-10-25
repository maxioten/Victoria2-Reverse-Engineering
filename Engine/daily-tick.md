# Frame, hourly tick and daily tick

How the game turns wall time into game days, what runs once per day, and why a day at max speed takes
several frames.

Source: research of October 2026: static reading in Ghidra of `v2game.exe` 3.04 and
measurements on TGC 1836 at max speed with a call-timing profiler and a sampling profiler. Builds on
`Engine/engine-structure.md` and `Engine/Country_Daily_Update.md` of this repository. Marks: **[C]**
read in the code, **[I]** inferred, **[M]** measured.

## Summary

- One frame = `CInGameIdler_Update` (`0x00654D80`, vtable slot `0x00E0A350`). Inside it,
  `ProcessGameTimeAdvance` (`0x00682BD0`) decides whether time advances (see [game-speed.md](game-speed.md));
  each step is a queued `CHourlyTickCommand`.
- `Update_World_and_Advance_Time` (`0x00682EC0`) adds 24 to the date on every call, so the "hourly" command
  advances a whole day, and calls `DayTick` once. **[C]**
- `DayTick` (`0x006859C0`) is the daily simulation: provinces, then countries, then the event scan. It runs
  once per day. **The name `Economy_ProcessMonthlyTick` used earlier for `FUN_006859C0` is wrong.** **[C]**
- In vanilla 1836 a day costs ~196 ms at max speed, ~45 % of it outside the simulation (see
  [performance-profile.md](performance-profile.md)).

## Call chain **[C]**

```text
CInGameIdler_Update (0x00654D80)                                  per frame
  ProcessGameTimeAdvance (0x00682BD0)                             speed table, world+0xB14
  CommandQueue_Process (0x009AF9F0)                               runs queued commands through CALL EAX
    CHourlyTickCommand_Execute (0x0072ECF0, vtable 0x00E12414 slot 6)
      Update_World_and_Advance_Time (0x00682EC0)                  <- 0x0072ECFA
        0x00682FA5  ADD [world+0xB0C], 0x18                        date += 1 day
        DayTick (0x006859C0)                                       <- 0x00683AB1
          per province: FUN_004B9C60 (pop pass, 0x00685B09), Province_DailyUpdate (0x004B1A10, 0x00685B49)
          1000 Mersenne Twister draws                              0x00685B6B
          per country: Country_PrePass (0x00508590)                <- 0x00685C2C
          Economy_Update (0x00489990)                              <- 0x00685F7E
          per country from index 1: Country_DailyUpdate (0x005091A0)   <- 0x00685ED1
               AI_DailyUpdate (0x0085CCB0)                         <- 0x0050B0EB
          ProcessPopStatistics (FUN_0068F4C0, a TBB parallel_for)  <- 0x00685FD6
          end: every AI country is queued for AI_FrameUpdate (see below)
          EventManager_DailyScan (0x008A7CD0) if world+0xD11 == 0  <- 0x006861E8
        monthly: FUN_00687E30 -> ... -> CBManager_IsAnyCBUsable    0x00683B36 (month index changed)
  AI_FrameUpdate (0x006874C0)                                      <- 0x006557C4, per frame
```

`UpdateTimeThrottle` (`0x00685620`) is called ~1400 times a day from inside the tick (14 call sites:
`DayTick`, `Economy_Update`, `WorldMarketUpdate`) and renders a whole frame
(`App_ProcessMessagePumpAndUpdate` `0x009DF2B0`) when enough real time has passed, so the frame code is
re-entered from inside the tick. **[C]** Measured in 1836: about one such frame per day. **[M]**

## Calendar **[C]**

`world+0xB0C` stores the raw date at 24 units per day, with fixed 365-day
years and no leap years. Raw zero is the epoch at year −5000; the offset
`0x029C55C0` = 43,800,000 units = `24 * 365 * 5000` reaches year 0,
not year −5000.

For positive campaign dates, use either equivalent decoding:

```text
absolute_days = floor(raw / 24)
year = floor(absolute_days / 365) - 5000
zero_based_day_of_year = absolute_days % 365

# Alternatively, subtract the epoch offset before decoding the year:
days_from_year_zero = floor((raw - 0x029C55C0) / 24)
year = floor(days_from_year_zero / 365)  # do not subtract 5000 again
```

Encoding a date is
`raw = 24 * (365 * (year + 5000) + zero_based_day_of_year)`.
Month lengths come from `0x00F1027C`.

| Date | Raw value | Evidence |
| --- | ---: | --- |
| 1836.1.1 | 59,883,360 | Derived from the encoding |
| 1836.1.2 | 59,883,384 | Historical runtime-correlated anchor |

The old expression subtracted the 5000-year offset twice. Smedley's
[date evidence](https://github.com/adrunkhuman/smedley_kernel/blob/a87832e6196168b6b6ac82701dc3f1dd95732848/mappings/evidence/telemetry.md#dates-and-world-snapshots)
provides the independent anchor and 24-unit daily progression for the English
Windows 3.04 executable, SHA-256
`62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
Addresses above are preferred-base VAs using image base `0x00400000`; `+0xB0C`
is an object offset. The retained runtime evidence lacks exact-built-commit
provenance and does not promote the surrounding world layout or establish
pre-epoch/negative-date engine behavior.

## `Country_DailyUpdate` (0x005091A0)

`(country, random array)`, `RET 8`, 683 calls/day in TGC (all defined tags; the loop skips countries
without provinces). In order: **[C]** unless marked

1. Pops of every owned province: a pop is updated when `pop.id % month_length == day_of_month`
   (`Pop_MonthlyUpdate` `0x00957EA0`), so each pop is updated once a month, spread over the days. A pop
   at size 0 is merged into another of the same type (`Pop_MergeEmpty` `0x004B9250`). **[I]**
2. Player-only statistics. **[?]**
3. Migration: score provinces, `std_sort`, distribute (`Migration_Distribute` `0x004BA430`). **[I]**
4. Leader list (`country+0xBD4`): daily death-by-age roll. **[I]**
5. Military lists `+0x7B4`, `+0x149C`, `+0x148C`. **[?]**
6. O(n²) loop at `0x0050ABF0`: for every other country with provinces,
   `CountryRelation_DailyPurge(country+0xBE8[other])` (`0x0092E290`, stdcall 1), which purges five relation
   lists. Its top level only reads relation `+0x50 +0xA8 +0x2C +0x30 +0x28 +0x20`; everything else is
   behind a non-zero test, so with those six fields zero the call does nothing.
7. Goods, prices, units, rank; `FUN_0052FCD0` (`0x0050B6B9`, reads `other+0x1580[self]` for every living
   country); `AI_DailyUpdate`; the player's decision alert (`0x0050B792`, player only).
8. Events: `on_action` pulses (`0x0050B1F4`) and delayed events (`country+0x68`, counter `+0x54`
   decremented per call, `0x0050B5CE`).

## Frames per day: the AI job queue **[C]**

At max speed a day takes several frames, not one.

- At the end of `DayTick`, every AI object (`world+0xA4`; `+0x30` tag, `+0x34` country index) of a country
  with provinces is appended to bucket `country % N` of the job queue at `world+0xB84`. Buckets are 16
  bytes `{head, tail, count, flag}`; nodes are `{tag, country index, prev, next}` (next at `+0x0C`);
  N = 1 in single player.
- Every frame `CInGameIdler_Update` calls `AI_FrameUpdate` (`0x006874C0`, stdcall 1, at `0x006557C4`)
  with a pointer to bucket 0 when it is not empty. It pops jobs and runs `AI_CountryFrameJob`
  (`0x0081E9E0`) for countries that still have provinces and an AI object (`country+0x208`) until the
  bucket is empty **or 0.02 s have passed** (double at `0x00E456C8`). See [../AI/Ai_daily_jobs.md](../AI/Ai_daily_jobs.md).
- `ProcessGameTimeAdvance` issues the next `CHourlyTickCommand` only when every bucket is empty (and the
  speed accumulator passed its threshold, and this client is the host). The command goes through the
  session and is executed by `CommandQueue_Process` in a later frame.

So a day is: a frame that executes the tick (and fills the queue), more frames while the AI runs 20 ms
at a time, a frame in which the next tick is issued. Every one of them renders. The 20 ms budget is
wall time, so the frame boundaries (and which commands run between AI jobs) already depend on machine
speed in vanilla. Measured in 1836: 3–4 frames per day at max speed. **[M]**

## Randomness **[C]**

The game draws from a 624-word Mersenne Twister list (`g_mtState` `0x00F0ECF0`, index `g_mtIndex`
`0x00F0F6B0`); `Rng_Next` (`0x009B7610`) takes the next value and `Rng_RegenerateMT` (`0x009B7700`)
refills the list when the index wraps. `DayTick` draws 1000 values per day. Anything that changes how
often or in which order the simulation draws changes the sequence, so every player of a multiplayer
game must run the same code. The AI's daily decision roll uses the CRT `rand()` (`0x00AB047B`,
per-thread state in the multithreaded CRT) instead, not the Mersenne Twister (see [decisions.md](decisions.md)).

## Open questions

1. Semantics of the `Country_DailyUpdate` military blocks.
2. What `FUN_00515490` (`Country_Recalculate`, see [performance-profile.md](performance-profile.md)) recomputes
   exactly.
