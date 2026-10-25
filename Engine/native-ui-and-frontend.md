# Native UI and single-player frontend

The frontend resolves controls by name and dispatches native GUI signals. Save
loading, entering gameplay, pausing and exiting are separate operations with
separate observable state. A displayed country is also distinct from human
ownership and AI scheduling.

These findings target the English Windows Heart of Darkness 3.04 executable:
SHA-256 `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`,
12,294,656 bytes, x86, preferred image base `0x00400000`. Addresses below are
**preferred-base VAs**; object offsets and vtable byte offsets are marked `+`.
At runtime use `loaded_base + (VA - 0x00400000)`.

## Evidence and scope

The source is Smedley's [campaign-automation evidence](https://github.com/adrunkhuman/smedley_kernel/blob/a87832e6196168b6b6ac82701dc3f1dd95732848/mappings/evidence/campaign-automation.md),
[speed-control evidence](https://github.com/adrunkhuman/smedley_kernel/blob/a87832e6196168b6b6ac82701dc3f1dd95732848/mappings/evidence/speed-control.md)
and [mapping catalog](https://github.com/adrunkhuman/smedley_kernel/blob/a87832e6196168b6b6ac82701dc3f1dd95732848/mappings/v2game-3.04.toml).
The checked call wrappers and controller lookup are in
[`kernel/game_state/src/runtime.cpp`](https://github.com/adrunkhuman/smedley_kernel/blob/a87832e6196168b6b6ac82701dc3f1dd95732848/kernel/game_state/src/runtime.cpp).

Here, **runtime-correlated** means an operation was exercised in that supported
game and correlated with the stated field or lifecycle change. **Static** means
reviewed code/callers support the claim without establishing all runtime cases.
The historical runtime record lacks exact-built-commit provenance: it supports
the exercised engine boundaries, not acceptance of later Smedley builds. Byte
matches alone do not establish an ABI or safe mutation contract.

This is a single-player route, exercised with unmodded and native GFM saves.
Multiplayer Play, arbitrary mods, repeated campaign loads in one process and a
native return-to-menu operation remain unestablished.

## Frontend controllers

| Object | Constructor | Primary vtable | Scalar deleting destructor | Verified narrow fields |
| --- | --- | --- | --- | --- |
| Main-menu controller | `0x00754A00` | `0x00E13DBC` | `0x00754DF0` | GUI registry pointer `+0x704` |
| Single-player frontend controller | `0x0076A2F0` | `0x00E14ED0` | `0x0076B030` | GUI registry pointer `+0x278`; selected-save string `+0x590`; request byte `+0x5BC`; completion byte `+0x5BD` |

These are borrowed live objects, not complete class layouts. The primary vtable
identifies the captured controller while it is alive; it does not extend its
lifetime. Constructor/destructor capture provides a bounded way to invalidate a
reference before storage is released. Frontend operations were correlated on
the captured constructor thread, not on arbitrary worker threads.

### Named lookup and signals

| Route | Native mechanism | Evidence |
| --- | --- | --- |
| Main menu → Single Player | Read controller `+0x704`; registry vtable `+0x6C` resolves `mainmenu_panel`; returned panel vtable `+0x34` resolves `single_player_button` | Runtime-correlated dispatch; main-menu update `0x00754F90` independently supports the lookup chain statically |
| Lobby → Play | Read controller `+0x278`; registry vtable `+0x34` resolves `play_button` | Runtime-correlated; constructor binds listener `0x00772300` |
| Press | Signal address is the resolved control `+0x54`; pass it in **EAX** to `0x009EE510` | Runtime-correlated for Single Player and Play |
| Release | Pass the same signal address in **EAX** to `0x009EE550`, after press | Same bounded coverage |

The lookup wrapper uses an x86 `__thiscall` target with the registry/panel in
ECX and a pointer to an MSVC engine string on the stack. The signal dispatchers
are **not ordinary `__thiscall(control)` functions**. They take the signal in
EAX, walk listeners from signal `+0x4`, and invoke listener virtual byte slots
`+0x8` (press) or `+0x10` (release); the next listener node is `+0x8`.

Calling press/release is native signal dispatch, not a synthetic mouse click.
It does not establish a universal button API: arbitrary controls, listener
lifetimes, nested destruction and all input-event variants have not been
validated. Recheck object identity and lifetime after a lifecycle-changing
callback rather than keeping the controller as a durable handle.

### Save selection, loading and Play

1. The single-player controller holds the selected save basename in an engine
   string at `+0x590`. In the checked automation route, only a canonical empty
   inline string was constructed; malformed metadata or a different existing
   name was rejected. These are implementation preconditions, not permission
   to overwrite an arbitrary live string.
2. A requested load has bytes `+0x5BC = 1`, `+0x5BD = 0`. The normal lobby update
   calls `CCurrentGameState::LoadSave` at `0x0076F8B3`, targeting `0x0067F1D0`.
   The exercised successful path completes post-load work, clears the request
   byte and sets the completion byte.
3. Completion is observed before Play dispatch. Resolve `play_button` and send
   the native press/release signals; listener `0x00772300` is the confirmed
   **single-player** listener, not a proven multiplayer callback.
4. Independently verify the active controller at `CGameState+0xB24` changes
   from RTTI `CFrontEnd` to `CInGameIdler`. A load-completion byte alone does
   not prove that a campaign has entered gameplay.

The global game-state pointer is `0x012588E8`. The field at world `+0xB24` is
phase-dependent controller state, not a permanently usable in-game idler.
This frontend route complements [gameplay load finalization](loading-initialization.md);
it does not prove names or enum values for all initialization phases.

## In-game speed and pause

Speed selection and pause state are independent. `CGameState+0xB28` is the
native speed index `0..4`, displayed as speeds `1..5`. Consumers index a
five-element table; writing index `5` is unsafe.

| Control | Callback | Idler virtual byte slot | Idler method | Message handler |
| --- | --- | --- | --- | --- |
| `button_speedup` | `0x00718CE0` | `+0x164` | `0x0066A0D0` | `0x0072EE90` |
| `button_speeddown` | `0x00718CF0` | `+0x168` | `0x0066A1B0` | `0x0072EFE0` |

The handlers increment/decrement world `+0xB28` and clamp to `0..4`. The
native control chains are runtime-correlated; decrement coverage includes
selecting displayed speed 2 from a higher speed, not every initial state.
Read back the index after each requested transition. These handlers select a
speed; [daily pacing and intra-day servicing](game-speed.md) are different
mechanisms.

`CInGameIdler::TogglePause` at `0x0066A2C0` is an x86 `__thiscall` method with
idler in ECX. Manual Space and the checked native invocation correlate with
byte `idler+0x1538`. Require current idler RTTI and a byte value of `0` or `1`;
invoke only when a transition is needed, then read back the requested state.
Pause alone does not distinguish ordinary pause from game over.

## Country view, ownership and AI

| State | Location | Meaning / limit |
| --- | --- | --- |
| Current view tag/index | World `+0xB5C/+0xB60` | Country used as the UI perspective; not sufficient to establish human ownership |
| Human-control entries | World vector `+0xAEC` | Nonzero entry means human control; zero alone does not establish AI scheduling |
| Country AI object | `CCountry+0x208` | Pointer must be non-null **and** present in world AI scheduler vector `+0xA4` for the checked full-AI observer route |
| Return to AI | `0x00687A70` | Native boundary clears human control and constructs/registers `CCountryAI`; verify both pointer and scheduler membership |

The checked observer route retains a country for viewing rather than creating
a null-country spectator UI. It requires all human-control entries zero and
verifies scheduled AI participation; directly writing the view tag establishes
neither property.

The registered native `tag` handler at `0x0041F720` starts an **asynchronous**
ownership/view transition. Handler return is not completion. The checked
manual switch pauses, invokes the saved native handler, waits for ownership
transition, restores target AI participation and verifies scheduler count
before resuming. Calling `tag` inside a synchronous annexation boundary cannot
substitute for a completed view-field handoff before native province removal.
This is a narrow ownership/lifecycle finding, not a general safe direct-tag
write or console ABI.

## Game over and native exit

The branch at `0x0065548D` compares the raw world date `+0xB0C` with the end
date at `+0xC` of the object pointed to by `0x012586DC`. It then checks the
idler's endgame-dialog pointer `+0x1D6C` and dialog visibility byte `+0x67`.
The correlated window primary vtable is `0x00E3C0D8`.

The checked game-over discriminator is **date beyond the configured end plus a
visible matching dialog**, not pause state or dialog existence. The same
window vtable can be present with visibility zero during ordinary pause. An
unreadable or unexpected object makes the observation unavailable, not false.
Only the end-date field is correlated here; this does not establish the entire
defines layout or every possible game-over cause.

The accepted quit/resign dialog callback `0x00676500` distinguishes the
`RESIGN` case (controller virtual `+0x114`) from the other branch used by an
accepted `QUIT` (virtual `+0x110`). For the in-game idler, `+0x110` targets
`CInGameIdler::RequestQuit` at `0x0064EDB0`:

```asm
mov byte ptr [ecx+0x1D20], 1
ret
```

This requests native exit; it is not external process termination. Require
current idler identity, the expected virtual target and request-flag readback.
The exercised route exited normally, but this method does not itself promise
a checkpoint save, final game-state assertion, plugin drain or pre-exit
notification. The `RESIGN` branch is not a verified return-to-menu capability.

## Definition-only controls and static candidates

Shipped GUI definitions supply names, not native object addresses or handler
contracts. Smedley's [GUI catalog](https://github.com/adrunkhuman/smedley_kernel/blob/a87832e6196168b6b6ac82701dc3f1dd95732848/mappings/gui-controls-3.04.toml)
records these independently:

| Definition file | Selected control names |
| --- | --- |
| `interface/temp_frontend.gui` | `single_player_button`, `save_game` |
| `interface/lobby.gui` | `save_games_list`, `play_button` |
| `interface/topbar.gui` | `button_speedup`, `button_speeddown`, `pause_bg`, `speed_indicator` |
| `interface/country_budget.gui` | `tax_0_slider`, `tax_1_slider`, `tax_2_slider`, `tariff_slider`, `take_loan`, `repay_loan`, loan-window `money_slider` controls |

Additional **static cross-reference candidates**, not runtime-verified control
APIs, are budget input handler `0x00606780` (compares `take_loan`), topbar
control binding `0x007129A0` (resolves named controls), and topbar tooltip/text
handlers `0x00709910` / `0x00713A90`. Finding a name in a tooltip handler does
not identify an action callback. The budget slider bindings remain candidates;
no arbitrary slider mutation or complete GUI class layout is established.
