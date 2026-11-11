# Experiment: counting the ENet socket wait (mechanism)

## Question

The companion experiment
[`../enet-wait-sample/`](../enet-wait-sample/) bounded time blocked in
`enet_socket_wait` at ≤0.13 ms/day in single player, but sampling cannot
catch µs-scale calls. Open mechanism question: is the wait never called, or
called with a ~0 timeout?

## Method

`count_wait.py` drives the proven x32dbg headless + MCP bridge
(day-tick-lab pattern): it verifies site bytes at runtime, arms an entry
breakpoint at the single wait call site `0x00A89E43` (reads the timeout from
ECX per hit; a one-shot exit breakpoint at `0x00A89E48` reads EAX on the
first 10 hits), and counts exact days with a calendar breakpoint at
`0x00682FA5` (clock value read through the debugger, +24 verified per day).
Stops neither create nor drop waits, so hits/day is exact. Ends at 30 days,
200 hits, flood escape (>100 hits before day 5), or 1800 s wall.

`client.py` is the lab's JSON-RPC helper for the bridge (stdlib only; the
bridge token in `debugger/mcp_config.json` stays local).

## Verified static facts (v2game.exe 3.04, SHA-256 `62d48c20…d6648`)

Same call graph as `enet-wait-sample` (single call site `0x00A89E43`,
`select` import at `0x00A8B477`, ECX = timeout), plus at runtime: module
base `0x00400000`, entry bytes `E8 B8 15 00 00`, exit bytes `85 C0`,
calendar bytes `83 86 0C 0B 00 00 18`.

## Result — 2026-11-11

30 days (`59892120` → `59892816`, every step +24), world `0x1d6e610`:

- **0 entry hits in 30 days. 0 loading-phase hits.**
- No flood, no stray pauses; counting loop wall 14.3 s.

The wait is **never called** in this single-player session — menu, loading,
and 30 max-speed days. Not a timeout question at all: the call does not
happen, so the `enet-timeout-zero` patch (which rewrites that call's timeout
load) could never take effect here. This confirms the A/B nulls
mechanistically and closes the ENet line: no `select()` win is available in
single player on this build.

Scope: single player only, vanilla 3.04 under Wine. Multiplayer paths (the
other 15 `enet_host_service` callers) are untouched and unmeasured; the
profile's 46–51 ms/day attribution does not reproduce here and must come
from elsewhere (different configuration or misattribution).

## Files

- `count_wait.py`: debugger-driven counter described above.
- `client.py`: stdlib JSON-RPC helper for the MCP bridge.
- Local evidence (receipt JSON, screenshots, debugger log, full `rpc.jsonl`):
  kept out of the repo with the other campaign data; aggregates only are
  published here.
