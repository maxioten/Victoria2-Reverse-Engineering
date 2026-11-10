# Experiment: ENet poll timeout zero

## Hypothesis

`NetSession_Service` calls `enet_host_service` every frame with a 15 ms timeout.
In single player the session is a local loopback with no remote peer, so the
call blocks in `select()` until the timeout expires. Setting the timeout to 0
should remove most of the ~46–51 ms/day attributed to this wait while still
servicing any pending packet.

## Code chain

From [`Engine/network.md`](../../../../Engine/network.md):

```text
CommandQueue_Process (0x009AF9F0)
  -> [obj+0x38]->vt[0x1C](0) at 0x009AFBB1
    -> NetSession_Service (0x00A61780)
      -> enet_host_service (0x00A89D00) at 0x00A618CC
        -> enet_socket_wait (0x00A8B400)
          -> select at 0x00A8B477
```

The timeout is loaded immediately before the call:

```asm
00A618C0: 8B 4B 20        mov ecx, dword ptr [ebx + 0x20]
00A618C3: 8B 43 18        mov eax, dword ptr [ebx + 0x18]
00A618C6: 51              push ecx
00A618C7: 8D 55 C4        lea edx, [ebp - 0x3c]
00A618CA: 52              push edx
00A618CB: 50              push eax
00A618CC: E8 2F 84 02 00  call 0x00A89D00
```

The base session constructor writes `0xF` (15 ms) at `[edi+0x20]`:

```asm
00A5FFCB: C7 47 20 0F 00 00 00  mov dword ptr [edi + 0x20], 0xF
```

## Patch

For the first experiment, replace the load with zero:

| | bytes |
|---|---|
| original | `8B 4B 20` |
| patched | `33 C9 90` (`xor ecx, ecx; nop`) |

This is a **global** experiment: it makes every session non-blocking, including
multiplayer. It is deliberately the smallest change that tests the hypothesis.
If it works, a second experiment will add a single-player guard.

Apply to a copy, never to `base-game/v2game.exe`:

```bash
python research/perf/experiments/enet-timeout-zero/patch.py \
  --input base-game/v2game.exe \
  --output work/enet-timeout-zero/v2game.exe
```

The script verifies the original SHA-256 and the three original bytes, writes a
patched copy, and emits a JSON receipt with both hashes and the file offset.

## Test

1. Baseline: original executable, fixed save, 30 days, 5 runs.
2. Patched: same save and machine, 30 days, 5 runs.
3. Compare with `parse_results.py`.
4. Verify save hash after 30 days.
5. Multiplayer smoke test: host + join, 5 minutes, no disconnect.

## Result — 2026-11-10

Environment: Wine under Xvfb 1280×720 (software rendering), 6-core i5-8600K,
host load average around 9 during the campaign. Fixed save
`a3885cc5…` (Spain, 1837.1.1), 30 game days per run, five baseline and five
patched runs interleaved B/E and E/B. The date was counted from a 60 fps
capture of the date text (30 intervals between the first and the 31st change),
not from a screenshot hash.

| Run | Baseline ms/day | ENet ms/day |
|---|---:|---:|
| 1 | 518.889 | 516.627 |
| 2 | 373.889 | 417.222 |
| 3 | 256.667 | 590.556 |
| 4 | 352.778 | 233.889 |
| 5 | 326.111 | 349.444 |
| **median** | **352.778** | **417.222** |
| p95 | 489.889 | 575.770 |

- Unpaired median delta from `parse_results.py`: **+18.27 %** (ENet slower).
- Paired differences (ENet − baseline): −2.3, +43.3, +333.9, −118.9, +23.3
  ms/day; median paired difference **+23.3 ms/day**, median per-pair ratio
  **+7.2 %**, mean +55.9 ms/day, 95 % CI **−152 to +264 ms/day**.
- CPU utilisation over the recording: median 2.95 (baseline) vs 3.05 (ENet),
  about +3 %; no large busy-loop explosion, but no saving either.
- Save SHA-256 after the campaign: `a3885cc5…` (unchanged).
- Patched executable SHA-256: `1caa7953…`; original `62d48c20…`.

**Conclusion:** this campaign does not show a win from the global timeout-zero
patch. The point estimate is slightly worse and the confidence interval is
wide; the host was too loaded to resolve the ~46–51 ms/day attributed to the
wait in the profile. The global patch is not adopted. A single-player-guarded,
event-driven wait (or a quieter host) is needed before retesting; the current
data are consistent with the block yielding CPU to the simulation/render
threads rather than being pure waste.

## Result — 2026-11-10 (load-gated rerun, same day)

Same save, executables, display and 60 fps video method. Each of the five new
pairs launched only when the 1-minute load average was below 3.0; load
before/after is stamped into each run record.

| Pair | Baseline ms/day | ENet ms/day | ENet − baseline |
|---|---:|---:|---:|
| 1 | 288.066 | 232.778 | −55.288 |
| 2 | 172.951 | 171.838 | −1.113 |
| 3 | 167.946 | 125.000 | −42.946 |
| 4 | 122.222 | 123.333 | +1.111 |
| 5 | 332.222 | 187.409 | −144.813 |
| **median** | **172.951** | **171.838** | **−42.946** |

- `parse_results.py` unpaired median delta: **−0.64 %** (identical).
- Paired mean −48.6 ms/day, 95 % CI **−122.2 to +25.0** (includes zero).
- Median per-pair ratio 0.808 (−19.2 %).
- CPU utilisation median 3.625 vs 3.646: identical, no busy-loop.
- Save SHA-256 unchanged.

Caveats, kept in the record:

- Both arms got ~2× faster from pair 1 to pair 4, an environmental drift, not
  a patch effect. Both arms share one Wine prefix, so a warming wineserver is
  suspected but unproven.
- The first baseline-5 attempt failed (7 date changes in 40 s, game process
  gone, no crash evidence in logs) and was retried. The retry rode a load
  spike (1-minute load 2.09 → 8.13) and its video captured at an effective
  119.6 fps; wall time still comes from real frame timestamps. Pair 5
  dominates the paired mean; without it the median paired difference is
  −22 ms/day (n=4).
- Pooled over both campaigns (10 interleaved pairs): median paired difference
  **−1.7 ms/day**, mean **+3.6 ms/day** — no effect.

**Conclusion stands:** the global patch is not adopted. Next step is a direct
`select()` timing or a guarded, event-driven wait, not more wall-clock A/B in
this environment.

## Acceptance

- Single-player median wall ms/day is lower than baseline by more than run
  noise.
- p95 does not regress.
- Save hash and RNG sequence match the baseline.
- Multiplayer still connects and exchanges packets.
- No busy-loop CPU explosion: CPU time should not increase more than the wall
  time saved.

## Risks

- `enet_host_service` with timeout 0 still polls the socket; CPU time may rise.
- Multiplayer may spin or starve if the timeout is too short.
- The patch changes a code byte; any mismatch in the expected original bytes
  must abort.
- This experiment does not prove that the 46 ms is entirely removable; it
  measures the upper bound of the timeout change.

## Revert

Use the original executable from `base-game/`; the patched copy is separate and
its receipt records the original hash.
