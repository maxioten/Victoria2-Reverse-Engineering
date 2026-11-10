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
