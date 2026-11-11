# Experiment: direct measurement of the ENet socket wait

## Question

How much time per game day is spent blocked in `enet_socket_wait`
(`0x00A8B400`, which blocks in `select()`), in single player?

Two wall-clock A/B campaigns (10 interleaved pairs, pooled median −1.7 ms/day)
could not resolve the ~46–51 ms/day attributed to this wait in
[`Engine/performance-profile.md`](../../../../Engine/performance-profile.md):
the effect, if any, is below the run-to-run noise (±70–200 ms/day). This
experiment measures the wait directly instead of differencing two noisy
timers.

## Verified static facts (v2game.exe 3.04, SHA-256 `62d48c20…d6648`, base `0x00400000`)

| Fact | Evidence |
|---|---|
| `enet_socket_wait` is at `0x00A8B400` | ENet timeout-splitting prologue (`mul ecx`, divide by 1000 by magic `0x10624DD3`); `select` via import pointer at `0x00A8B477` (`FF 15 30 A3 C8 00`) |
| Single direct call site: `0x00A89E43` | Full `.text` scan for `E8` resolving to `0x00A8B400`; bytes `E8 B8 15 00 00`. All socket waits flow through it |
| `NetSession_Service` (`0x00A61780`) calls `enet_host_service` (`0x00A89D00`) at `0x00A618CC` | Bytes `E8 2F 84 02 00`, timeout loaded at `0x00A618C0` |
| `enet_host_service` has 16 call sites | Full `.text` scan for `E8` resolving to `0x00A89D00` |
| Timeout register is ECX, socket in EDI, condition in ESI | `enet_socket_wait` prologue consumes ECX (timeout split) and ESI (`mov eax,[esi]` flag test) |
| Daily tick call at `0x00683AB1` | Bytes `E8 0A 1F 00 00` → `0x006859C0` (6906-byte day function) |

## Method

`wait_sample.py` is an EIP sampling profiler. It runs as the parent of the
game (required by `ptrace_scope=1`), seizes every game thread, and at ~50 Hz
interrupts each thread for microseconds, reads registers, and resumes it.
Samples are classified by module; EIP inside `0x00A8B400–0x00A8B800` counts as
blocked in the wait. A full EIP histogram is kept so the wait range is
confirmed post-hoc from clustering instead of assumed.

Days are counted from the calendar clock itself: every address holding the
initial clock (`43800000 + 1837*365*24`) while paused is tracked, and
addresses stepping by exactly +24 per day identify the clock. Total days come
from first/last values, exact to the day.

Metric: `main_wait_frac × wall_s / days` = blocked wall ms per game day,
directly comparable to the profile attribution. No code is modified; no
compiler is needed (the hook approach was dropped because no 32-bit toolchain
is installed and debugger breakpoints would distort the very durations being
measured; EIP sampling costs each thread ~50 µs × rate).

Overhead is quantified by comparing days/sec with and without the sampler.

## Results — 2026-11-11

| Run | Mode | Days | ms/day | Wait-range samples |
|---|---|---:|---:|--:|
| mainonly2 | main thread, 50 Hz, 30 s | 207 | 121.9 | 0/1468 |
| sweep | all 23 threads, 30 Hz, 30 s | 82 | 125.7 | 0/20470 |

Both runs at full speed (matching the fastest wall-clock campaign runs, so
sampling does not distort the game). Clock tracking: 1286 candidates,
414–427 qualifying addresses stepping exactly +24/day (heap ASLR moves the
clock between runs; the method does not assume its address). Hottest EIP
`0xAC02F5` (5%, the `0xAC02A0` arithmetic-helper area from the day profile);
53% of sweep samples in futex (software-rendering wineserver RPC).

**0 wait-range samples in 21,938 thread-samples over 289 game days.**
Main-thread pooled 0/2950 → 95% upper bound 0.10% of thread time →
**≤0.13 ms/day** blocked in `enet_socket_wait`/`select()` in single player.
The profile's 46–51 ms/day does not reproduce as single-player main-thread
select block (≈350× refuted). Consistent with both wall-clock A/B nulls
(pooled 10-pair median −1.7 ms/day).

Candidate explanations (not distinguished): the runtime timeout collapses
via the dynamic clamp in `enet_host_service` with no peers, or the wait
returns immediately on the loopback. Open follow-up: per-call counts and
runtime timeout values via breakpoint counting (sampling cannot catch
µs-scale calls; the duration bound above stands regardless).

Superseded runs (kept in local evidence, not in the table): an all-thread
smoke run with a 32-bit-blind decoder (zero is meaningless), two slow runs
under host load 4–10, and a clock-only control stopped early by an event
modal (which also confirmed clock-span dating is pause-robust).

## Files

- `wait_sample.py`: ptrace EIP sampler (parent process, read-only).
- `run_wait_sample.py`: orchestrator — launches the private copy, loads the
  fixed save through the UI, samples, counts days from the clock.
- Local evidence (run JSONs, screenshots): kept out of the repo with the other
  campaign data; aggregates only are published here.
