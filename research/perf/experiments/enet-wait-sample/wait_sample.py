#!/usr/bin/env python3
"""EIP sampling profiler for a running Wine game process (same-user, parent).

Seizes all threads of PID, samples each instruction pointer at RATE Hz for
SECONDS, and classifies samples by module and address. Answers: what fraction
of each thread's time is spent inside enet_socket_wait (0xA8B400), i.e. blocked
in select(), and where else time goes.

Read-only: threads are interrupted for microseconds per sample, then resumed.
No code is modified. Must run as the parent of the game (ptrace_scope=1).

Output JSON: per-thread sample counts and wait fractions, EIP histogram for
the game image, module histogram, 64-bit syscall histogram, achieved rate.
"""
import argparse
import collections
import ctypes
import ctypes.util
import json
import os
import time
from pathlib import Path

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
libc.ptrace.restype = ctypes.c_long
libc.ptrace.argtypes = [ctypes.c_ulong, ctypes.c_ulong,
                        ctypes.c_void_p, ctypes.c_void_p]

PTRACE_SEIZE = 0x4206
PTRACE_INTERRUPT = 0x4207
PTRACE_CONT = 7
PTRACE_DETACH = 17
PTRACE_GETREGS = 12
WALL_T = os.WNOHANG

WAIT_START = 0xA8B400
WAIT_END = 0xA8B800  # refined post-hoc from the EIP histogram


def ptrace(req, tid, addr=0, data=0):
    ctypes.set_errno(0)
    res = libc.ptrace(req, tid,
                      ctypes.c_void_p(addr) if addr else None,
                      ctypes.c_void_p(data) if data else None)
    return res, ctypes.get_errno()


def decode(buf):
    u64 = [int.from_bytes(buf[i*8:(i+1)*8], "little") for i in range(27)]
    u32 = [int.from_bytes(buf[i*4:(i+1)*4], "little") for i in range(17)]
    # WOW64: 64-bit task executing 32-bit code has cs == 0x23 with the
    # real EIP in the low 32 bits of rip.
    if u64[17] == 0x23:
        return ("32", u64[16] & 0xFFFFFFFF, u64[17], u64[15] & 0xFFFFFFFF)
    if u32[13] == 0x23:
        return ("32", u32[12], u32[13], u32[11])
    return ("64", u64[16], u64[17], u64[15])


def parse_maps(pid):
    """Return [(start, end, name)] for executable regions."""
    regions = []
    for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
        parts = line.split()
        if len(parts) < 5 or "x" not in parts[1]:
            continue
        start_s, end_s = parts[0].split("-")
        name = parts[5] if len(parts) > 5 else ""
        regions.append((int(start_s, 16), int(end_s, 16), name))
    return regions


def find_module(regions, addr):
    for start, end, name in regions:
        if start <= addr < end:
            short = name.rsplit("/", 1)[-1] if name else "anon"
            return short, addr - start
    return "unmapped", addr


def list_tids(pid):
    try:
        return sorted(int(t) for t in os.listdir(f"/proc/{pid}/task"))
    except FileNotFoundError:
        return []


def seize(tids):
    seized = set()
    for tid in tids:
        res, _ = ptrace(PTRACE_SEIZE, tid)
        if res == 0:
            seized.add(tid)
    return seized


def sample_thread(tid, buf):
    """Interrupt one thread, read regs, resume. Returns decoded tuple or None."""
    res, _ = ptrace(PTRACE_INTERRUPT, tid)
    if res != 0:
        return None
    deadline = time.monotonic() + 0.05
    stopped = False
    while time.monotonic() < deadline:
        try:
            wpid, status = os.waitpid(tid, WALL_T)
        except ChildProcessError:
            return None
        if wpid == tid and os.WIFSTOPPED(status):
            stopped = True
            break
        time.sleep(0.0005)
    if not stopped:
        return None
    res, _ = ptrace(PTRACE_GETREGS, tid, 0, ctypes.addressof(buf))
    if res != 0:
        ptrace(PTRACE_CONT, tid)
        return None
    out = decode(buf.raw)
    ptrace(PTRACE_CONT, tid)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--seconds", type=float, default=40.0)
    ap.add_argument("--rate", type=float, default=50.0)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    pid = args.pid
    regions = parse_maps(pid)
    game_base = None
    for start, end, name in regions:
        if name.endswith("v2game.exe"):
            game_base = start
            break
    print(f"game_base={hex(game_base) if game_base else None} "
          f"regions={len(regions)}")

    tids = seize(list_tids(pid))
    print(f"seized {len(tids)} threads")
    if not tids:
        raise SystemExit("no threads seized")

    period = 1.0 / args.rate
    per_thread = collections.Counter()
    per_thread_wait = collections.Counter()
    eip_hist = collections.Counter()
    mod_hist = collections.Counter()
    syscall_hist = collections.Counter()
    buf = ctypes.create_string_buffer(512)
    deadline = time.monotonic() + args.seconds
    rounds = 0
    next_scan = time.monotonic()
    try:
        while time.monotonic() < deadline:
            tick = time.monotonic()
            if tick >= next_scan:
                for tid in list_tids(pid):
                    if tid not in tids:
                        if ptrace(PTRACE_SEIZE, tid)[0] == 0:
                            tids.add(tid)
                next_scan = tick + 1.0
            for tid in sorted(tids):
                sample = sample_thread(tid, buf)
                if sample is None:
                    if not Path(f"/proc/{pid}/task/{tid}").exists():
                        tids.discard(tid)
                    continue
                mode, ip, cs, orig = sample
                per_thread[tid] += 1
                if mode == "32":
                    if WAIT_START <= ip < WAIT_END:
                        per_thread_wait[tid] += 1
                        eip_hist[ip] += 1
                    elif game_base and game_base <= ip < game_base + 0x1000000:
                        eip_hist[ip] += 1
                    else:
                        mod, off = find_module(regions, ip)
                        mod_hist[f"32:{mod}"] += 1
                else:
                    mod, off = find_module(regions, ip)
                    mod_hist[f"64:{mod}"] += 1
                    syscall_hist[orig] += 1
            rounds += 1
            wait = tick + period - time.monotonic()
            if wait > 0:
                time.sleep(wait)
    finally:
        for tid in sorted(tids):
            ptrace(PTRACE_INTERRUPT, tid)
        for tid in sorted(tids):
            try:
                os.waitpid(tid, WALL_T)
            except ChildProcessError:
                pass
            ptrace(PTRACE_DETACH, tid)

    wall = args.seconds
    summary = {
        "pid": pid,
        "seconds": wall,
        "rate_hz": args.rate,
        "rounds": rounds,
        "threads": len(per_thread),
        "per_thread": {str(t): per_thread[t] for t in sorted(per_thread)},
        "per_thread_wait": {str(t): per_thread_wait[t]
                            for t in sorted(per_thread_wait)},
        "per_thread_wait_frac": {
            str(t): round(per_thread_wait[t] / per_thread[t], 5)
            for t in sorted(per_thread) if per_thread[t]},
        "total_samples": sum(per_thread.values()),
        "total_wait": sum(per_thread_wait.values()),
        "eip_top": [[hex(a), c] for a, c in eip_hist.most_common(60)],
        "eip_distinct": len(eip_hist),
        "modules": dict(sorted(mod_hist.items(),
                               key=lambda kv: -kv[1])[:20]),
        "syscalls": {hex(k): v for k, v in syscall_hist.most_common(20)},
    }
    print(json.dumps({k: v for k, v in summary.items()
                      if k not in ("eip_top",)}, indent=1))
    Path(args.out).write_text(json.dumps(summary, indent=1) + "\n")
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
