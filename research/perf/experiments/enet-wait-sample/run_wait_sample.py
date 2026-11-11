#!/usr/bin/env python3
"""Direct measurement of time blocked in enet_socket_wait per game day.

Launches the private game copy as a child (ptrace_scope=1 requires a
descendant), loads the fixed save through the UI, and while the game runs at
max speed:

- tracks every memory address holding the calendar clock (world+0xB0C,
  +24 per game day) to count exact days;
- EIP-samples all game threads via ptrace SEIZE/INTERRUPT/GETREGS/CONT and
  classifies samples by module, flagging EIP inside enet_socket_wait
  (0xA8B400, the unique select() wait, single call site 0xA89E43).

Metric: main-thread wait fraction x wall time / days = blocked ms/day,
directly comparable to the 46-51 ms/day attributed to the wait in
Engine/performance-profile.md. Read-only: no code is modified.
"""
import argparse
import collections
import importlib.util
import json
import os
import struct
import subprocess
import time
from pathlib import Path

GAME = "/home/daniel/Documentos/v2/experiments/day-tick-lab/game"
PREFIX = "/home/daniel/Documentos/v2/experiments/day-tick-lab/wine"
DISPLAY = ":99"
INITIAL = 43800000 + 1837 * 365 * 24
CLOCK_STEP = 24

ENV = {
    **os.environ,
    "WINEPREFIX": PREFIX,
    "WINEARCH": "wow64",
    "WINEDEBUG": "-all",
    "WINEDLLOVERRIDES": "winemenubuilder.exe=d;dinput8=b;lua51=n;"
                         "d3dx9_41=n;d3dcompiler_41=n;d3dcompiler_43=n",
    "DISPLAY": DISPLAY,
}

HERE = Path(__file__).resolve().parent
OUTDIR = Path("/tmp/opencode/wait-hook")
GAMELOG = Path("/home/daniel/Documentos/v2/experiments/day-tick-lab/wine/"
               "drive_c/users/daniel/Documents/Paradox Interactive/"
               "Victoria II/logs/game.log")
LAUNCH_MARK = "[[ Launching SINGLEPLAYER-game ]]"


def load_sampler():
    spec = importlib.util.spec_from_file_location(
        "wait_sample", str(HERE / "wait_sample.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def xdo(*args):
    return subprocess.run(["xdotool", *args], env=ENV, capture_output=True,
                          text=True)


def click(win, x, y, delay=1.0):
    xdo("mousemove", "--window", win, str(x), str(y))
    time.sleep(0.2)
    xdo("mousedown", "1")
    time.sleep(0.2)
    xdo("mouseup", "1")
    time.sleep(delay)


def shot(name):
    subprocess.run(["import", "-display", DISPLAY, "-window", "root",
                    str(OUTDIR / f"wait-{name}.png")], check=False)


def date_hash():
    p = subprocess.run(["import", "-display", DISPLAY, "-window", "root",
                        "-crop", "155x22+198+119", "png:-"],
                       capture_output=True)
    if p.returncode != 0:
        raise RuntimeError("import failed")
    import hashlib
    return hashlib.sha256(p.stdout).hexdigest()


def wait_change(timeout=8.0):
    prev = date_hash()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        time.sleep(0.5)
        if date_hash() != prev:
            return True
    return False


def load1():
    try:
        return float(Path("/proc/loadavg").read_text().split()[0])
    except (FileNotFoundError, IndexError, ValueError):
        return 0.0


def wait_gate(thresh, timeout):
    waited = 0.0
    while True:
        cur = load1()
        if cur < thresh:
            return cur
        if waited >= timeout:
            print(f"gate expired at load1={cur}", flush=True)
            return cur
        print(f"load gate: load1={cur} >= {thresh}, waiting...", flush=True)
        time.sleep(30)
        waited += 30


def proc_cpu_self():
    try:
        fields = Path("/proc/self/stat").read_text().split()
        return (int(fields[13]) + int(fields[14])) / os.sysconf("SC_CLK_TCK")
    except (FileNotFoundError, IndexError, ValueError):
        return 0.0


def log_mark():
    try:
        return GAMELOG.stat().st_size
    except FileNotFoundError:
        return 0


def wait_launch(mark, timeout=90.0):
    """True once the game logs a new single-player launch after mark."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with open(GAMELOG, "rb") as f:
                f.seek(mark)
                if LAUNCH_MARK.encode() in f.read():
                    return True
        except FileNotFoundError:
            pass
        time.sleep(2.0)
    return False


def load_save(win):
    click(win, 383, 606, 1)
    click(win, 383, 606, 5)
    click(win, 100, 268, 1)
    click(win, 1178, 674, 10)
    click(win, 1178, 674, 8)


def launch(label):
    log = open(OUTDIR / f"wait-{label}.log", "wb")
    proc = subprocess.Popen(["wine", "v2game.exe"], cwd=GAME, env=ENV,
                            stdout=log, stderr=subprocess.STDOUT)
    return proc, log


def find_window(timeout=120):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        p = xdo("search", "--onlyvisible", "--name", "Victoria 2")
        if p.returncode == 0 and p.stdout.strip():
            return p.stdout.splitlines()[0].strip()
        time.sleep(1.0)
    raise RuntimeError("game window not found")


def scan_clock(pid):
    """All addresses currently holding INITIAL (calendar candidates)."""
    needle = struct.pack("<I", INITIAL)
    hits = []
    with open(f"/proc/{pid}/mem", "rb", buffering=0) as mem:
        for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
            parts = line.split()
            if len(parts) < 2 or "r" not in parts[1]:
                continue
            start, end = (int(x, 16) for x in parts[0].split("-"))
            size = end - start
            if size <= 0 or size > 2**31:
                continue
            offset = 0
            while offset < size:
                chunk = min(8 * 1024 * 1024, size - offset)
                try:
                    mem.seek(start + offset)
                    data = mem.read(chunk)
                except OSError:
                    break
                pos = 0
                while True:
                    idx = data.find(needle, pos)
                    if idx < 0:
                        break
                    hits.append(start + offset + idx)
                    pos = idx + 1
                offset += chunk
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", required=True)
    ap.add_argument("--seconds", type=float, default=40.0)
    ap.add_argument("--rate", type=float, default=50.0)
    ap.add_argument("--no-sample", action="store_true",
                    help="control run: track the clock only, no ptrace")
    ap.add_argument("--threads", default="main", choices=("main", "all"),
                    help="main: sample only the main thread (default, "
                         "minimal distortion); all: sweep every thread")
    ap.add_argument("--gate-load", type=float, default=0.0,
                    help="wait until 1-minute load is below this before "
                         "launching (0 = no gate)")
    ap.add_argument("--gate-timeout", type=float, default=1800.0,
                    help="max seconds to wait for the load gate")
    ap.add_argument("--startup", type=float, default=75.0)
    args = ap.parse_args()
    OUTDIR.mkdir(parents=True, exist_ok=True)
    S = load_sampler()

    subprocess.run(["pkill", "-f", "[v]2game.exe"], check=False)
    time.sleep(2)
    load_before = load1()
    if args.gate_load > 0:
        load_before = wait_gate(args.gate_load, args.gate_timeout)
    proc, log = launch(args.label)
    try:
        time.sleep(args.startup)
        win = find_window()
        print(f"window {win}", flush=True)
        xdo("windowmove", win, "30", "30")
        xdo("windowfocus", win)
        time.sleep(1)
        shot(f"{args.label}-menu")
        mark = log_mark()
        load_save(win)
        if not wait_launch(mark):
            print("save did not load; retrying clicks once", flush=True)
            xdo("key", "--window", win, "Escape")
            time.sleep(2)
            mark = log_mark()
            load_save(win)
            if not wait_launch(mark):
                raise RuntimeError("save did not load after retry")

        pid = proc.pid
        print(f"game pid {pid}", flush=True)
        candidates = scan_clock(pid)
        print(f"clock candidates: {len(candidates)}", flush=True)
        if len(candidates) < 100:
            raise RuntimeError(
                f"only {len(candidates)} clock candidates; save not loaded?")

        if not wait_change():
            xdo("key", "--window", win, "space")
            if not wait_change():
                raise RuntimeError("game did not start")
        xdo("windowfocus", win)
        for _ in range(15):
            xdo("key", "--window", win, "plus")
            time.sleep(0.25)
        time.sleep(0.5)
        shot(f"{args.label}-running")

        regions = S.parse_maps(pid)
        game_base = next((s for s, e, n in regions
                          if n.endswith("v2game.exe")), None)
        has_game = any(n.endswith("v2game.exe") for _, _, n in regions)
        print(f"game mapped: {has_game} "
              f"game_base={hex(game_base) if game_base else None}", flush=True)
        tids = set()
        if not args.no_sample:
            if args.threads == "main":
                if S.ptrace(S.PTRACE_SEIZE, pid)[0] == 0:
                    tids = {pid}
                print(f"seized main thread only: {sorted(tids)}",
                      flush=True)
            else:
                tids = S.seize(S.list_tids(pid))
                print(f"seized {len(tids)} threads", flush=True)
            print(f"game_base={hex(game_base) if game_base else None}",
                  flush=True)

        last = {a: INITIAL for a in candidates}
        transitions = collections.Counter()
        first_seen = {}
        last_seen = {}
        per_thread = collections.Counter()
        per_thread_wait = collections.Counter()
        eip_hist = collections.Counter()
        mod_hist = collections.Counter()
        syscall_hist = collections.Counter()
        import ctypes
        buf = ctypes.create_string_buffer(512)
        period = 1.0 / args.rate
        rounds = 0
        deadline = time.monotonic() + args.seconds
        next_scan = time.monotonic()
        self_cpu0 = proc_cpu_self()
        with open(f"/proc/{pid}/mem", "rb", buffering=0) as mem:
            while time.monotonic() < deadline:
                tick = time.monotonic()
                if tick >= next_scan:
                    if not args.no_sample and args.threads == "all":
                        for tid in S.list_tids(pid):
                            if tid not in tids and S.ptrace(
                                    S.PTRACE_SEIZE, tid)[0] == 0:
                                tids.add(tid)
                    next_scan = tick + 1.0
                for addr in (candidates if rounds % 5 == 0 else ()):
                    try:
                        mem.seek(addr)
                        data = mem.read(4)
                    except OSError:
                        continue
                    if len(data) != 4:
                        continue
                    val = struct.unpack("<I", data)[0]
                    if val != last[addr] and val >= INITIAL and \
                            (val - INITIAL) % CLOCK_STEP == 0:
                        transitions[addr] += 1
                        last_seen[addr] = (tick, val)
                        first_seen.setdefault(addr, (tick, val))
                    if val >= INITIAL and (val - INITIAL) % CLOCK_STEP == 0:
                        last[addr] = val
                for tid in (sorted(tids) if not args.no_sample else ()):
                    sample = S.sample_thread(tid, buf)
                    if sample is None:
                        if not Path(f"/proc/{pid}/task/{tid}").exists():
                            tids.discard(tid)
                        continue
                    mode, ip, cs, orig = sample
                    per_thread[tid] += 1
                    if mode == "32":
                        if S.WAIT_START <= ip < S.WAIT_END:
                            per_thread_wait[tid] += 1
                            eip_hist[ip] += 1
                        elif game_base and game_base <= ip < game_base + 0x1000000:
                            eip_hist[ip] += 1
                        else:
                            mod, off = S.find_module(regions, ip)
                            mod_hist[f"32:{mod}"] += 1
                    else:
                        mod, off = S.find_module(regions, ip)
                        mod_hist[f"64:{mod}"] += 1
                        syscall_hist[orig] += 1
                rounds += 1
                wait = tick + period - time.monotonic()
                if wait > 0:
                    time.sleep(wait)
        wall = args.seconds
        self_cpu1 = proc_cpu_self()

        if not args.no_sample:
            for tid in sorted(tids):
                S.ptrace(S.PTRACE_INTERRUPT, tid)
            for tid in sorted(tids):
                try:
                    os.waitpid(tid, os.WNOHANG)
                except ChildProcessError:
                    pass
                S.ptrace(S.PTRACE_DETACH, tid)

        qualifying = {a: transitions[a] for a in candidates
                      if transitions[a] >= 5}
        days = 0
        day_span_s = 0.0
        best = None
        if qualifying:
            best = max(qualifying, key=lambda a: qualifying[a])
            t0, v0 = first_seen[best]
            t1, v1 = last_seen[best]
            days = (v1 - v0) // CLOCK_STEP
            day_span_s = t1 - t0

        main_tid = pid
        main_samples = per_thread.get(main_tid, 0)
        main_wait = per_thread_wait.get(main_tid, 0)
        main_frac = main_wait / main_samples if main_samples else 0
        rec = {
            "label": args.label,
            "days_clock": days,
            "day_span_s": round(day_span_s, 3),
            "clock_candidates": len(candidates),
            "clock_qualifying": len(qualifying),
            "best_clock": hex(best) if best is not None else None,
            "seconds": wall,
            "rounds": rounds,
            "rate_hz": round(rounds / wall, 2),
            "threads": len(per_thread),
            "main_tid": main_tid,
            "main_samples": main_samples,
            "main_wait": main_wait,
            "main_wait_frac": round(main_frac, 5),
            "blocked_ms_per_day":
                round(main_frac * day_span_s * 1000.0 / days, 3) if days else None,
            "total_samples": sum(per_thread.values()),
            "total_wait": sum(per_thread_wait.values()),
            "per_thread_wait_frac": {
                str(t): round(per_thread_wait[t] / per_thread[t], 5)
                for t in sorted(per_thread) if per_thread[t]},
            "eip_top": [[hex(a), c] for a, c in eip_hist.most_common(60)],
            "eip_distinct": len(eip_hist),
            "modules": dict(sorted(mod_hist.items(),
                                   key=lambda kv: -kv[1])[:20]),
            "syscalls": {hex(k): v for k, v in syscall_hist.most_common(20)},
            "no_sample": args.no_sample,
            "sampler_cpu_s": round(self_cpu1 - self_cpu0, 3),
            "load1_before": round(load_before, 2),
            "load1_after": round(load1(), 2),
        }
        print(json.dumps(rec, indent=1), flush=True)
        (OUTDIR / f"wait-{args.label}.json").write_text(
            json.dumps(rec, indent=1) + "\n")

        shot(f"{args.label}-final")
        xdo("key", "--window", win, "space")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            pass
        subprocess.run(["pkill", "-f", "[v]2game.exe"], check=False)
        log.close()
        time.sleep(2)


if __name__ == "__main__":
    main()
