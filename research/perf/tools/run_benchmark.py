#!/usr/bin/env python3
"""Manual start/stop benchmark for a fixed number of Victoria II game days.

The operator loads a fixed save, pauses on day 1, starts the timer, unpauses,
lets 30 days pass, pauses and stops the timer.  The script samples process CPU
and RSS while the run is active and appends one JSON line per run.

It does not read the game calendar; the day boundary is the operator's
responsibility.  See ../docs/PROTOCOL.md.
"""
import argparse
import json
import platform
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import psutil
except ImportError:  # pragma: no cover - operator-facing error
    print("psutil is required: python -m pip install psutil", file=sys.stderr)
    raise SystemExit(2)

DEFAULT_OUT = Path(__file__).resolve().parents[1] / "benchmarks" / "runs.jsonl"
SCHEMA_VERSION = 1


def find_process(name, pid=None):
    if pid is not None:
        return psutil.Process(pid)
    matches = []
    for p in psutil.process_iter(["pid", "name"]):
        try:
            pname = (p.info.get("name") or "").lower()
            if name.lower() in pname:
                matches.append(p)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    if not matches:
        return None
    if len(matches) > 1:
        print(f"multiple processes match {name!r}: "
              + ", ".join(f"{p.pid}:{p.name()}" for p in matches))
        print("using the first; pass --pid to choose")
    return matches[0]


def sample_process(proc, stop_event, interval, result):
    max_rss = 0
    samples = 0
    last_error = None
    while not stop_event.is_set():
        try:
            mem = proc.memory_info().rss
            max_rss = max(max_rss, mem)
            samples += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
            last_error = str(exc)
            break
        stop_event.wait(interval)
    result["max_rss_bytes"] = max_rss
    result["samples"] = samples
    if last_error:
        result["sample_error"] = last_error


def cpu_seconds(proc):
    t = proc.cpu_times()
    return float(t.user + t.system)


def run_once(args, index):
    proc = None
    print(f"\n[{index}/{args.runs}] waiting for process {args.process!r}...")
    while proc is None:
        proc = find_process(args.process, args.pid)
        if proc is None:
            time.sleep(1)
    print(f"process {proc.pid} ({proc.name()})")
    print("load the fixed save, pause on day 1, then press Enter to start.")
    input("start> ")

    try:
        start_wall = time.perf_counter()
        start_cpu = cpu_seconds(proc)
        stop_event = threading.Event()
        sample = {}
        thread = threading.Thread(
            target=sample_process,
            args=(proc, stop_event, args.interval, sample),
            daemon=True,
        )
        thread.start()
        input("stop after 30 game days, then press Enter> ")
        stop_event.set()
        thread.join(timeout=5)
        end_wall = time.perf_counter()
        end_cpu = cpu_seconds(proc)
    except psutil.NoSuchProcess:
        print("process exited during the run", file=sys.stderr)
        return None

    wall_s = end_wall - start_wall
    cpu_s = max(0.0, end_cpu - start_cpu)
    record = {
        "schema_version": SCHEMA_VERSION,
        "label": args.label,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "process": args.process,
        "pid": proc.pid,
        "save_sha256": args.save_hash,
        "days": args.days,
        "wall_s": round(wall_s, 6),
        "cpu_s": round(cpu_s, 6),
        "wall_ms_per_day": round(wall_s * 1000.0 / args.days, 3),
        "cpu_ms_per_day": round(cpu_s * 1000.0 / args.days, 3),
        "max_rss_mb": round(sample.get("max_rss_bytes", 0) / (1024 * 1024), 3),
        "samples": sample.get("samples", 0),
        "notes": args.notes,
        "host": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
    }
    if "sample_error" in sample:
        record["sample_error"] = sample["sample_error"]
    print(json.dumps(record, indent=1))
    return record


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--label", required=True, help="baseline, enet-timeout-zero, ...")
    ap.add_argument("--process", default="v2game.exe", help="process name substring")
    ap.add_argument("--pid", type=int, default=None, help="exact process id")
    ap.add_argument("--save-hash", default="", help="SHA-256 of the fixed save")
    ap.add_argument("--days", type=int, default=30, help="game days per run")
    ap.add_argument("--runs", type=int, default=1, help="runs in this invocation")
    ap.add_argument("--interval", type=float, default=0.25, help="RSS sample interval")
    ap.add_argument("--notes", default="", help="free-form run notes")
    ap.add_argument("--out", default=str(DEFAULT_OUT), help="JSONL output")
    args = ap.parse_args()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    records = []
    for i in range(1, args.runs + 1):
        rec = run_once(args, i)
        if rec is None:
            break
        records.append(rec)
        with out.open("a") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n")
        if i != args.runs:
            input("press Enter for the next run> ")

    print(f"\nwrote {len(records)} run(s) to {out}")


if __name__ == "__main__":
    main()
