#!/usr/bin/env python3
"""Watch live +0x34 values of sampled relations across 30 game days.

Static mapping found only zeroing writers (constructor tail + reset paths);
no nonzero writer in any examined path. This run checks behaviorally: read
+0x34 of 8 sampled relations at every calendar breakpoint. Any nonzero value
or transition reopens the hunt with a day-precision window; all-zero
confirms reset-only for caching purposes.

Debugger channel only (x32dbg headless + MCP): no extra stops beyond the
daily calendar BP. Array bases re-read daily (vector may grow).
"""
import json
import os
import struct
import subprocess
import sys
import time
from pathlib import Path

LAB = Path(__file__).resolve().parent
ROOT = Path(__file__).resolve().parents[4]
GAME = Path(os.environ.get("V2_GAME_DIR", ROOT / "experiments/day-tick-lab/game"))
PREFIX = Path(os.environ.get("WINEPREFIX", ROOT / "experiments/day-tick-lab/wine"))
DISPLAY = ":99"
CAL_RVA = 0x282FA5
CAL_BYTES = bytes.fromhex("83860c0b000018")
COUNTRIES_VEC = 0x12587E4
WINE_USER = os.environ.get("WINEUSER", os.environ.get("USER", "user"))
GAMELOG = PREFIX / f"drive_c/users/{WINE_USER}/Documents/Paradox Interactive/Victoria II/logs/game.log"
LAUNCH_MARK = "[[ Launching SINGLEPLAYER-game ]]"
N_COUNTRIES = 2
N_RELS = 4

sys.path.insert(0, str(LAB))
from client import call, registers, memory  # noqa: E402

ENV = {
    **__import__("os").environ,
    "WINEPREFIX": str(PREFIX),
    "WINEARCH": "wow64",
    "WINEDEBUG": "-all",
    "WINEDLLOVERRIDES": "winemenubuilder.exe=d;dinput8=b;lua51=n;"
                         "d3dx9_41=n;d3dcompiler_41=n;d3dcompiler_43=n",
    "DISPLAY": DISPLAY,
    "QT_QPA_PLATFORM": "offscreen",
}


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
                    str(LAB / "evidence" / f"watch-{name}.png")], check=False)


def log_mark():
    try:
        return GAMELOG.stat().st_size
    except FileNotFoundError:
        return 0


def wait_launch(mark, timeout=90.0):
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


def find_window(timeout=120):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        p = xdo("search", "--onlyvisible", "--name", "Victoria 2")
        if p.returncode == 0 and p.stdout.strip():
            return p.stdout.splitlines()[0].strip()
        time.sleep(1.0)
    raise RuntimeError("game window not found")


def u32(addr):
    return struct.unpack("<I", memory(addr, 4))[0]


def stopped_at(addr, timeout=180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = call("GetDebugState")
        if "NO_TARGET" in state:
            raise RuntimeError("target exited")
        if "isRunning: false" in state and "currentAddress:" in state:
            reg = registers()
            if reg["eip"] != addr:
                return reg
            return reg
        time.sleep(0.3)
    raise TimeoutError(f"no stop at {addr:#x}")


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--label", default="watch1")
    args = ap.parse_args()

    subprocess.run(["pkill", "-f", "[v]2game.exe"], check=False)
    time.sleep(2)
    dbg_log = open(LAB / "evidence" / "debugger-watch.log", "w")
    env = dict(ENV)
    dbg = subprocess.Popen(
        ["wine", str(LAB / "debugger/headless.exe"), "-workingDir",
         "Z:" + str(GAME).replace("/", "\\"), "-plugin",
         "Z:" + str(LAB / "debugger/plugins/x64dbg-MCP-Server.dp32").replace("/", "\\")],
        cwd=str(GAME), env=env, stdin=subprocess.PIPE, stdout=dbg_log,
        stderr=subprocess.STDOUT, text=True)
    try:
        from client import rpc, _ConnectionError
        deadline = time.monotonic() + 60
        while True:
            try:
                rpc("initialize", {"protocolVersion": "2024-11-05",
                                   "capabilities": {},
                                   "clientInfo": {"name": "v2-watch-34",
                                                  "version": "1"}})
                break
            except _ConnectionError:
                if dbg.poll() is not None or time.monotonic() > deadline:
                    raise
                time.sleep(0.5)
        print(call("LoadBinary",
                   {"filePath": "Z:" + str(GAME / "v2game.exe").replace("/", "\\")}),
              flush=True)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            state = call("GetDebugState")
            if "isRunning: false" in state and "currentAddress:" in state:
                break
            time.sleep(0.5)
        answer = call("EvalExpression", {"expression": "mod.main()"})
        base = int(answer.split()[0], 16)
        assert base == 0x400000, "requires preferred base"
        cal = base + CAL_RVA
        assert memory(cal, 7) == CAL_BYTES, "calendar bytes differ"
        call("SetBreakpoint", {"target": hex(cal)})
        print(call("run", {"timeoutMs": 1000}), flush=True)

        end = time.monotonic() + 120
        running = False
        while time.monotonic() < end:
            state = call("GetDebugState")
            if "isRunning: true" in state:
                running = True
                break
            if "isRunning: false" in state and "currentAddress:" in state:
                call("run", {"timeoutMs": 5000})
            time.sleep(0.5)
        if not running:
            raise RuntimeError("game did not start running")

        time.sleep(75)
        win = find_window()
        print(f"window {win}", flush=True)
        xdo("windowmove", win, "30", "30")
        xdo("windowfocus", win)
        time.sleep(1)
        shot("menu")
        mark = log_mark()
        load_save(win)
        if not wait_launch(mark):
            xdo("key", "--window", win, "Escape")
            time.sleep(2)
            mark = log_mark()
            load_save(win)
            if not wait_launch(mark):
                raise RuntimeError("save did not load after retry")

        xdo("key", "--window", win, "space")
        xdo("windowfocus", win)
        for _ in range(15):
            xdo("key", "--window", win, "plus")
            time.sleep(0.25)
        time.sleep(0.5)
        shot("running")

        days = 0
        world = None
        series = {}
        t_start = time.monotonic()
        while days < args.days and time.monotonic() - t_start < 1800:
            state = call("GetDebugState")
            if "NO_TARGET" in state:
                raise RuntimeError("target exited")
            if "isRunning: false" in state and "currentAddress:" in state:
                reg = registers()
                if reg["eip"] != cal:
                    call("run", {"timeoutMs": 5000})
                    time.sleep(0.3)
                    continue
                if world is None:
                    world = reg["esi"]
                clock = u32(world + 0xB0C)
                days += 1
                entry = {}
                for ci in range(N_COUNTRIES):
                    cv = u32(COUNTRIES_VEC)  # absolute VA (base verified)
                    begin = u32(cv + 4)
                    country = u32(begin + ci * 4)
                    arr = u32(country + 0xBE8)
                    for ri in range(N_RELS):
                        rel = u32(arr + ri * 4)
                        val = struct.unpack("<i", memory(rel + 0x34, 4))[0]
                        key = f"c{ci}r{ri}"
                        series.setdefault(key, []).append(val)
                        entry[key] = val
                print(f"day {days} clock={clock} " +
                      " ".join(f"{k}={v}" for k, v in entry.items()),
                      flush=True)
                call("run", {"timeoutMs": 5000})
            else:
                time.sleep(0.3)

        flat = [v for vals in series.values() for v in vals]
        rec = {
            "label": args.label,
            "days": days,
            "samples": {k: v for k, v in series.items()},
            "distinct_values": sorted(set(flat)),
            "any_nonzero": any(v != 0 for v in flat),
            "transitions": sum(
                1 for vals in series.values()
                for a, b in zip(vals, vals[1:]) if a != b),
            "world": hex(world) if world is not None else None,
            "binary_sha256": "62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648",
        }
        print(json.dumps(rec, indent=1)[:2000], flush=True)
        (LAB / "evidence" / f"watch-{args.label}.json").write_text(
            json.dumps(rec, indent=1) + "\n")
        shot("final")
    finally:
        try:
            call("StopDebug")
        except Exception:
            pass
        if dbg.poll() is None:
            try:
                dbg.stdin.close()
            except Exception:
                pass
            try:
                dbg.wait(timeout=10)
            except subprocess.TimeoutExpired:
                dbg.terminate()
        dbg_log.close()
        subprocess.run(["pkill", "-f", "[v]2game.exe"], check=False)
        time.sleep(2)


if __name__ == "__main__":
    main()
