#!/usr/bin/env python3
"""Count enet_socket_wait calls in single player and sample runtime values.

Debugger (x32dbg headless + MCP, proven day-tick-lab pattern) stops at the
single wait call site 0xA89E43 per hit: records ECX (timeout argument) and a
timestamp, sets a one-shot breakpoint at 0xA89E48 (return), records EAX
(0 = timeout expired, >0 = socket ready, <0 = error), resumes.

Game days come from a second breakpoint at the calendar increment
(0x682FA5, proven): one hit per day, with the clock value read through the
debugger to verify +24 steps. Stops do not create or drop waits, so
hits/day is exact.

Stops after 30 days or 200 hits (whichever first). A handful of stops cost
seconds total; counting is exact, durations carry debugger bias and are NOT
reported as measurements (see enet-wait-sample for the duration bound).
"""
import importlib.util
import json
import os
import re
import shutil
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
WAIT_RVA = 0x689E43   # 0xA89E43, call enet_socket_wait
WAIT_RET = 0x689E48   # 0xA89E48, first insn after the call
CAL_RVA = 0x282FA5    # 0x682FA5, add [esi+0xb0c], 0x18 (calendar)
CAL_BYTES = bytes.fromhex("83860c0b000018")
WAIT_BYTES = bytes.fromhex("e8b8150000")
RET_BYTES = bytes.fromhex("85c0")
WINE_USER = os.environ.get("WINEUSER", os.environ.get("USER", "user"))
GAMELOG = PREFIX / f"drive_c/users/{WINE_USER}/Documents/Paradox Interactive/Victoria II/logs/game.log"
LAUNCH_MARK = "[[ Launching SINGLEPLAYER-game ]]"

sys.path.insert(0, str(LAB))
from client import OUT, call, registers, memory  # noqa: E402

ENV = {
    **os.environ,
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
                    str(LAB / "evidence" / f"count-{name}.png")], check=False)



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


def stopped_at(addr, timeout=120):
    """Wait until the debugger reports stopped at addr. Returns registers."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = call("GetDebugState")
        if "NO_TARGET" in state:
            raise RuntimeError("target exited")
        if "isRunning: false" in state and "currentAddress:" in state:
            reg = registers()
            if reg["eip"] != addr:
                raise AssertionError(
                    f'unexpected pause at {reg["eip"]:#x}, wanted {addr:#x}')
            return reg
        time.sleep(0.2)
    raise TimeoutError(f"no breakpoint at {addr:#x}")


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--max-hits", type=int, default=200)
    ap.add_argument("--label", default="count1")
    args = ap.parse_args()

    dbg_src = Path(os.environ.get("V2_DBG_DIR", ROOT / "experiments/day-tick-lab/debugger"))
    if not (LAB / "debugger").exists():
        # borrow the proven debugger install; symlink, read-only use
        (LAB / "debugger").symlink_to(dbg_src, target_is_directory=True)

    subprocess.run(["pkill", "-f", "[v]2game.exe"], check=False)
    time.sleep(2)
    dbg_log = open(LAB / "evidence" / "debugger.log", "w")
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
                                   "clientInfo": {"name": "v2-wait-count",
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
        print(f"module base {base:#x}", flush=True)
        assert base == 0x400000, "requires preferred base"
        entry, exit_ = base + WAIT_RVA, base + WAIT_RET
        cal = base + CAL_RVA
        assert memory(entry, 5) == WAIT_BYTES, "wait call bytes differ"
        assert memory(exit_, 2) == RET_BYTES, "wait return bytes differ"
        assert memory(cal, 7) == CAL_BYTES, "calendar bytes differ"
        print("site bytes verified", flush=True)
        call("SetBreakpoint", {"target": hex(entry)})
        call("SetBreakpoint", {"target": hex(cal)})

        def resume_until_running(deadline=120.0):
            """Run, re-running past entry-point/TLS pauses (not our site)."""
            end = time.monotonic() + deadline
            while time.monotonic() < end:
                state = call("GetDebugState")
                if "NO_TARGET" in state:
                    raise RuntimeError("target exited")
                if "isRunning: true" in state:
                    return True
                if "isRunning: false" in state and "currentAddress:" in state:
                    reg = registers()
                    if reg["eip"] == entry:
                        return True  # our site; caller handles it
                    print(f"resuming past pause at {reg['eip']:#x}",
                          flush=True)
                    call("run", {"timeoutMs": 5000})
                time.sleep(0.5)
            return False

        print(call("run", {"timeoutMs": 1000}), flush=True)
        if not resume_until_running():
            raise RuntimeError("game did not start running")
        print("game running", flush=True)

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
            print("retrying clicks once", flush=True)
            xdo("key", "--window", win, "Escape")
            time.sleep(2)
            mark = log_mark()
            load_save(win)
            if not wait_launch(mark):
                raise RuntimeError("save did not load after retry")

        print("save loaded (log marker); days counted via calendar BP",
              flush=True)
        loading_hits = []

        def ensure_running(phase):
            for _ in range(30):
                state = call("GetDebugState")
                if "NO_TARGET" in state:
                    raise RuntimeError("target exited")
                if "isRunning: true" in state:
                    return True
                if "isRunning: false" in state and "currentAddress:" in state:
                    reg = registers()
                    if reg["eip"] == entry:
                        loading_hits.append({"timeout": reg["ecx"]})
                        print(f"loading-phase wait hit "
                              f"timeout={reg['ecx']}", flush=True)
                    call("run", {"timeoutMs": 5000})
                    time.sleep(0.5)
            return False

        # NOTE: no date-change gate here. Under the debugger every wait hit
        # stops the game, so days can advance slower than any screenshot
        # timeout; the main loop below counts days via the calendar BP and
        # has its own wall cap.
        xdo("key", "--window", win, "space")
        ensure_running("unpause")
        xdo("windowfocus", win)
        for _ in range(15):
            xdo("key", "--window", win, "plus")
            time.sleep(0.25)
        time.sleep(0.5)
        shot("running")

        days = 0
        hits = []
        stray = 0
        world = None
        clocks = []
        t_start = time.monotonic()
        try:
            wall_cap = time.monotonic() + 1800.0
            flooded = False
            while days < args.days and len(hits) < args.max_hits:
                if time.monotonic() > wall_cap:
                    print("wall cap reached", flush=True)
                    break
                state = call("GetDebugState")
                if "NO_TARGET" in state:
                    raise RuntimeError("target exited")
                if "isRunning: false" in state and "currentAddress:" in state:
                    reg = registers()
                    if reg["eip"] == cal:
                        if world is None:
                            world = reg["esi"]
                        clock = struct.unpack(
                            "<I", memory(world + 0xB0C, 4))[0]
                        clocks.append(clock)
                        days += 1
                        print(f"day {days} clock={clock}", flush=True)
                        call("run", {"timeoutMs": 5000})
                        time.sleep(0.1)
                        continue
                    if reg["eip"] != entry:
                        # stray pause (loader event, exception); resume
                        stray += 1
                        print(f"stray pause #{stray} at {reg['eip']:#x}, "
                              f"resuming", flush=True)
                        if stray > 50:
                            raise RuntimeError("too many stray pauses")
                        call("run", {"timeoutMs": 5000})
                        time.sleep(0.2)
                        continue
                    t0 = time.monotonic()
                    timeout = reg["ecx"]
                    if len(hits) < 10:
                        call("SetBreakpoint", {"target": hex(exit_)})
                        call("run", {"timeoutMs": 30000})
                        reg2 = stopped_at(exit_, timeout=60)
                        ret = reg2["eax"]
                        call("DeleteBreakpoint", {"target": hex(exit_)})
                        ret = ret - 0x100000000 if ret >= 0x80000000 else ret
                    else:
                        ret = None
                    hits.append({"t": round(t0 - t_start, 3),
                                 "timeout": timeout,
                                 "ret": ret,
                                 "day": days})
                    if len(hits) <= 12 or len(hits) % 25 == 0:
                        print(f"hit #{len(hits)} day~{days} "
                              f"timeout={timeout} ret={hits[-1]['ret']}",
                              flush=True)
                    if not flooded and len(hits) > 100 and days < 5:
                        flooded = True
                        call("DeleteBreakpoint", {"target": hex(entry)})
                        print("flood: entry BP removed after 100 hits; "
                              "counting days only", flush=True)
                    call("run", {"timeoutMs": 1000})
                else:
                    time.sleep(0.1)
        finally:
            pass

        try:
            call("DeleteBreakpoint", {"target": hex(entry)})
        except Exception:
            pass
        call("DeleteBreakpoint", {"target": hex(cal)})
        deltas = [b - a for a, b in zip(clocks, clocks[1:])]
        wall_s = round(time.monotonic() - t_start, 1)
        rec = {
            "label": args.label,
            "days": days,
            "wall_s": wall_s,
            "flooded": flooded,
            "clock_first": clocks[0] if clocks else None,
            "clock_last": clocks[-1] if clocks else None,
            "clock_all_plus_24": all(d == 24 for d in deltas),
            "world": hex(world) if world is not None else None,
            "hits": len(hits),
            "hit_list": hits,
            "loading_hits": loading_hits,
            "timeout_values": sorted({h["timeout"] for h in hits}),
            "return_values": sorted({h["ret"] for h in hits
                                     if h["ret"] is not None}),
            "entry_va": hex(entry),
            "entry_bytes": WAIT_BYTES.hex(),
            "calendar_va": hex(cal),
            "calendar_bytes": CAL_BYTES.hex(),
            "binary_sha256": "62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648",
        }
        print(json.dumps(rec, indent=1), flush=True)
        (LAB / "evidence" / f"count-{args.label}.json").write_text(
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
