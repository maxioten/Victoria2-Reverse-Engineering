#!/usr/bin/env python3
"""Run a single isolated 90-day SPA 1837.1.1 baseline benchmark in Wine + Xvfb."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import statistics
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "experiments" / "perf-baseline-lab"
GAME_DIR = LAB / "game"
WINE_DIR = LAB / "wine"
XVFB_BIN = ROOT / "tools" / "xvfb-local" / "root" / "usr" / "bin" / "Xvfb"
GAMELOG = WINE_DIR / "drive_c/users/daniel/Documents/Paradox Interactive/Victoria II/logs/game.log"
LAUNCH_MARK = b"[[ Launching SINGLEPLAYER-game ]]"

INITIAL_CLOCK = 43800000 + 1837 * 365 * 24  # 1837.1.1 = 59892120
CLOCK_STEP = 24


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def load1() -> float:
    try:
        return float(Path("/proc/loadavg").read_text().split()[0])
    except (FileNotFoundError, IndexError, ValueError):
        return 0.0


def find_free_display(preferred: int | None = None) -> int:
    if preferred is not None:
        assert 90 <= preferred <= 199
        sock = Path("/tmp/.X11-unix") / f"X{preferred}"
        assert not sock.exists(), f"Display :{preferred} already in use"
        return preferred
    for d in range(95, 200):
        if d == 99:
            continue
        if not (Path("/tmp/.X11-unix") / f"X{d}").exists():
            return d
    raise RuntimeError("No free X display in :90..:199")


def check_no_active_game() -> None:
    my_pid = os.getpid()
    active = []
    for p in Path("/proc").iterdir():
        if not p.name.isdigit():
            continue
        pid = int(p.name)
        if pid == my_pid:
            continue
        try:
            args = (p / "cmdline").read_bytes().split(b"\x00")
        except OSError:
            continue
        args_s = [a.decode("utf-8", "replace") for a in args if a]
        if not args_s:
            continue
        exe0 = Path(args_s[0].replace("\\", "/")).name.lower()
        if exe0 == "v2game.exe" or (
            exe0 in ("wine", "wine64", "wine-preloader", "wine64-preloader")
            and any(Path(a.replace("\\", "/")).name.lower() == "v2game.exe" for a in args_s[1:])
        ):
            active.append((pid, " ".join(args_s)))
    if active:
        raise RuntimeError(f"Another v2game.exe is already running: {active}")


def write_patch_ini(ini_path: Path, sample_interval: int, skip_network_wait: int) -> None:
    ini_path.write_text(
        f"""; P0 baseline run config
skip_network_wait = {skip_network_wait}
cull_decision_checks = 0
cull_cb_checks = 0
prefetch_relations = 0
prefetch_pops = 0
prefetch_ai_relations = 0
skip_clean_resets = 0
fast_ai_queue = 0
parallel_decisions = 0
parallel_events = 0
engine_worker_threads = 0
background_sleep_ms = 100
state_checksum = 0
oos_log = 0
fix_rng_resync = 0
sync_world_rng = 0
mp_host_wait_days = 0
oos_notice = 0
pin_fpu = 0
fpu_precision = 0
fix_supply_crash = 0
fix_tech_window_crash = 0
fix_missing_modifier = 0
fix_missing_state_crash = 0
borderless_fullscreen = 0
fix_edge_scroll = 0
clipboard_paste = 0
save_last_ip = 0
join_port = 0
chat_line_seconds = 60
compress_flag_cache = 0
tick_profiler = 0
sample_profiler = {sample_interval}
decision_profiling = 0
cull_cb_profiling = 0
oos_test_button = 0
network_log = 0
"""
    )


def xdo(env: dict[str, str], *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["xdotool", *args], env=env, capture_output=True, text=True)


def click(env: dict[str, str], win: str, x: int, y: int, delay: float = 1.0, hold: float = 0.2) -> None:
    xdo(env, "mousemove", "--window", win, str(x), str(y))
    time.sleep(hold)
    xdo(env, "mousedown", "1")
    time.sleep(hold)
    xdo(env, "mouseup", "1")
    time.sleep(delay)


def shot(env: dict[str, str], path: Path) -> None:
    subprocess.run(["import", "-display", env["DISPLAY"], "-window", "root", str(path)], env=env, check=False)


def date_hash(env: dict[str, str]) -> str:
    p = subprocess.run(
        ["import", "-display", env["DISPLAY"], "-window", "root", "-crop", "155x22+198+119", "png:-"],
        env=env,
        capture_output=True,
    )
    if p.returncode != 0:
        raise RuntimeError("import failed during date_hash")
    return hashlib.sha256(p.stdout).hexdigest()


def wait_date_change(env: dict[str, str], timeout: float = 8.0) -> bool:
    prev = date_hash(env)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        time.sleep(0.5)
        if date_hash(env) != prev:
            return True
    return False


def find_window(env: dict[str, str], timeout: float = 150.0) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        p = xdo(env, "search", "--onlyvisible", "--name", "Victoria 2")
        if p.returncode == 0 and p.stdout.strip():
            return p.stdout.splitlines()[0].strip()
        time.sleep(1.0)
    raise RuntimeError("Victoria 2 window not found before timeout")


def wait_launch(mark: int, timeout: float = 90.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with GAMELOG.open("rb") as fh:
                fh.seek(mark)
                if LAUNCH_MARK in fh.read():
                    return True
        except FileNotFoundError:
            pass
        time.sleep(1.5)
    return False


def wait_menu_ready(timeout: float = 150.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            txt = GAMELOG.read_text(errors="replace")
            if "Initialized cities" in txt:
                time.sleep(6.0)
                return
        except FileNotFoundError:
            pass
        time.sleep(1.0)
    raise RuntimeError("Timed out waiting for game menu initialization in game.log")


def load_save_ui(env: dict[str, str], win: str, session_dir: Path | None = None) -> None:
    click(env, win, 383, 606, 1.5)
    click(env, win, 383, 606, 4.0)
    if session_dir is not None:
        shot(env, session_dir / "01b-saves.png")
    click(env, win, 100, 105, 1.5)
    if session_dir is not None:
        shot(env, session_dir / "01c-selected.png")
    click(env, win, 1178, 674, 8.0)
    click(env, win, 1178, 674, 6.0)


def wait_clock_advance(pid: int, addrs: list[int], initial: int, timeout: float = 8.0) -> bool:
    deadline = time.monotonic() + timeout
    with open(f"/proc/{pid}/mem", "rb", buffering=0) as mem:
        while time.monotonic() < deadline:
            for addr in addrs:
                try:
                    mem.seek(addr)
                    val = struct.unpack("<I", mem.read(4))[0]
                    if initial < val <= initial + 240 and (val - initial) % CLOCK_STEP == 0:
                        return True
                except OSError:
                    continue
            time.sleep(0.2)
    return False


def scan_clock(pid: int, target_val: int) -> list[int]:
    needle = struct.pack("<I", target_val)
    hits: list[int] = []
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


def run_once(tag: str, days_target: int, sample_interval: int, skip_network_wait: int,
             display_num: int | None, out_dir: Path) -> dict:
    check_no_active_game()
    disp_n = find_free_display(display_num)
    display = f":{disp_n}"

    session_dir = LAB / "sessions" / tag
    if session_dir.exists():
        shutil.rmtree(session_dir)
    session_dir.mkdir(parents=True, exist_ok=True)

    raw_dir = out_dir / tag
    raw_dir.mkdir(parents=True, exist_ok=True)

    auth = session_dir / "xauthority"
    auth.touch(mode=0o600)
    subprocess.run(["xauth", "-f", str(auth), "add", display, ".", secrets.token_hex(16)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    x_env = dict(os.environ, DISPLAY=display, XAUTHORITY=str(auth))
    xvfb_cmd = [str(XVFB_BIN), display, "-screen", "0", "1280x800x24",
                "-nolisten", "tcp", "-auth", str(auth), "-noreset"]

    # Configure INI and remove stale TSV/logs.
    write_patch_ini(GAME_DIR / "mod/performance_patch.ini", sample_interval, skip_network_wait)
    for stale in ("performance_patch_samples.tsv", "the_grand_loader.log"):
        (GAME_DIR / stale).unlink(missing_ok=True)
    GAMELOG.unlink(missing_ok=True)

    xvfb_log = (session_dir / "xvfb.log").open("w")
    xvfb = subprocess.Popen(xvfb_cmd, stdout=xvfb_log, stderr=subprocess.STDOUT, env=x_env)
    wm = None
    wm_log = None
    game_proc = None
    game_log_fh = None
    sock = Path("/tmp/.X11-unix") / f"X{disp_n}"

    load_before = load1()
    try:
        deadline = time.monotonic() + 15.0
        while not sock.exists():
            if xvfb.poll() is not None:
                raise RuntimeError("Xvfb exited prematurely")
            if time.monotonic() > deadline:
                raise TimeoutError("Timed out waiting for Xvfb socket")
            time.sleep(0.1)

        wm_log = (session_dir / "xfwm4.log").open("w")
        wm = subprocess.Popen(
            ["xfwm4", "--sm-client-disable", "--compositor=off", "--vblank=off"],
            env=x_env, stdout=wm_log, stderr=subprocess.STDOUT,
        )
        time.sleep(0.5)

        wine_env = dict(
            x_env,
            WINEPREFIX=str(WINE_DIR),
            WINEARCH="wow64",
            WINEDEBUG="-all",
            WINEDLLOVERRIDES="winemenubuilder.exe=d;dinput8=n,b;lua51=n;d3dx9_41=n;d3dcompiler_41=n;d3dcompiler_43=n",
        )
        game_log_fh = (session_dir / "wine.log").open("wb")
        game_proc = subprocess.Popen(
            ["wine", "v2game.exe"],
            cwd=GAME_DIR,
            env=wine_env,
            stdout=game_log_fh,
            stderr=subprocess.STDOUT,
        )
        pid = game_proc.pid

        win = find_window(wine_env, timeout=150.0)
        wait_menu_ready(timeout=150.0)
        xdo(wine_env, "windowmove", win, "30", "30")
        xdo(wine_env, "windowfocus", win)
        time.sleep(1.0)
        shot(wine_env, session_dir / "01-menu.png")

        mark = GAMELOG.stat().st_size if GAMELOG.exists() else 0
        load_save_ui(wine_env, win, session_dir)
        if not wait_launch(mark, timeout=90.0):
            xdo(wine_env, "key", "--window", win, "Escape")
            time.sleep(2.0)
            mark = GAMELOG.stat().st_size if GAMELOG.exists() else 0
            load_save_ui(wine_env, win, session_dir)
            if not wait_launch(mark, timeout=90.0):
                shot(wine_env, session_dir / "load-failed.png")
                raise RuntimeError("Save failed to load")

        time.sleep(4.0)
        shot(wine_env, session_dir / "02-loaded.png")

        candidates = scan_clock(pid, INITIAL_CLOCK)
        if len(candidates) < 1:
            raise RuntimeError(f"No clock candidates found for {INITIAL_CLOCK}")

        if not wait_clock_advance(pid, candidates, INITIAL_CLOCK, timeout=2.5):
            xdo(wine_env, "key", "--window", win, "space")
            if not wait_clock_advance(pid, candidates, INITIAL_CLOCK, timeout=8.0):
                shot(wine_env, session_dir / "unpause-failed.png")
                raise RuntimeError("Game did not unpause")

        xdo(wine_env, "windowfocus", win)
        for _ in range(6):
            click(wine_env, win, 370, 102, delay=0.05, hold=0.05)
        time.sleep(0.2)
        shot(wine_env, session_dir / "03-running.png")

        # Track clock transitions until day (start_day + days_target).
        # Start measuring after clicking '+' so startup/unpause latency is excluded.
        # Validate candidates strictly: monotonic non-decreasing, 0 <= d <= 500,
        # and only trust step deltas 1 <= dd <= 3 per 20 ms poll (preferring addresses
        # that have stepped >= 3 times). Never prune on max_seen_day - d.
        tracked = list(candidates)
        cur_vals: dict[int, int] = {}
        steps: dict[int, int] = {}
        day_events: list[tuple[int, float]] = []  # (day_offset_from_initial, monotonic_ts)
        max_seen_day = 0
        last_progress_t = time.monotonic()
        modal_pauses = 0
        modal_stall_ms = 0.0

        with open(f"/proc/{pid}/mem", "rb", buffering=0) as mem:
            for addr in tracked:
                try:
                    mem.seek(addr)
                    val = struct.unpack("<I", mem.read(4))[0]
                    if INITIAL_CLOCK <= val <= INITIAL_CLOCK + 30 * CLOCK_STEP and (val - INITIAL_CLOCK) % CLOCK_STEP == 0:
                        cur_vals[addr] = val
                        steps[addr] = 1 if val > INITIAL_CLOCK else 0
                except OSError:
                    pass

            if cur_vals:
                init_days = [(v - INITIAL_CLOCK) // CLOCK_STEP for v in cur_vals.values()]
                start_day_offset = min(max(init_days), 15) if max(init_days) > 0 else 1
            else:
                start_day_offset = 1
            max_seen_day = start_day_offset
            day_events.append((start_day_offset, time.monotonic()))
            active_addrs = set(cur_vals.keys())
            # Ensure we pass day >= 93 so performance_patch (30/60/90) flushes day 90.
            stop_day_offset = max(start_day_offset + days_target, 93)
            overall_deadline = time.monotonic() + 300.0

            while max_seen_day < stop_day_offset and time.monotonic() < overall_deadline:
                t_now = time.monotonic()
                if game_proc.poll() is not None:
                    raise RuntimeError(f"v2game.exe exited unexpectedly with code {game_proc.returncode}")

                progressed = False
                bad = []
                have_trusted = any(s >= 3 for s in steps.values())
                for addr in list(active_addrs):
                    try:
                        mem.seek(addr)
                        data = mem.read(4)
                    except OSError:
                        bad.append(addr)
                        continue
                    if len(data) != 4:
                        bad.append(addr)
                        continue
                    val = struct.unpack("<I", data)[0]
                    prev_val = cur_vals[addr]
                    if val < prev_val or val > INITIAL_CLOCK + 500 * CLOCK_STEP or (val - INITIAL_CLOCK) % CLOCK_STEP != 0:
                        bad.append(addr)
                        continue
                    if val > prev_val:
                        dd = (val - prev_val) // CLOCK_STEP
                        if dd <= 3:
                            cur_vals[addr] = val
                            steps[addr] = steps.get(addr, 0) + 1
                            d = (val - INITIAL_CLOCK) // CLOCK_STEP
                            if (not have_trusted or steps[addr] >= 3) and 0 < d - max_seen_day <= 3:
                                max_seen_day = d
                                day_events.append((d, t_now))
                                last_progress_t = t_now
                                progressed = True
                        else:
                            bad.append(addr)
                if len(active_addrs) - len(bad) >= 1:
                    for addr in bad:
                        active_addrs.discard(addr)

                if not progressed and (t_now - last_progress_t) > 4.0:
                    modal_pauses += 1
                    shot(wine_env, session_dir / f"modal-{modal_pauses}.png")
                    resumed = False
                    dismiss_actions = [
                        ("click", 550, 529, 1.2),
                        ("click", 550, 565, 1.2),
                        ("click", 550, 585, 1.2),
                        ("key", "Return", 1.0),
                        ("key", "space", 1.5),
                    ]
                    for act in dismiss_actions:
                        if act[0] == "click":
                            click(wine_env, win, act[1], act[2], delay=0.08, hold=0.08)
                        else:
                            xdo(wine_env, "key", "--window", win, act[1])
                        probe_end = time.monotonic() + act[-1]
                        while time.monotonic() < probe_end:
                            for addr in list(active_addrs):
                                try:
                                    mem.seek(addr)
                                    val = struct.unpack("<I", mem.read(4))[0]
                                except OSError:
                                    continue
                                prev_val = cur_vals.get(addr, val)
                                if (
                                    val > prev_val
                                    and val <= INITIAL_CLOCK + 500 * CLOCK_STEP
                                    and (val - INITIAL_CLOCK) % CLOCK_STEP == 0
                                    and (val - prev_val) // CLOCK_STEP <= 3
                                ):
                                    resumed = True
                                    break
                            if resumed:
                                break
                            time.sleep(0.05)
                        if resumed:
                            break
                    last_progress_t = time.monotonic()
                    modal_stall_ms += (last_progress_t - t_now + 4.0) * 1000.0
                    if modal_pauses >= 10:
                        raise RuntimeError("Simulation stalled repeatedly (possible unclosed modal)")

                time.sleep(0.02)

        if max_seen_day < stop_day_offset:
            raise TimeoutError(f"Only reached day {max_seen_day}, target {stop_day_offset}")

        # Let performance_patch flush its 90-day report if just crossed day 90.
        time.sleep(1.5)
        shot(wine_env, session_dir / "04-final.png")
        xdo(wine_env, "key", "--window", win, "space")
        time.sleep(0.3)

    finally:
        if game_proc is not None and game_proc.poll() is None:
            game_proc.terminate()
            try:
                game_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                game_proc.kill()
                game_proc.wait(timeout=5)
        subprocess.run(["wineserver", "-k"], env=dict(os.environ, WINEPREFIX=str(WINE_DIR)),
                       check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if game_log_fh is not None:
            game_log_fh.close()
        if wm is not None and wm.poll() is None:
            wm.terminate()
            try:
                wm.wait(timeout=5)
            except subprocess.TimeoutExpired:
                wm.kill()
                wm.wait(timeout=5)
        if wm_log is not None:
            wm_log.close()
        if xvfb.poll() is None:
            xvfb.terminate()
            try:
                xvfb.wait(timeout=5)
            except subprocess.TimeoutExpired:
                xvfb.kill()
                xvfb.wait(timeout=5)
        xvfb_log.close()

    load_after = load1()

    # Copy raw artifacts
    for src_name, dst_name in [
        ("performance_patch_samples.tsv", "performance_patch_samples.tsv"),
        ("the_grand_loader.log", "the_grand_loader.log"),
    ]:
        src = GAME_DIR / src_name
        if src.exists():
            shutil.copy2(src, raw_dir / dst_name)
    if GAMELOG.exists():
        shutil.copy2(GAMELOG, raw_dir / "game.log")

    # Analyze exact 90-day wall-clock span from day_events
    day_ts = {d: ts for d, ts in day_events}
    d0 = min(d for d in day_ts if d >= start_day_offset)
    # Find d_end = d0 + days_target (or nearest available if 2 days jumped in 25ms)
    d_end_candidates = [d for d in day_ts if d >= d0 + days_target]
    d_end = min(d_end_candidates)
    elapsed_days = d_end - d0
    wall_ms = (day_ts[d_end] - day_ts[d0]) * 1000.0
    wall_ms_per_day = wall_ms / elapsed_days

    per_day_ms = []
    sorted_days = sorted(d for d in day_ts if d0 <= d <= d_end)
    for da, db in zip(sorted_days, sorted_days[1:]):
        dd = db - da
        if dd > 0:
            per_day_ms.append(((day_ts[db] - day_ts[da]) * 1000.0) / dd)

    result = {
        "tag": tag,
        "display": display,
        "skip_network_wait": skip_network_wait,
        "sample_interval_ms": sample_interval,
        "start_day_offset": d0,
        "end_day_offset": d_end,
        "elapsed_days": elapsed_days,
        "wall_total_ms": round(wall_ms, 3),
        "wall_ms_per_day": round(wall_ms_per_day, 3),
        "modal_stall_ms": round(modal_stall_ms, 3),
        "active_wall_ms_per_day": round(max(0.0, wall_ms - modal_stall_ms) / elapsed_days, 3),
        "per_day_median_ms": round(statistics.median(per_day_ms), 3) if per_day_ms else None,
        "per_day_mean_ms": round(statistics.mean(per_day_ms), 3) if per_day_ms else None,
        "per_day_stdev_ms": round(statistics.stdev(per_day_ms), 3) if len(per_day_ms) > 1 else None,
        "modal_pauses": modal_pauses,
        "remaining_clock_addrs": [hex(a) for a in sorted(active_addrs)],
        "load1_before": load_before,
        "load1_after": load_after,
        "day_events": [[d, round(ts - day_ts[d0], 6)] for d, ts in day_events],
    }
    (raw_dir / "run_metrics.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k != "day_events"}, indent=2), flush=True)
    return result


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", required=True)
    ap.add_argument("--days", type=int, default=90)
    ap.add_argument("--sample-interval", type=int, default=50)
    ap.add_argument("--skip-network-wait", type=int, default=0, choices=(0, 1))
    ap.add_argument("--display", type=int, default=None)
    ap.add_argument("--out-dir", type=Path, default=ROOT / "research" / "perf" / "raw")
    args = ap.parse_args()
    run_once(args.tag, args.days, args.sample_interval, args.skip_network_wait, args.display, args.out_dir)


if __name__ == "__main__":
    main()
