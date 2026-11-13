#!/usr/bin/env python3
"""Run Paso B HighPerfWinClock (0x00A7B0F0 + 0x00A7B490) pipeline & atexit equivalence check."""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import statistics
import struct
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import analyze_baseline as ab
import run_baseline as rb

ROOT = rb.ROOT
LAB = rb.LAB
GAME_DIR = rb.GAME_DIR
WINE_DIR = rb.WINE_DIR
GAMELOG = rb.GAMELOG
P2_LAB = ROOT / "experiments" / "p2-hook-lab"
V2P2_DLL_SRC = P2_LAB / "build" / "v2p2.dll"
RAW_DIR = ROOT / "research" / "perf" / "raw" / "pilot-a7b490"
OUT_JSON = ROOT / "research" / "perf" / "pilot_a7b490.json"

RVA_CTOR_SKIP = 0x0067B433
RVA_DTOR_ORIG = 0x0067B490
RVA_DTOR_VTABLE_SLOT = 0x00A43A88
RVA_CLOCK_LIST_HEAD = 0x00FF0758  # head(+0), tail(+4), count(+8), flag(+12)
EXPECTED_CTOR_PATCH = bytes([0x83, 0xC4, 0x04, 0xEB, 0x3E, 0x90])


def find_exe_base_and_maps(pid: int) -> tuple[int, list[tuple[int, int, str, str]]]:
    maps: list[tuple[int, int, str, str]] = []
    exe_base = None
    for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
        parts = line.split(None, 5)
        if len(parts) < 2:
            continue
        start, end = (int(x, 16) for x in parts[0].split("-"))
        perms = parts[1]
        pathname = parts[5].strip() if len(parts) >= 6 else ""
        maps.append((start, end, perms, pathname))
        if exe_base is None and "v2game.exe" in pathname.lower():
            exe_base = start
    if exe_base is None:
        exe_base = 0x00400000
    return exe_base, maps


def inspect_clock_pilot_mem(pid: int) -> dict:
    base, maps = find_exe_base_and_maps(pid)
    with open(f"/proc/{pid}/mem", "rb", buffering=0) as mem:
        mem.seek(base + RVA_CTOR_SKIP)
        ctor_bytes = mem.read(6)
        mem.seek(base + RVA_DTOR_VTABLE_SLOT)
        dtor_slot = struct.unpack("<I", mem.read(4))[0]
        mem.seek(base + RVA_CLOCK_LIST_HEAD)
        head, tail, count, flag = struct.unpack("<IIIB", mem.read(13))

    slot_perms = None
    for start, end, perms, _ in maps:
        if start <= dtor_slot < end:
            slot_perms = perms
            break

    return {
        "exe_base": f"0x{base:08x}",
        "ctor_skip_va": f"0x{base + RVA_CTOR_SKIP:08x}",
        "ctor_skip_bytes": ctor_bytes.hex(" "),
        "ctor_skip_matches_expected": ctor_bytes == EXPECTED_CTOR_PATCH,
        "dtor_vtable_slot_va": f"0x{base + RVA_DTOR_VTABLE_SLOT:08x}",
        "dtor_vtable_target": f"0x{dtor_slot:08x}",
        "dtor_vtable_hooked": dtor_slot != (base + RVA_DTOR_ORIG),
        "dtor_target_page_perms": slot_perms,
        "clock_list_head": head,
        "clock_list_tail": tail,
        "clock_list_count": count,
        "clock_list_tombstone_flag": flag,
        "clock_list_zero": (head == 0 and tail == 0 and count == 0 and flag == 0),
    }


def stage_v2p2(mode: str = "prod") -> str:
    if not V2P2_DLL_SRC.exists():
        raise FileNotFoundError(f"Missing {V2P2_DLL_SRC}")
    v2p2_dir = GAME_DIR / "mod" / "v2p2"
    v2p2_dir.mkdir(parents=True, exist_ok=True)
    dst_dll = v2p2_dir / "v2p2.dll"
    shutil.copy2(V2P2_DLL_SRC, dst_dll)
    dst_ini = GAME_DIR / "mod" / "v2p2.ini"
    dst_ini.write_text(f"[hooks]\nfn_00a7b490 = {mode}\n", encoding="utf-8")
    return rb.sha256(dst_dll)


def unstage_v2p2() -> None:
    shutil.rmtree(GAME_DIR / "mod" / "v2p2", ignore_errors=True)
    (GAME_DIR / "mod" / "v2p2.ini").unlink(missing_ok=True)


def run_pilot(days_target: int = 90, sample_interval: int = 50) -> dict:
    rb.check_no_active_game()
    disp_n = rb.find_free_display(None)
    display = f":{disp_n}"

    tag = "pilot-a7b490"
    session_dir = LAB / "sessions" / tag
    if session_dir.exists():
        shutil.rmtree(session_dir)
    session_dir.mkdir(parents=True, exist_ok=True)
    if RAW_DIR.exists():
        shutil.rmtree(RAW_DIR)
    RAW_DIR.mkdir(parents=True, exist_ok=True)

    auth = session_dir / "xauthority"
    auth.touch(mode=0o600)
    subprocess.run(
        ["xauth", "-f", str(auth), "add", display, ".", secrets.token_hex(16)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )

    x_env = dict(os.environ, DISPLAY=display, XAUTHORITY=str(auth))
    xvfb_cmd = [
        str(rb.XVFB_BIN),
        display,
        "-screen",
        "0",
        "1280x800x24",
        "-nolisten",
        "tcp",
        "-auth",
        str(auth),
        "-noreset",
    ]

    v2p2_sha = stage_v2p2("prod")
    rb.write_patch_ini(GAME_DIR / "mod" / "performance_patch.ini", sample_interval, skip_network_wait=0)
    for stale in ("performance_patch_samples.tsv", "the_grand_loader.log", "v2p2.log"):
        (GAME_DIR / stale).unlink(missing_ok=True)
    GAMELOG.unlink(missing_ok=True)

    xvfb_log = (session_dir / "xvfb.log").open("w")
    xvfb = subprocess.Popen(xvfb_cmd, stdout=xvfb_log, stderr=subprocess.STDOUT, env=x_env)
    wm = None
    wm_log = None
    game_proc = None
    game_log_fh = None
    sock = Path("/tmp/.X11-unix") / f"X{disp_n}"

    load_before = rb.load1()
    mem_post_load = None
    mem_post_90d = None
    clean_exit = False
    exit_returncode = None
    exit_method = None

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
            env=x_env,
            stdout=wm_log,
            stderr=subprocess.STDOUT,
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

        win = rb.find_window(wine_env, timeout=150.0)
        rb.wait_menu_ready(timeout=150.0)
        rb.xdo(wine_env, "windowmove", win, "30", "30")
        rb.xdo(wine_env, "windowfocus", win)
        time.sleep(1.0)
        rb.shot(wine_env, session_dir / "01-menu.png")

        mark = GAMELOG.stat().st_size if GAMELOG.exists() else 0
        rb.load_save_ui(wine_env, win, session_dir)
        if not rb.wait_launch(mark, timeout=90.0):
            rb.xdo(wine_env, "key", "--window", win, "Escape")
            time.sleep(2.0)
            mark = GAMELOG.stat().st_size if GAMELOG.exists() else 0
            rb.load_save_ui(wine_env, win, session_dir)
            if not rb.wait_launch(mark, timeout=90.0):
                rb.shot(wine_env, session_dir / "load-failed.png")
                raise RuntimeError("Save failed to load")

        time.sleep(4.0)
        rb.shot(wine_env, session_dir / "02-loaded.png")
        mem_post_load = inspect_clock_pilot_mem(pid)

        candidates = rb.scan_clock(pid, rb.INITIAL_CLOCK)
        if len(candidates) < 1:
            raise RuntimeError(f"No clock candidates found for {rb.INITIAL_CLOCK}")

        if not rb.wait_clock_advance(pid, candidates, rb.INITIAL_CLOCK, timeout=2.5):
            rb.xdo(wine_env, "key", "--window", win, "space")
            if not rb.wait_clock_advance(pid, candidates, rb.INITIAL_CLOCK, timeout=8.0):
                rb.shot(wine_env, session_dir / "unpause-failed.png")
                raise RuntimeError("Game did not unpause")

        rb.xdo(wine_env, "windowfocus", win)
        for _ in range(6):
            rb.click(wine_env, win, 370, 102, delay=0.05, hold=0.05)
        time.sleep(0.2)
        rb.shot(wine_env, session_dir / "03-running.png")

        tracked = list(candidates)
        cur_vals: dict[int, int] = {}
        steps: dict[int, int] = {}
        day_events: list[tuple[int, float]] = []
        max_seen_day = 0
        last_progress_t = time.monotonic()
        modal_pauses = 0
        modal_stall_ms = 0.0

        with open(f"/proc/{pid}/mem", "rb", buffering=0) as mem:
            for addr in tracked:
                try:
                    mem.seek(addr)
                    val = struct.unpack("<I", mem.read(4))[0]
                    if rb.INITIAL_CLOCK <= val <= rb.INITIAL_CLOCK + 30 * rb.CLOCK_STEP and (val - rb.INITIAL_CLOCK) % rb.CLOCK_STEP == 0:
                        cur_vals[addr] = val
                        steps[addr] = 1 if val > rb.INITIAL_CLOCK else 0
                except OSError:
                    pass

            if cur_vals:
                init_days = [(v - rb.INITIAL_CLOCK) // rb.CLOCK_STEP for v in cur_vals.values()]
                start_day_offset = min(max(init_days), 15) if max(init_days) > 0 else 1
            else:
                start_day_offset = 1
            max_seen_day = start_day_offset
            day_events.append((start_day_offset, time.monotonic()))
            active_addrs = set(cur_vals.keys())
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
                    if val < prev_val or val > rb.INITIAL_CLOCK + 500 * rb.CLOCK_STEP or (val - rb.INITIAL_CLOCK) % rb.CLOCK_STEP != 0:
                        bad.append(addr)
                        continue
                    if val > prev_val:
                        dd = (val - prev_val) // rb.CLOCK_STEP
                        if dd <= 3:
                            cur_vals[addr] = val
                            steps[addr] = steps.get(addr, 0) + 1
                            d = (val - rb.INITIAL_CLOCK) // rb.CLOCK_STEP
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
                    rb.shot(wine_env, session_dir / f"modal-{modal_pauses}.png")
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
                            rb.click(wine_env, win, act[1], act[2], delay=0.08, hold=0.08)
                        else:
                            rb.xdo(wine_env, "key", "--window", win, act[1])
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
                                    and val <= rb.INITIAL_CLOCK + 500 * rb.CLOCK_STEP
                                    and (val - rb.INITIAL_CLOCK) % rb.CLOCK_STEP == 0
                                    and (val - prev_val) // rb.CLOCK_STEP <= 3
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

        time.sleep(1.5)
        rb.shot(wine_env, session_dir / "04-final.png")
        mem_post_90d = inspect_clock_pilot_mem(pid)

        # Trigger clean exit via in-game menu -> Quit so CRT runs _atexit (0x00A7B850).
        rb.xdo(wine_env, "key", "--window", win, "space")
        time.sleep(0.3)
        rb.xdo(wine_env, "key", "--window", win, "Escape")
        time.sleep(0.8)
        rb.shot(wine_env, session_dir / "05-menu.png")
        rb.click(wine_env, win, 662, 446, delay=0.5, hold=0.1)

        try:
            exit_returncode = game_proc.wait(timeout=8.0)
            clean_exit = exit_returncode == 0
            exit_method = "in_game_menu_quit"
        except subprocess.TimeoutExpired:
            rb.shot(wine_env, session_dir / "05b-confirm.png")
            rb.xdo(wine_env, "key", "--window", win, "Return")
            try:
                exit_returncode = game_proc.wait(timeout=8.0)
                clean_exit = exit_returncode == 0
                exit_method = "in_game_menu_quit_return"
            except subprocess.TimeoutExpired:
                rb.xdo(wine_env, "key", "--window", win, "Alt+F4")
                try:
                    exit_returncode = game_proc.wait(timeout=8.0)
                    clean_exit = exit_returncode == 0
                    exit_method = "alt_f4"
                except subprocess.TimeoutExpired:
                    exit_method = "forced_terminate"

    finally:
        if game_proc is not None and game_proc.poll() is None:
            game_proc.terminate()
            try:
                exit_returncode = game_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                game_proc.kill()
                exit_returncode = game_proc.wait(timeout=5)
        subprocess.run(
            ["wineserver", "-k"],
            env=dict(os.environ, WINEPREFIX=str(WINE_DIR)),
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
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

        for src_name, dst_name in [
            ("performance_patch_samples.tsv", "performance_patch_samples.tsv"),
            ("the_grand_loader.log", "the_grand_loader.log"),
        ]:
            src = GAME_DIR / src_name
            if src.exists():
                shutil.copy2(src, RAW_DIR / dst_name)
        if GAMELOG.exists():
            shutil.copy2(GAMELOG, RAW_DIR / "game.log")
        unstage_v2p2()

    load_after = rb.load1()

    day_ts = {d: ts for d, ts in day_events}
    d0 = min(d for d in day_ts if d >= start_day_offset)
    d_end = min(d for d in day_ts if d >= d0 + days_target)
    elapsed_days = d_end - d0
    wall_ms = (day_ts[d_end] - day_ts[d0]) * 1000.0
    wall_ms_per_day = wall_ms / elapsed_days

    per_day_ms = []
    sorted_days = sorted(d for d in day_ts if d0 <= d <= d_end)
    for da, db in zip(sorted_days, sorted_days[1:]):
        dd = db - da
        if dd > 0:
            per_day_ms.append(((day_ts[db] - day_ts[da]) * 1000.0) / dd)

    loader_text = (RAW_DIR / "the_grand_loader.log").read_text(errors="replace") if (RAW_DIR / "the_grand_loader.log").exists() else ""
    v2p2_lines = [ln.strip() for ln in loader_text.splitlines() if "v2p2" in ln or "plugin(s) loaded" in ln]

    tsv = ab.parse_sample_tsv(RAW_DIR / "performance_patch_samples.tsv")
    starts, entries = ab.load_ghidra_functions()
    tsv_summary = ab.aggregate_samples([{"_tsv": tsv}], starts, entries)

    # Check if any sample references 0x00A7B4.. (ctor/dtor range)
    a7b4_hits = [
        {"count": c, "frames": fr}
        for c, _, fr in tsv["stacks"]
        if any(x.upper().startswith("0X00A7B4") or x.upper().startswith("0X00A7B0") for x in fr)
    ]

    result = {
        "schema_version": "p0-pilot-a7b490-v1",
        "purpose": "pipeline_and_atexit_equivalence_only_NOT_a_perf_claim",
        "tag": tag,
        "display": display,
        "v2p2_dll_sha256": v2p2_sha,
        "v2p2_ini": "fn_00a7b490 = prod",
        "loader_verification_lines": v2p2_lines,
        "v2p2_installed_logged": any("fn_00a7b490 paired HighPerfWinClock pilot installed" in l for l in v2p2_lines),
        "plugins_loaded_2": any("2 plugin(s) loaded" in l for l in v2p2_lines),
        "clean_exit": clean_exit,
        "exit_returncode": exit_returncode,
        "exit_method": exit_method,
        "memory_check_post_load": mem_post_load,
        "memory_check_post_90d": mem_post_90d,
        "elapsed_days": elapsed_days,
        "wall_ms_per_day": round(wall_ms_per_day, 3),
        "modal_stall_ms": round(modal_stall_ms, 3),
        "active_wall_ms_per_day": round(max(0.0, wall_ms - modal_stall_ms) / elapsed_days, 3),
        "per_day_median_ms": round(statistics.median(per_day_ms), 3) if per_day_ms else None,
        "modal_pauses": modal_pauses,
        "load1_before": load_before,
        "load1_after": load_after,
        "tsv_header": tsv["header"],
        "a7b4_range_stack_hits": a7b4_hits,
        "sample_profiler_summary": tsv_summary,
    }
    (RAW_DIR / "run_metrics.json").write_text(
        json.dumps(
            {
                "tag": tag,
                "elapsed_days": elapsed_days,
                "wall_total_ms": round(wall_ms, 3),
                "wall_ms_per_day": result["wall_ms_per_day"],
                "modal_stall_ms": result["modal_stall_ms"],
                "active_wall_ms_per_day": result["active_wall_ms_per_day"],
                "per_day_median_ms": result["per_day_median_ms"],
                "modal_pauses": modal_pauses,
                "clean_exit": clean_exit,
                "exit_returncode": exit_returncode,
                "exit_method": exit_method,
                "day_events": [[d, round(ts - day_ts[d0], 6)] for d, ts in day_events],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    OUT_JSON.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if k != "sample_profiler_summary"}, indent=2))
    return result


if __name__ == "__main__":
    run_pilot()
