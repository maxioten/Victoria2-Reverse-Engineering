#!/usr/bin/env python3
"""Gate 2 determinism check: 2 identical 90-day SPA 1837.1.1 baseline runs."""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import struct
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_baseline as rb

ROOT = rb.ROOT
LAB = rb.LAB
GAME_DIR = rb.GAME_DIR
WINE_DIR = rb.WINE_DIR
GAMELOG = rb.GAMELOG
SAVE_DIR = WINE_DIR / "drive_c/users/daniel/Documents/Paradox Interactive/Victoria II/save games"
OUT_JSON = ROOT / "research" / "perf" / "determinism_spa90.json"

RNG_STATE_VA = 0x00F0ECF0
RNG_STATE_SIZE = 625 * 4  # 2500 bytes (624 state words + index at 0x00F0F6B0)
RNG_META_VA = 0x00F20C14
RNG_META_SIZE = 12        # counter (+0), flag (+4), seed (+8)


def snapshot_rng(pid: int) -> dict:
    with open(f"/proc/{pid}/mem", "rb", buffering=0) as mem:
        mem.seek(RNG_STATE_VA)
        state_bytes = mem.read(RNG_STATE_SIZE)
        mem.seek(RNG_META_VA)
        meta_bytes = mem.read(RNG_META_SIZE)
    words = list(struct.unpack("<625I", state_bytes))
    counter, flag, seed = struct.unpack("<3I", meta_bytes)
    return {
        "rng_state_sha256": hashlib.sha256(state_bytes).hexdigest(),
        "rng_index": words[624],
        "rng_counter": counter,
        "rng_flag": flag,
        "rng_seed": seed,
        "rng_words_head8": [f"0x{w:08x}" for w in words[:8]],
        "rng_words_tail4": [f"0x{w:08x}" for w in words[620:624]],
        "_state_bytes": state_bytes,
        "_meta_bytes": meta_bytes,
    }


def read_trusted_clock(pid: int, addrs: list[int]) -> int | None:
    vals = []
    with open(f"/proc/{pid}/mem", "rb", buffering=0) as mem:
        for a in addrs:
            try:
                mem.seek(a)
                v = struct.unpack("<I", mem.read(4))[0]
                if rb.INITIAL_CLOCK <= v <= rb.INITIAL_CLOCK + 500 * rb.CLOCK_STEP and (v - rb.INITIAL_CLOCK) % rb.CLOCK_STEP == 0:
                    vals.append(v)
            except OSError:
                pass
    if not vals:
        return None
    # Most frequent value among remaining trusted addresses
    return max(set(vals), key=vals.count)


def run_det_once(tag: str, target_day: int = 90) -> dict:
    rb.check_no_active_game()
    disp_n = rb.find_free_display(None)
    display = f":{disp_n}"

    session_dir = LAB / "sessions" / tag
    if session_dir.exists():
        shutil.rmtree(session_dir)
    session_dir.mkdir(parents=True, exist_ok=True)

    raw_dir = ROOT / "research" / "perf" / "raw" / tag
    if raw_dir.exists():
        shutil.rmtree(raw_dir)
    raw_dir.mkdir(parents=True, exist_ok=True)

    save_name = f"det_{tag}"
    save_file_wine = SAVE_DIR / f"{save_name}.v2"
    save_file_wine.unlink(missing_ok=True)

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

    rb.write_patch_ini(GAME_DIR / "mod" / "performance_patch.ini", sample_interval=50, skip_network_wait=0)
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

    rng_post_load = None
    rng_day90 = None
    clock_day90 = None
    modal_pauses = 0
    clean_exit = False
    exit_returncode = None

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

        mark = GAMELOG.stat().st_size if GAMELOG.exists() else 0
        rb.load_save_ui(wine_env, win, session_dir)
        if not rb.wait_launch(mark, timeout=90.0):
            rb.xdo(wine_env, "key", "--window", win, "Escape")
            time.sleep(2.0)
            mark = GAMELOG.stat().st_size if GAMELOG.exists() else 0
            rb.load_save_ui(wine_env, win, session_dir)
            if not rb.wait_launch(mark, timeout=90.0):
                raise RuntimeError("Save failed to load")

        time.sleep(4.0)
        rng_post_load = snapshot_rng(pid)

        candidates = rb.scan_clock(pid, rb.INITIAL_CLOCK)
        if not candidates:
            raise RuntimeError("No clock candidates found")

        # Increase speed to 5 BEFORE unpausing, then press space once if still paused.
        rb.xdo(wine_env, "windowfocus", win)
        for _ in range(6):
            rb.click(wine_env, win, 370, 102, delay=0.05, hold=0.05)

        if not rb.wait_clock_advance(pid, candidates, rb.INITIAL_CLOCK, timeout=2.0):
            rb.xdo(wine_env, "key", "--window", win, "space")
            if not rb.wait_clock_advance(pid, candidates, rb.INITIAL_CLOCK, timeout=8.0):
                raise RuntimeError("Game did not unpause")

        tracked = list(candidates)
        cur_vals: dict[int, int] = {}
        steps: dict[int, int] = {}
        max_seen_day = 0
        last_progress_t = time.monotonic()
        slowed_down = False

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

            active_addrs = set(cur_vals.keys())
            overall_deadline = time.monotonic() + 300.0

            while max_seen_day < target_day and time.monotonic() < overall_deadline:
                t_now = time.monotonic()
                if game_proc.poll() is not None:
                    raise RuntimeError(f"v2game.exe exited unexpectedly: {game_proc.returncode}")

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
                                last_progress_t = t_now
                                progressed = True
                                if max_seen_day >= target_day:
                                    # Immediately pause on reaching exact target_day
                                    rb.xdo(wine_env, "key", "--window", win, "space")
                                    break
                        else:
                            bad.append(addr)
                if len(active_addrs) - len(bad) >= 1:
                    for addr in bad:
                        active_addrs.discard(addr)

                if not slowed_down and max_seen_day >= target_day - 4:
                    slowed_down = True
                    # Click '-' (398, 102) 4 times to slow down before day 90 so we don't overshoot.
                    for _ in range(4):
                        rb.click(wine_env, win, 398, 102, delay=0.04, hold=0.04)

                if not progressed and (t_now - last_progress_t) > 4.0:
                    modal_pauses += 1
                    rb.shot(wine_env, session_dir / f"modal-{modal_pauses}.png")
                    resumed = False
                    for act in [
                        ("click", 550, 529, 1.2),
                        ("click", 550, 565, 1.2),
                        ("click", 550, 585, 1.2),
                        ("key", "Return", 1.0),
                        ("key", "space", 1.5),
                    ]:
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
                    if modal_pauses >= 10:
                        raise RuntimeError("Simulation stalled repeatedly")

                time.sleep(0.005 if slowed_down else 0.02)

        # Wait briefly and verify game is actually paused at day 90 (re-press space if it kept ticking)
        time.sleep(1.0)
        trusted_addrs = [a for a in active_addrs if steps.get(a, 0) >= 3] or list(active_addrs)
        c1 = read_trusted_clock(pid, trusted_addrs)
        time.sleep(0.8)
        c2 = read_trusted_clock(pid, trusted_addrs)
        if c2 is not None and c1 is not None and c2 > c1:
            rb.xdo(wine_env, "key", "--window", win, "space")
            time.sleep(1.0)
            c2 = read_trusted_clock(pid, trusted_addrs)

        clock_day90 = (c2 - rb.INITIAL_CLOCK) // rb.CLOCK_STEP if c2 is not None else max_seen_day
        rb.shot(wine_env, session_dir / "04-day90-paused.png")
        rng_day90 = snapshot_rng(pid)

        # Save game via UI: Escape -> menu_save_button (662, 275) -> editbox (662, 467) -> type name -> save (662, 495)
        rb.xdo(wine_env, "key", "--window", win, "Escape")
        time.sleep(0.8)
        rb.shot(wine_env, session_dir / "05-menu.png")
        rb.click(wine_env, win, 662, 275, delay=0.8, hold=0.1)
        rb.shot(wine_env, session_dir / "05b-save-dialog.png")
        rb.click(wine_env, win, 662, 467, delay=0.3, hold=0.08)
        for _ in range(25):
            rb.xdo(wine_env, "key", "--window", win, "BackSpace")
        rb.xdo(wine_env, "type", "--window", win, "--delay", "30", save_name)
        time.sleep(0.4)
        rb.shot(wine_env, session_dir / "05c-save-typed.png")
        rb.click(wine_env, win, 662, 495, delay=0.5, hold=0.1)

        save_deadline = time.monotonic() + 30.0
        last_sz = -1
        stable_ticks = 0
        while time.monotonic() < save_deadline:
            if save_file_wine.exists():
                sz = save_file_wine.stat().st_size
                if sz > 1_000_000 and sz == last_sz:
                    stable_ticks += 1
                    if stable_ticks >= 3:
                        break
                else:
                    stable_ticks = 0
                last_sz = sz
            time.sleep(0.5)
        if not save_file_wine.exists() or save_file_wine.stat().st_size < 1_000_000:
            rb.shot(wine_env, session_dir / "save-failed.png")
            raise RuntimeError(f"Savegame {save_file_wine} not created")

        shutil.copy2(save_file_wine, raw_dir / "day90.v2")
        save_file_wine.unlink(missing_ok=True)

        # Clean quit
        rb.xdo(wine_env, "key", "--window", win, "Escape")
        time.sleep(0.6)
        rb.click(wine_env, win, 662, 446, delay=0.5, hold=0.1)
        try:
            exit_returncode = game_proc.wait(timeout=8.0)
            clean_exit = exit_returncode == 0
        except subprocess.TimeoutExpired:
            rb.xdo(wine_env, "key", "--window", win, "Return")
            try:
                exit_returncode = game_proc.wait(timeout=8.0)
                clean_exit = exit_returncode == 0
            except subprocess.TimeoutExpired:
                pass

    finally:
        save_file_wine.unlink(missing_ok=True)
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

        for src_name in ("performance_patch_samples.tsv", "the_grand_loader.log"):
            src = GAME_DIR / src_name
            if src.exists():
                shutil.copy2(src, raw_dir / src_name)
        if GAMELOG.exists():
            shutil.copy2(GAMELOG, raw_dir / "game.log")

    save_sha = rb.sha256(raw_dir / "day90.v2")
    save_size = (raw_dir / "day90.v2").stat().st_size

    out = {
        "tag": tag,
        "display": display,
        "clock_day90_offset": clock_day90,
        "modal_pauses": modal_pauses,
        "clean_exit": clean_exit,
        "exit_returncode": exit_returncode,
        "savegame_path": str((raw_dir / "day90.v2").relative_to(ROOT)),
        "savegame_size_bytes": save_size,
        "savegame_sha256": save_sha,
        "rng_post_load": {k: v for k, v in rng_post_load.items() if not k.startswith("_")},
        "rng_day90": {k: v for k, v in rng_day90.items() if not k.startswith("_")},
        "_post_load_raw": rng_post_load,
        "_day90_raw": rng_day90,
    }
    return out


def compare_saves(p1: Path, p2: Path) -> dict:
    b1 = p1.read_bytes()
    b2 = p2.read_bytes()
    if b1 == b2:
        return {"byte_identical": True, "size_1": len(b1), "size_2": len(b2), "diff_bytes": 0, "diff_lines": []}
    min_len = min(len(b1), len(b2))
    diff_bytes = sum(1 for i in range(min_len) if b1[i] != b2[i]) + abs(len(b1) - len(b2))
    l1 = b1.decode("latin1").splitlines()
    l2 = b2.decode("latin1").splitlines()
    diff_lines = []
    for idx in range(max(len(l1), len(l2))):
        s1 = l1[idx] if idx < len(l1) else "<EOF>"
        s2 = l2[idx] if idx < len(l2) else "<EOF>"
        if s1 != s2:
            diff_lines.append({"line": idx + 1, "run1": s1[:160], "run2": s2[:160]})
            if len(diff_lines) >= 50:
                break
    return {
        "byte_identical": False,
        "size_1": len(b1),
        "size_2": len(b2),
        "line_count_1": len(l1),
        "line_count_2": len(l2),
        "diff_bytes_at_same_offset": diff_bytes,
        "total_diff_lines_capped_50": len(diff_lines),
        "diff_lines_sample": diff_lines,
    }


def main() -> None:
    r1 = run_det_once("det-run-1", target_day=90)
    time.sleep(3.0)
    r2 = run_det_once("det-run-2", target_day=90)

    post_load_rng_match = (
        r1["_post_load_raw"]["_state_bytes"] == r2["_post_load_raw"]["_state_bytes"]
        and r1["_post_load_raw"]["_meta_bytes"] == r2["_post_load_raw"]["_meta_bytes"]
    )
    day90_rng_state_match = r1["_day90_raw"]["_state_bytes"] == r2["_day90_raw"]["_state_bytes"]
    day90_rng_meta_match = r1["_day90_raw"]["_meta_bytes"] == r2["_day90_raw"]["_meta_bytes"]
    save_cmp = compare_saves(ROOT / r1["savegame_path"], ROOT / r2["savegame_path"])

    deterministic_for_gate2 = (
        r1["clock_day90_offset"] == r2["clock_day90_offset"]
        and day90_rng_state_match
        and day90_rng_meta_match
        and save_cmp["byte_identical"]
    )

    summary = {
        "schema_version": "p0-determinism-spa90-v1",
        "scenario": "SPA 1837.1.1 (input-autosave.v2)",
        "target_day_offset": 90,
        "runs": [
            {k: v for k, v in r1.items() if not k.startswith("_")},
            {k: v for k, v in r2.items() if not k.startswith("_")},
        ],
        "comparison": {
            "clock_day90_match": r1["clock_day90_offset"] == r2["clock_day90_offset"],
            "post_load_rng_exact_match": post_load_rng_match,
            "day90_rng_state_2500B_exact_match": day90_rng_state_match,
            "day90_rng_meta_12B_exact_match": day90_rng_meta_match,
            "savegame_comparison": save_cmp,
            "deterministic_for_gate2": deterministic_for_gate2,
        },
    }
    OUT_JSON.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
