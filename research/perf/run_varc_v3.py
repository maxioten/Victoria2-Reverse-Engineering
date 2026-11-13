#!/usr/bin/env python3
"""V3 Country_Recalculate variant (c): 90d live validate + n=3 paired A/B (off vs prod)."""
from __future__ import annotations

import argparse
import json
import os
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
RAW_BASE = ROOT / "research" / "perf" / "raw"
OUT_JSON = ROOT / "research" / "perf" / "varc_ab.json"

RVA_CR_SESE_ENTRY = 0x00115EA6
OFF_VARC_BLOB_ENTRY = 0x0C00
OFF_VARC_BLOB_CONFIG = 0x0C30
VARC_BLOB_SIZE = 3148

# Exact ranges in v2game.exe (preferred base 0x00400000)
RANGE_DEAD_CHECK = (0x00515EC0, 0x00515F35)
RANGE_SESE = (0x00515EA6, 0x00516285)
RANGE_CR_TOTAL = (0x00515490, 0x005163BA)


def stage_v2p2_varc(mode: str) -> str:
    if not V2P2_DLL_SRC.exists():
        raise FileNotFoundError(f"Missing {V2P2_DLL_SRC}")
    v2p2_dir = GAME_DIR / "mod" / "v2p2"
    v2p2_dir.mkdir(parents=True, exist_ok=True)
    dst_dll = v2p2_dir / "v2p2.dll"
    shutil.copy2(V2P2_DLL_SRC, dst_dll)
    dst_ini = GAME_DIR / "mod" / "v2p2.ini"
    dst_ini.write_text(
        f"[hooks]\nfn_00a7b490 = off\nfn_00515ea6 = off\nfn_00515ea6_varc = {mode}\n",
        encoding="utf-8",
    )
    return rb.sha256(dst_dll)


def unstage_v2p2() -> None:
    shutil.rmtree(GAME_DIR / "mod" / "v2p2", ignore_errors=True)
    (GAME_DIR / "mod" / "v2p2.ini").unlink(missing_ok=True)
    (GAME_DIR / "mod" / "v2p2_varc_validate.log").unlink(missing_ok=True)
    (GAME_DIR / "v2p2_varc_validate.log").unlink(missing_ok=True)


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


def inspect_varc_mem(pid: int) -> dict:
    base, maps = find_exe_base_and_maps(pid)
    entry_va = base + RVA_CR_SESE_ENTRY
    with open(f"/proc/{pid}/mem", "rb", buffering=0) as mem:
        mem.seek(entry_va)
        site_bytes = mem.read(6)
        if site_bytes[0] != 0xE9:
            return {
                "exe_base": f"0x{base:08x}",
                "sese_patched": False,
                "site_bytes": site_bytes.hex(" "),
            }
        rel32 = struct.unpack("<i", site_bytes[1:5])[0]
        blob_entry = (entry_va + 5 + rel32) & 0xFFFFFFFF
        blob_base = blob_entry - OFF_VARC_BLOB_ENTRY
        mem.seek(blob_base + OFF_VARC_BLOB_CONFIG)
        cfg_bytes = mem.read(28)
        _eb, _ex, _bc, _bx, varc_state_ptr, varc_mode, _sf = struct.unpack("<7I", cfg_bytes)
        mem.seek(varc_state_ptr)
        state_bytes = mem.read(512 + 11 * 4)
        words = struct.unpack("<128I", state_bytes[:512])
        initialized, dirty, total_tags, entries_ptr, _sbase, val_mode, mm_cnt, last_idx, last_exp, last_act, _cb = struct.unpack(
            "<11I", state_bytes[512:]
        )

    blob_perms = None
    for start, end, perms, _ in maps:
        if start <= blob_entry < end:
            blob_perms = perms
            break

    living_tags = sum(int(w).bit_count() for w in words)
    return {
        "exe_base": f"0x{base:08x}",
        "sese_patched": True,
        "site_bytes": site_bytes.hex(" "),
        "blob_base": f"0x{blob_base:08x}",
        "blob_end": f"0x{blob_base + VARC_BLOB_SIZE:08x}",
        "blob_entry": f"0x{blob_entry:08x}",
        "blob_page_perms": blob_perms,
        "varc_mode": varc_mode,
        "initialized": initialized,
        "dirty": dirty,
        "total_tags": total_tags,
        "living_tags_bitcount": living_tags,
        "validate_mode": val_mode,
        "mismatch_count": mm_cnt,
        "last_mismatch_idx": last_idx,
        "last_expected": last_exp,
        "last_actual": last_act,
    }


def run_one(tag: str, varc_mode: str, days_target: int = 90, sample_interval: int = 50) -> dict:
    rb.check_no_active_game()
    disp_n = rb.find_free_display(None)
    display = f":{disp_n}"

    session_dir = LAB / "sessions" / tag
    if session_dir.exists():
        shutil.rmtree(session_dir)
    session_dir.mkdir(parents=True, exist_ok=True)

    raw_dir = RAW_BASE / tag
    if raw_dir.exists():
        shutil.rmtree(raw_dir)
    raw_dir.mkdir(parents=True, exist_ok=True)

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

    unstage_v2p2()
    v2p2_sha = stage_v2p2_varc(varc_mode)
    rb.write_patch_ini(GAME_DIR / "mod" / "performance_patch.ini", sample_interval, skip_network_wait=0)
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

    load_before = rb.load1()
    mem_post_90d = None
    validate_log_text = ""
    validate_log_exists = False

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
                rb.shot(wine_env, session_dir / "load-failed.png")
                raise RuntimeError("Save failed to load")

        time.sleep(4.0)
        candidates = rb.scan_clock(pid, rb.INITIAL_CLOCK)
        if not candidates:
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
                    modal_stall_ms += (last_progress_t - t_now + 4.0) * 1000.0
                    if modal_pauses >= 10:
                        raise RuntimeError("Simulation stalled repeatedly")

                time.sleep(0.02)

        if max_seen_day < stop_day_offset:
            raise TimeoutError(f"Only reached day {max_seen_day}, target {stop_day_offset}")

        time.sleep(1.5)
        mem_post_90d = inspect_varc_mem(pid)
        rb.xdo(wine_env, "key", "--window", win, "space")
        time.sleep(0.3)

    finally:
        if game_proc is not None and game_proc.poll() is None:
            game_proc.terminate()
            try:
                game_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                game_proc.kill()
                game_proc.wait(timeout=5)
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
        for vlog in (GAME_DIR / "mod" / "v2p2_varc_validate.log", GAME_DIR / "v2p2_varc_validate.log"):
            if vlog.exists():
                validate_log_exists = True
                validate_log_text = vlog.read_text(errors="replace")
                shutil.copy2(vlog, raw_dir / "v2p2_varc_validate.log")

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

    metrics = {
        "tag": tag,
        "varc_mode": varc_mode,
        "v2p2_dll_sha256": v2p2_sha,
        "display": display,
        "sample_interval_ms": sample_interval,
        "start_day_offset": d0,
        "end_day_offset": d_end,
        "elapsed_days": elapsed_days,
        "wall_total_ms": round(wall_ms, 3),
        "wall_ms_per_day": round(wall_ms_per_day, 3),
        "modal_stall_ms": round(modal_stall_ms, 3),
        "active_wall_ms_per_day": round(max(0.0, wall_ms - modal_stall_ms) / elapsed_days, 3),
        "per_day_median_ms": round(statistics.median(per_day_ms), 3) if per_day_ms else None,
        "modal_pauses": modal_pauses,
        "load1_before": load_before,
        "load1_after": load_after,
        "mem_post_90d": mem_post_90d,
        "validate_log_exists": validate_log_exists,
        "validate_log_lines": len(validate_log_text.splitlines()) if validate_log_text else 0,
        "day_events": [[d, round(ts - day_ts[d0], 6)] for d, ts in day_events],
    }
    (raw_dir / "run_metrics.json").write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in metrics.items() if k != "day_events"}, indent=2), flush=True)
    return metrics


# Direct .text helper VA ranges called by cr_sese_body.c (whose stacks lose 0x005089E0 when
# sampled inside the EBP-as-GPR VirtualAlloc SESE blob).
SESE_HELPER_RANGES = (
    (0x00511140, 0x005112F6),  # FUN_00511140 (call_00511140)
    (0x004A8300, 0x004A8323),  # FUN_004a8300 (call_004A8300)
    (0x005067D0, 0x005068E8),  # FUN_005067d0/68b0 called under 00511140
    (0x004D61D0, 0x004D62FF),  # vec_push pair
    (0x004E9B90, 0x004E9C9F),  # vec_push ptr
    (0x004A7BC0, 0x004A7CBF),  # list append 004A7BC0
    (0x005F2AE0, 0x005F2BDF),  # list append 005F2AE0
    (0x009692C0, 0x009693BF),  # FUN_009692C0
    (0x005163C0, 0x005164BF),  # FUN_005163C0
)


def analyze_tsv_cr(tsv_path: Path, blob_range: tuple[int, int] | None) -> dict:
    tsv = ab.parse_sample_tsv(tsv_path)
    total = sum(c for c, _, _ in tsv["stacks"])

    def in_range(va: int, lo: int, hi: int) -> bool:
        return lo <= va <= hi

    dead_leaf = 0
    dead_incl = 0
    sese_exe_leaf = 0
    sese_exe_incl = 0
    blob_mapped_leaf = 0
    blob_mapped_incl = 0
    blob_q_a7b825 = 0
    helpers_dropped_5089e0 = 0
    sese_incl = 0
    cr_exe_leaf = 0
    cr_exe_incl = 0
    cr_incl = 0

    for cnt, _ms, frames in tsv["stacks"]:
        vas = []
        for fr in frames:
            if fr.startswith("0x") or fr.startswith("0X"):
                vas.append(int(fr, 16))
            else:
                vas.append(None)

        leaf_va = vas[0] if vas else None
        if leaf_va is not None:
            if in_range(leaf_va, *RANGE_DEAD_CHECK):
                dead_leaf += cnt
            if in_range(leaf_va, *RANGE_SESE):
                sese_exe_leaf += cnt
            if in_range(leaf_va, *RANGE_CR_TOTAL):
                cr_exe_leaf += cnt
            if blob_range and in_range(leaf_va, blob_range[0], blob_range[1] - 1):
                blob_mapped_leaf += cnt

        if any(v is not None and in_range(v, *RANGE_DEAD_CHECK) for v in vas):
            dead_incl += cnt

        sese_exe_hit = any(v is not None and in_range(v, *RANGE_SESE) for v in vas)
        blob_mapped_hit = bool(
            blob_range and any(v is not None and in_range(v, blob_range[0], blob_range[1] - 1) for v in vas)
        )
        cr_exe_hit = any(v is not None and in_range(v, *RANGE_CR_TOTAL) for v in vas)

        # performance_patch.dll emits '?' for EIPs inside VirtualAlloc'd non-PE code and
        # drops frame 0x005089E0 when sampling the -O2 EBP-as-GPR blob or its .text helpers,
        # leaving 0x00A7B825;0x00685701 directly underneath.
        q_a7_hit = len(frames) >= 2 and frames[0] == "?" and frames[1] == "0x00A7B825"

        helper_dropped_hit = False
        if not cr_exe_hit and "0x005089E0" not in frames:
            for i in range(len(frames) - 1):
                if frames[i] == "0x00A7B825" and frames[i + 1] == "0x00685701":
                    pref_vas = vas[:i]
                    if any(
                        v is not None and any(in_range(v, lo, hi) for lo, hi in SESE_HELPER_RANGES)
                        for v in pref_vas
                    ):
                        helper_dropped_hit = True
                    break

        if sese_exe_hit:
            sese_exe_incl += cnt
        if blob_mapped_hit:
            blob_mapped_incl += cnt
        if q_a7_hit:
            blob_q_a7b825 += cnt
        if helper_dropped_hit:
            helpers_dropped_5089e0 += cnt
        if cr_exe_hit:
            cr_exe_incl += cnt

        if sese_exe_hit or blob_mapped_hit or q_a7_hit or helper_dropped_hit:
            sese_incl += cnt
        if cr_exe_hit or blob_mapped_hit or q_a7_hit or helper_dropped_hit:
            cr_incl += cnt

    def pct(n: int) -> float:
        return round((n / total * 100.0), 3) if total else 0.0

    sese_leaf_total = sese_exe_leaf + blob_mapped_leaf + blob_q_a7b825
    cr_leaf_total = cr_exe_leaf + blob_mapped_leaf + blob_q_a7b825
    return {
        "tsv_header": tsv["header"],
        "total_samples": total,
        "dead_check_00515ec0_00515f35": {"leaf": dead_leaf, "leaf_pct": pct(dead_leaf), "incl": dead_incl, "incl_pct": pct(dead_incl)},
        "sese_total_incl_blob": {
            "exe_leaf": sese_exe_leaf,
            "exe_incl": sese_exe_incl,
            "blob_mapped_leaf": blob_mapped_leaf,
            "blob_mapped_incl": blob_mapped_incl,
            "blob_proxy_q_a7b825": blob_q_a7b825,
            "helpers_dropped_5089e0": helpers_dropped_5089e0,
            "leaf": sese_leaf_total,
            "leaf_pct": pct(sese_leaf_total),
            "incl": sese_incl,
            "incl_pct": pct(sese_incl),
        },
        "country_recalculate_total": {
            "exe_leaf": cr_exe_leaf,
            "exe_incl": cr_exe_incl,
            "leaf": cr_leaf_total,
            "leaf_pct": pct(cr_leaf_total),
            "incl": cr_incl,
            "incl_pct": pct(cr_incl),
        },
    }


def summarize_results() -> dict:
    def load_entry(tag: str) -> dict:
        d = RAW_BASE / tag
        m = json.loads((d / "run_metrics.json").read_text(encoding="utf-8"))
        mem = m.get("mem_post_90d") or {}
        blob_range = None
        if mem.get("sese_patched") and mem.get("blob_base") and mem.get("blob_end"):
            blob_range = (int(mem["blob_base"], 16), int(mem["blob_end"], 16))
        cr = analyze_tsv_cr(d / "performance_patch_samples.tsv", blob_range)
        tgl = (d / "the_grand_loader.log").read_text(errors="replace")
        v2p2_lines = [ln.strip() for ln in tgl.splitlines() if "v2p2" in ln or "plugin(s) loaded" in ln]
        return {
            "tag": tag,
            "varc_mode": m["varc_mode"],
            "v2p2_dll_sha256": m["v2p2_dll_sha256"],
            "elapsed_days": m["elapsed_days"],
            "wall_ms_per_day": m["wall_ms_per_day"],
            "modal_stall_ms": m["modal_stall_ms"],
            "active_wall_ms_per_day": m["active_wall_ms_per_day"],
            "per_day_median_ms": m["per_day_median_ms"],
            "modal_pauses": m["modal_pauses"],
            "load1_before": m["load1_before"],
            "load1_after": m["load1_after"],
            "loader_lines": v2p2_lines,
            "mem_post_90d": mem,
            "validate_log_exists": m["validate_log_exists"],
            "validate_log_lines": m["validate_log_lines"],
            "profiler_cr": cr,
        }

    val_run = load_entry("varc-validate-90d")
    pairs = []
    for idx in (1, 2, 3):
        off_e = load_entry(f"ab-0{idx}-off")
        prod_e = load_entry(f"ab-0{idx}-prod")
        pairs.append({
            "pair": idx,
            "off": off_e,
            "prod": prod_e,
            "delta_per_day_median_ms": round(prod_e["per_day_median_ms"] - off_e["per_day_median_ms"], 3),
            "delta_active_wall_ms_per_day": round(prod_e["active_wall_ms_per_day"] - off_e["active_wall_ms_per_day"], 3),
            "delta_dead_check_incl_samples": prod_e["profiler_cr"]["dead_check_00515ec0_00515f35"]["incl"] - off_e["profiler_cr"]["dead_check_00515ec0_00515f35"]["incl"],
            "delta_sese_incl_samples": prod_e["profiler_cr"]["sese_total_incl_blob"]["incl"] - off_e["profiler_cr"]["sese_total_incl_blob"]["incl"],
            "delta_cr_total_incl_samples": prod_e["profiler_cr"]["country_recalculate_total"]["incl"] - off_e["profiler_cr"]["country_recalculate_total"]["incl"],
        })

    off_runs = [p["off"] for p in pairs]
    prod_runs = [p["prod"] for p in pairs]

    def sum_field(runs: list[dict], path: tuple[str, ...]) -> int:
        tot = 0
        for r in runs:
            cur = r
            for k in path:
                cur = cur[k]
            tot += cur
        return tot

    off_tot_samples = sum(r["profiler_cr"]["total_samples"] for r in off_runs)
    prod_tot_samples = sum(r["profiler_cr"]["total_samples"] for r in prod_runs)
    off_dead_incl = sum_field(off_runs, ("profiler_cr", "dead_check_00515ec0_00515f35", "incl"))
    prod_dead_incl = sum_field(prod_runs, ("profiler_cr", "dead_check_00515ec0_00515f35", "incl"))
    off_sese_incl = sum_field(off_runs, ("profiler_cr", "sese_total_incl_blob", "incl"))
    prod_sese_incl = sum_field(prod_runs, ("profiler_cr", "sese_total_incl_blob", "incl"))
    off_cr_incl = sum_field(off_runs, ("profiler_cr", "country_recalculate_total", "incl"))
    prod_cr_incl = sum_field(prod_runs, ("profiler_cr", "country_recalculate_total", "incl"))

    out = {
        "schema_version": "p0-varc-v3-v2",
        "v2p2_dll_src_sha256": rb.sha256(V2P2_DLL_SRC),
        "profiler_attribution_note": (
            "performance_patch.dll emits '?' for VirtualAlloc'd non-PE blob EIPs and its "
            "frame walker drops 0x005089E0 when sampling the -O2 EBP-as-GPR cr_sese_varc blob "
            "or its .text helpers (0x00511140, 0x004A8300, 0x009692C0, etc.). "
            "Accordingly, sese_total_incl_blob and country_recalculate_total include both "
            "blob_proxy_q_a7b825 ('?;0x00A7B825;...') and helpers_dropped_5089e0 (SESE helpers "
            "above '0x00A7B825;0x00685701' with 0x005089E0 dropped)."
        ),
        "validate_90d": val_run,
        "paired_ab": pairs,
        "aggregate_ab": {
            "n_pairs": len(pairs),
            "off": {
                "per_day_median_ms_median": round(statistics.median([r["per_day_median_ms"] for r in off_runs]), 3),
                "active_wall_ms_per_day_median": round(statistics.median([r["active_wall_ms_per_day"] for r in off_runs]), 3),
                "total_samples": off_tot_samples,
                "dead_check_leaf_samples": sum_field(off_runs, ("profiler_cr", "dead_check_00515ec0_00515f35", "leaf")),
                "dead_check_incl_samples": off_dead_incl,
                "dead_check_incl_pct": round(off_dead_incl / off_tot_samples * 100.0, 3) if off_tot_samples else 0.0,
                "sese_exe_incl_samples": sum_field(off_runs, ("profiler_cr", "sese_total_incl_blob", "exe_incl")),
                "sese_blob_q_a7b825_samples": sum_field(off_runs, ("profiler_cr", "sese_total_incl_blob", "blob_proxy_q_a7b825")),
                "sese_helpers_dropped_5089e0_samples": sum_field(off_runs, ("profiler_cr", "sese_total_incl_blob", "helpers_dropped_5089e0")),
                "sese_leaf_samples": sum_field(off_runs, ("profiler_cr", "sese_total_incl_blob", "leaf")),
                "sese_incl_samples": off_sese_incl,
                "sese_incl_pct": round(off_sese_incl / off_tot_samples * 100.0, 3) if off_tot_samples else 0.0,
                "cr_total_leaf_samples": sum_field(off_runs, ("profiler_cr", "country_recalculate_total", "leaf")),
                "cr_total_incl_samples": off_cr_incl,
                "cr_total_incl_pct": round(off_cr_incl / off_tot_samples * 100.0, 3) if off_tot_samples else 0.0,
            },
            "prod": {
                "per_day_median_ms_median": round(statistics.median([r["per_day_median_ms"] for r in prod_runs]), 3),
                "active_wall_ms_per_day_median": round(statistics.median([r["active_wall_ms_per_day"] for r in prod_runs]), 3),
                "total_samples": prod_tot_samples,
                "dead_check_leaf_samples": sum_field(prod_runs, ("profiler_cr", "dead_check_00515ec0_00515f35", "leaf")),
                "dead_check_incl_samples": prod_dead_incl,
                "dead_check_incl_pct": round(prod_dead_incl / prod_tot_samples * 100.0, 3) if prod_tot_samples else 0.0,
                "sese_exe_incl_samples": sum_field(prod_runs, ("profiler_cr", "sese_total_incl_blob", "exe_incl")),
                "sese_blob_q_a7b825_samples": sum_field(prod_runs, ("profiler_cr", "sese_total_incl_blob", "blob_proxy_q_a7b825")),
                "sese_helpers_dropped_5089e0_samples": sum_field(prod_runs, ("profiler_cr", "sese_total_incl_blob", "helpers_dropped_5089e0")),
                "sese_leaf_samples": sum_field(prod_runs, ("profiler_cr", "sese_total_incl_blob", "leaf")),
                "sese_incl_samples": prod_sese_incl,
                "sese_incl_pct": round(prod_sese_incl / prod_tot_samples * 100.0, 3) if prod_tot_samples else 0.0,
                "cr_total_leaf_samples": sum_field(prod_runs, ("profiler_cr", "country_recalculate_total", "leaf")),
                "cr_total_incl_samples": prod_cr_incl,
                "cr_total_incl_pct": round(prod_cr_incl / prod_tot_samples * 100.0, 3) if prod_tot_samples else 0.0,
            },
        },
    }
    OUT_JSON.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--analyze-only", action="store_true")
    args = ap.parse_args()

    if not args.analyze_only:
        schedule = [
            ("varc-validate-90d", "validate"),
            ("ab-01-off", "off"),
            ("ab-01-prod", "prod"),
            ("ab-02-off", "off"),
            ("ab-02-prod", "prod"),
            ("ab-03-off", "off"),
            ("ab-03-prod", "prod"),
        ]
        for idx, (tag, mode) in enumerate(schedule):
            print(f"=== [{idx+1}/{len(schedule)}] Starting {tag} (fn_00515ea6_varc={mode}) ===", flush=True)
            run_one(tag, mode, days_target=90, sample_interval=50)
            if idx + 1 < len(schedule):
                time.sleep(3.0)

    out = summarize_results()
    print("=== V3 SUMMARY ===", flush=True)
    print(json.dumps(out["aggregate_ab"], indent=2), flush=True)


if __name__ == "__main__":
    main()
