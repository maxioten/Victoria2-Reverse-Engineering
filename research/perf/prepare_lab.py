#!/usr/bin/env python3
"""Prepare an isolated Victoria II performance baseline lab in experiments/perf-baseline-lab/."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "experiments" / "perf-baseline-lab"
SOURCE = ROOT / "base-game"
DAY_TICK_WINE = ROOT / "experiments" / "day-tick-lab" / "wine"
SAVE_SOURCE = Path(
    os.environ.get(
        "V2_SAVE_SOURCE",
        str(Path.home() / "Documents/Paradox Interactive/Victoria II/save games/autosave.v2"),
    )
)

EXPECTED_EXE_SHA256 = "62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648"
EXPECTED_SAVE_SHA256 = "a3885cc5b64328e04b45b92c2329e5cfa7d2d931746110fb750e47475fd39e1b"
EXPECTED_PATCH_SHA256 = "2681385e9314d204fb00f5244d9624162366d332b47474e834301afb3ddaf9da"
EXPECTED_LOADER_SHA256 = "c6e25bdc119d01014064d18284ddb7116b6bcca8abfbd9159a31b3e39e8d746f"
EXPECTED_LUA_SHA256 = "e50c69219a676587199fce1e27d9ef9f2924990f006b3f84cb37971f2e804215"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def write_patch_ini(ini_path: Path, *, sample_profiler: int = 50, skip_network_wait: int = 0) -> None:
    ini_path.write_text(
        f"""; P0 reproducible baseline config: all gameplay/perf optimizations OFF except requested control
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
background_sleep_ms = 0
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
sample_profiler = {sample_profiler}
decision_profiling = 0
cull_cb_profiling = 0
oos_test_button = 0
network_log = 0
"""
    )


def main() -> None:
    assert sha256(SOURCE / "v2game.exe") == EXPECTED_EXE_SHA256, "Unexpected base-game/v2game.exe hash"
    assert sha256(SAVE_SOURCE) == EXPECTED_SAVE_SHA256, "Unexpected input save hash"
    assert sha256(SOURCE / "performance_patch/performance_patch.dll") == EXPECTED_PATCH_SHA256
    assert sha256(SOURCE / "dinput8.dll") == EXPECTED_LOADER_SHA256
    assert sha256(SOURCE / "lua5.1.dll") == EXPECTED_LUA_SHA256

    LAB.mkdir(parents=True, exist_ok=True)
    game_dir = LAB / "game"
    wine_dir = LAB / "wine"

    if not game_dir.exists():
        subprocess.run(["cp", "-a", "--reflink=auto", str(SOURCE), str(game_dir)], check=True)
    if not wine_dir.exists():
        subprocess.run(["cp", "-a", "--reflink=auto", str(DAY_TICK_WINE), str(wine_dir)], check=True)

    # Use original vanilla lua5.1.dll as lua51.dll (disabling V2DLL so we isolate v2game.exe).
    shutil.copy2(SOURCE / "lua5.1.dll", game_dir / "lua51.dll")
    assert sha256(game_dir / "lua51.dll") == EXPECTED_LUA_SHA256

    # Copy DirectX runtime DLLs used in day-tick-lab.
    dx_info = []
    for name in ("d3dx9_41.dll", "d3dcompiler_41.dll", "d3dcompiler_43.dll"):
        installed = Path(os.environ.get("WINEPREFIX", str(Path.home() / ".wine"))) / "drive_c/windows/syswow64" / name
        shutil.copy2(installed, game_dir / name)
        dx_info.append({"name": name, "sha256": sha256(installed)})

    # Remove v2probe from lab mod/ and configure performance_patch under mod/.
    mod_dir = game_dir / "mod"
    (mod_dir / "v2probe.ini").unlink(missing_ok=True)
    if (mod_dir / "v2probe").exists():
        shutil.rmtree(mod_dir / "v2probe")

    patch_mod_dir = mod_dir / "performance_patch"
    patch_mod_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(SOURCE / "performance_patch/performance_patch.dll", patch_mod_dir / "performance_patch.dll")
    write_patch_ini(mod_dir / "performance_patch.ini", sample_profiler=50, skip_network_wait=0)

    # Clean stale logs/TSVs in lab game copy.
    for stale in ("performance_patch_samples.tsv", "the_grand_loader.log"):
        (game_dir / stale).unlink(missing_ok=True)

    # Prepare isolated Documents/Paradox Interactive/Victoria II/ in lab wine prefix.
    profile = wine_dir / "drive_c/users/daniel/Documents/Paradox Interactive/Victoria II"
    (profile / "logs").mkdir(parents=True, exist_ok=True)
    for f in (profile / "logs").glob("*"):
        if f.is_file():
            f.unlink()
    save_dir = profile / "save games"
    save_dir.mkdir(parents=True, exist_ok=True)
    for f in save_dir.glob("*"):
        if f.is_file():
            f.unlink()
    shutil.copy2(SAVE_SOURCE, save_dir / "input-autosave.v2")

    settings_path = profile / "settings.txt"
    settings = settings_path.read_text()
    settings = re.sub(r"x=\d+", "x=1280", settings)
    settings = re.sub(r"y=\d+", "y=720", settings)
    settings = settings.replace("borderless=yes", "borderless=no")
    settings = re.sub(r"(master_volume|music_volume)=\S+", r"\1=0.000000", settings)
    settings = re.sub(r'autosave="[^"]*"', 'autosave="NEVER"', settings)
    settings_path.write_text(settings)

    receipt = {
        "v2game_sha256": sha256(game_dir / "v2game.exe"),
        "save_sha256": sha256(save_dir / "input-autosave.v2"),
        "dinput8_sha256": sha256(game_dir / "dinput8.dll"),
        "lua51_sha256": sha256(game_dir / "lua51.dll"),
        "performance_patch_sha256": sha256(patch_mod_dir / "performance_patch.dll"),
        "directx": dx_info,
        "lab_game_dir": str(game_dir),
        "lab_wine_dir": str(wine_dir),
        "settings_sha256": sha256(settings_path),
    }
    (LAB / "lab-setup.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print("Prepared experiments/perf-baseline-lab cleanly.")


if __name__ == "__main__":
    main()
