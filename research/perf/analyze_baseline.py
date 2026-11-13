#!/usr/bin/env python3
"""Analyze P0 baseline runs and generate research/perf/baseline.json."""
from __future__ import annotations

import bisect
import csv
import json
import math
import re
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
PERF_DIR = ROOT / "research" / "perf"
RAW_DIR = PERF_DIR / "raw"
GHIDRA_FUNCS_CSV = ROOT / "research" / "evidence" / "generated" / "ghidra-converged" / "functions.csv"
BASE_GAME_TSV = ROOT / "base-game" / "performance_patch_samples.tsv"

HEADER_RE = re.compile(
    r"interval (\d+) ms, (\d+) days \(day (\d+) to (\d+), year (\d+)\), "
    r"(\d+) samples, ([\d.]+) ms/day sampled, (\d+) stacks, (\d+) dropped"
)


def load_ghidra_functions() -> tuple[list[int], list[tuple[int, int, str]]]:
    entries: list[tuple[int, int, str]] = []
    with GHIDRA_FUNCS_CSV.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            start = int(row["entry_va"], 16)
            end = int(row["end_va"], 16)
            name = row["name"]
            entries.append((start, end, name))
    entries.sort(key=lambda x: x[0])
    starts = [e[0] for e in entries]
    return starts, entries


def resolve_va(va: int, starts: list[int], entries: list[tuple[int, int, str]]) -> dict[str, Any]:
    idx = bisect.bisect_right(starts, va) - 1
    if idx >= 0:
        start, end, name = entries[idx]
        if start <= va <= end:
            return {
                "func_va": f"0x{start:08X}",
                "func_name": name,
                "offset": f"+0x{va - start:X}",
            }
    return {
        "func_va": f"0x{va:08X}",
        "func_name": f"unmapped_0x{va:08X}",
        "offset": "+0x0",
    }


def parse_sample_tsv(tsv_path: Path) -> dict[str, Any]:
    mods: dict[str, str] = {}
    stacks: list[tuple[int, float, list[str]]] = []
    header_info: dict[str, Any] = {}
    for line in tsv_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line:
            continue
        if line.startswith("#"):
            m = HEADER_RE.search(line)
            if m:
                header_info = {
                    "interval_ms": int(m.group(1)),
                    "days": int(m.group(2)),
                    "start_day": int(m.group(3)),
                    "end_day": int(m.group(4)),
                    "year": int(m.group(5)),
                    "samples": int(m.group(6)),
                    "ms_per_day_sampled": float(m.group(7)),
                    "unique_stacks": int(m.group(8)),
                    "dropped": int(m.group(9)),
                }
            continue
        parts = line.split("\t")
        if parts[0] == "mod" and len(parts) >= 3:
            mods[parts[1]] = parts[2]
        elif parts[0] == "stack" and len(parts) >= 4:
            cnt = int(parts[1])
            ms_day = float(parts[2])
            frames = [fr.strip() for fr in parts[3].split(";") if fr.strip()]
            stacks.append((cnt, ms_day, frames))
    return {"header": header_info, "mods": mods, "stacks": stacks}


def parse_loader_flags(log_path: Path) -> dict[str, str]:
    flags: dict[str, str] = {}
    if not log_path.exists():
        return flags
    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.search(r"\[performance_patch\]\s+([a-z0-9_]+):\s+(.*)$", line)
        if m:
            flags[m.group(1)] = m.group(2).strip()
    return flags


def quantiles_q1_q3(vals: list[float]) -> tuple[float, float]:
    s = sorted(vals)
    n = len(s)
    if n < 2:
        return s[0], s[0]
    qs = statistics.quantiles(s, n=4, method="inclusive")
    return qs[0], qs[2]


def summarize_metric(vals: list[float]) -> dict[str, Any]:
    n = len(vals)
    med = statistics.median(vals)
    mean = statistics.mean(vals)
    std = statistics.stdev(vals) if n > 1 else 0.0
    q1, q3 = quantiles_q1_q3(vals)
    iqr = q3 - q1
    cv_pct = (std / mean * 100.0) if mean else 0.0
    iqr_pct = (iqr / med * 100.0) if med else 0.0
    rng = max(vals) - min(vals)
    rng_pct = (rng / med * 100.0) if med else 0.0
    return {
        "n": n,
        "values": [round(v, 3) for v in vals],
        "min": round(min(vals), 3),
        "max": round(max(vals), 3),
        "median": round(med, 3),
        "mean": round(mean, 3),
        "stdev": round(std, 3),
        "cv_pct": round(cv_pct, 3),
        "q1": round(q1, 3),
        "q3": round(q3, 3),
        "iqr": round(iqr, 3),
        "iqr_pct_of_median": round(iqr_pct, 3),
        "range_pct_of_median": round(rng_pct, 3),
        "robust_sigma_iqr": round(iqr / 1.3489795, 3),
    }


def aggregate_samples(
    runs: list[dict[str, Any]],
    starts: list[int],
    entries: list[tuple[int, int, str]],
) -> dict[str, Any]:
    total_samples = 0
    total_days = 0
    leaf_counts: Counter[str] = Counter()
    module_leaf_counts: Counter[str] = Counter()
    exe_leaf_func_counts: Counter[str] = Counter()
    exe_inclusive_func_counts: Counter[str] = Counter()
    stack_counts: Counter[str] = Counter()

    func_meta: dict[str, dict[str, str]] = {}

    for run in runs:
        tsv = run["_tsv"]
        mods = tsv["mods"]
        total_days += tsv["header"].get("days", 0)
        for cnt, _ms_day, frames in tsv["stacks"]:
            total_samples += cnt
            if not frames:
                continue

            # Resolve leaf
            leaf = frames[0]
            if leaf.startswith("0x") or leaf.startswith("0X"):
                va = int(leaf, 16)
                res = resolve_va(va, starts, entries)
                module_leaf_counts["v2game.exe"] += cnt
                fkey = res["func_va"]
                func_meta[fkey] = res
                exe_leaf_func_counts[fkey] += cnt
                leaf_counts[f"v2game.exe:{res['func_name']} ({res['func_va']}{res['offset']})"] += cnt
            elif ":" in leaf:
                mid, sym = leaf.split(":", 1)
                mod_name = mods.get(mid, mid)
                module_leaf_counts[mod_name] += cnt
                leaf_counts[f"{mod_name}:{sym}"] += cnt
            else:
                mod_name = mods.get(leaf, leaf)
                module_leaf_counts[mod_name] += cnt
                leaf_counts[f"{mod_name}:<unknown>"] += cnt

            # Resolve inclusive v2game.exe functions (unique per stack)
            seen_funcs: set[str] = set()
            norm_frames: list[str] = []
            for fr in frames:
                if fr.startswith("0x") or fr.startswith("0X"):
                    va = int(fr, 16)
                    res = resolve_va(va, starts, entries)
                    fkey = res["func_va"]
                    func_meta[fkey] = res
                    seen_funcs.add(fkey)
                    norm_frames.append(f"{res['func_name']}@{fr}")
                elif ":" in fr:
                    mid, sym = fr.split(":", 1)
                    norm_frames.append(f"{mods.get(mid, mid)}:{sym}")
                else:
                    norm_frames.append(mods.get(fr, fr))
            for fkey in seen_funcs:
                exe_inclusive_func_counts[fkey] += cnt
            stack_counts[" ; ".join(norm_frames[:10])] += cnt

    def pct(c: int) -> float:
        return round((c / total_samples * 100.0), 2) if total_samples else 0.0

    return {
        "total_samples": total_samples,
        "total_profiled_days": total_days,
        "module_leaf_breakdown": [
            {"module": mod, "samples": cnt, "pct": pct(cnt)}
            for mod, cnt in module_leaf_counts.most_common()
        ],
        "top_leaf_frames": [
            {"frame": k, "samples": cnt, "pct": pct(cnt)}
            for k, cnt in leaf_counts.most_common(25)
        ],
        "top_exe_leaf_functions": [
            {
                "func_va": fkey,
                "func_name": func_meta[fkey]["func_name"],
                "samples": cnt,
                "pct": pct(cnt),
            }
            for fkey, cnt in exe_leaf_func_counts.most_common(25)
        ],
        "top_exe_inclusive_functions": [
            {
                "func_va": fkey,
                "func_name": func_meta[fkey]["func_name"],
                "samples": cnt,
                "pct": pct(cnt),
            }
            for fkey, cnt in exe_inclusive_func_counts.most_common(25)
        ],
        "top_stacks_prefix10": [
            {"stack": st, "samples": cnt, "pct": pct(cnt)}
            for st, cnt in stack_counts.most_common(15)
        ],
    }


def audit_base_game_tsv() -> dict[str, Any]:
    parsed = parse_sample_tsv(BASE_GAME_TSV)
    hdr = parsed["header"]
    sum_count = sum(c for c, _, _ in parsed["stacks"])
    sum_ms_day = sum(m for _, m, _ in parsed["stacks"])
    days = hdr["days"]
    interval = hdr["interval_ms"]
    return {
        "file": str(BASE_GAME_TSV.relative_to(ROOT)),
        "header": hdr,
        "parsed_stack_rows": len(parsed["stacks"]),
        "sum_stack_counts": sum_count,
        "sum_stack_ms_per_day": round(sum_ms_day, 4),
        "expected_at_100ms_per_sample": round(sum_count * interval / days, 4),
        "actual_at_50ms_clamp_per_sample": round(sum_count * 50.0 / days, 4),
        "confirmed_root_cause": (
            "performance_patch.dll caps sample_profiler interval at 100 ms (0x10036590), "
            "sleeps 100 ms per iteration (0x10037494), yet computes max_sample_qpc = (qpc_freq * 50) / 1000 "
            "at 0x10037457..0x1003747b and clamps measured delta_qpc to max_sample_qpc at 0x100374cd..0x100374d9. "
            "Every 100 ms sleep sample is therefore recorded with 50 ms of QPC weight, halving reported ms/day sampled."
        ),
    }


def load_run(run_dir: Path) -> dict[str, Any]:
    metrics = json.loads((run_dir / "run_metrics.json").read_text(encoding="utf-8"))
    tsv = parse_sample_tsv(run_dir / "performance_patch_samples.tsv")
    loader_flags = parse_loader_flags(run_dir / "the_grand_loader.log")
    record = {
        "tag": metrics["tag"],
        "skip_network_wait": metrics["skip_network_wait"],
        "skip_network_wait_log": loader_flags.get("skip_network_wait", "unknown"),
        "sample_interval_ms": metrics["sample_interval_ms"],
        "elapsed_days": metrics["elapsed_days"],
        "wall_total_ms": metrics["wall_total_ms"],
        "wall_ms_per_day": metrics["wall_ms_per_day"],
        "modal_stall_ms": metrics.get("modal_stall_ms", 0.0),
        "active_wall_ms_per_day": metrics.get("active_wall_ms_per_day", metrics["wall_ms_per_day"]),
        "per_day_median_ms": metrics["per_day_median_ms"],
        "per_day_mean_ms": metrics["per_day_mean_ms"],
        "per_day_stdev_ms": metrics["per_day_stdev_ms"],
        "modal_pauses": metrics["modal_pauses"],
        "load1_before": metrics["load1_before"],
        "load1_after": metrics["load1_after"],
        "tsv_header": tsv["header"],
        "_tsv": tsv,
    }
    return record


def main() -> None:
    starts, entries = load_ghidra_functions()
    run_dirs = sorted(p for p in RAW_DIR.iterdir() if p.is_dir() and (p / "run_metrics.json").exists())
    baseline_runs: list[dict[str, Any]] = []
    control_runs: list[dict[str, Any]] = []
    for d in run_dirs:
        if not (d.name.startswith("run-") or d.name.startswith("ctrl-")):
            continue
        rec = load_run(d)
        if d.name.startswith("ctrl-") or rec["skip_network_wait"] == 1:
            control_runs.append(rec)
        else:
            baseline_runs.append(rec)

    if len(baseline_runs) < 5:
        raise SystemExit(f"Expected >= 5 baseline runs, found {len(baseline_runs)}")

    stats = {
        "wall_ms_per_day_raw": summarize_metric([r["wall_ms_per_day"] for r in baseline_runs]),
        "active_wall_ms_per_day": summarize_metric([r["active_wall_ms_per_day"] for r in baseline_runs]),
        "per_day_median_ms": summarize_metric([r["per_day_median_ms"] for r in baseline_runs]),
        "sample_profiler_ms_per_day": summarize_metric(
            [r["tsv_header"]["ms_per_day_sampled"] for r in baseline_runs]
        ),
    }

    # Evaluate P0 gate (< ~2% dispersion)
    active_cv = stats["active_wall_ms_per_day"]["cv_pct"]
    active_iqr_pct = stats["active_wall_ms_per_day"]["iqr_pct_of_median"]
    median_day_cv = stats["per_day_median_ms"]["cv_pct"]
    median_day_iqr_pct = stats["per_day_median_ms"]["iqr_pct_of_median"]
    raw_cv = stats["wall_ms_per_day_raw"]["cv_pct"]
    gate = {
        "threshold_pct": 2.0,
        "active_wall_cv_pct": active_cv,
        "active_wall_iqr_pct": active_iqr_pct,
        "per_day_median_cv_pct": median_day_cv,
        "per_day_median_iqr_pct": median_day_iqr_pct,
        "raw_wall_cv_pct": raw_cv,
        "active_wall_pass": (active_cv < 2.0 and active_iqr_pct < 2.0),
        "per_day_median_pass": (median_day_cv < 2.0 and median_day_iqr_pct < 2.0),
        "raw_wall_pass": (raw_cv < 2.0),
    }

    baseline_profile = aggregate_samples(baseline_runs, starts, entries)
    control_summary = []
    base_med = stats["active_wall_ms_per_day"]["median"]
    base_day_med = stats["per_day_median_ms"]["median"]
    for cr in control_runs:
        c_prof = aggregate_samples([cr], starts, entries)
        c_clean = {k: v for k, v in cr.items() if k != "_tsv"}
        c_clean["delta_active_wall_ms_per_day_vs_baseline_median"] = round(
            cr["active_wall_ms_per_day"] - base_med, 3
        )
        c_clean["delta_active_wall_pct"] = round(
            ((cr["active_wall_ms_per_day"] - base_med) / base_med * 100.0) if base_med else 0.0, 2
        )
        c_clean["delta_per_day_median_ms_vs_baseline_median"] = round(
            cr["per_day_median_ms"] - base_day_med, 3
        )
        c_clean["sample_profiler_summary"] = c_prof
        control_summary.append(c_clean)

    out = {
        "schema_version": "p0-baseline-v1",
        "target_binary": {
            "path": "base-game/v2game.exe",
            "sha256": "62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648",
            "preferred_base": "0x00400000",
        },
        "save": {
            "name": "input-autosave.v2",
            "scenario": "SPA 1837.1.1",
            "sha256": "a3885cc5b64328e04b45b92c2329e5cfa7d2d931746110fb750e47475fd39e1b",
        },
        "profiler_audit_base_game": audit_base_game_tsv(),
        "baseline_runs": [{k: v for k, v in r.items() if k != "_tsv"} for r in baseline_runs],
        "baseline_statistics": stats,
        "p0_gate": gate,
        "baseline_sample_profiler": baseline_profile,
        "control_runs_excluded_from_baseline": control_summary,
    }

    out_path = PERF_DIR / "baseline.json"
    out_path.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {out_path}")
    print("P0 Gate:", json.dumps(gate, indent=2))
    print("Active wall stats:", json.dumps(stats["active_wall_ms_per_day"], indent=2))
    print("Per-day median stats:", json.dumps(stats["per_day_median_ms"], indent=2))


if __name__ == "__main__":
    main()
