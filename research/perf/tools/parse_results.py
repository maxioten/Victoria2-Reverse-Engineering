#!/usr/bin/env python3
"""Aggregate benchmark runs and compare a baseline against an experiment."""
import argparse
import csv
import json
import math
import statistics
import sys
from collections import defaultdict
from pathlib import Path


def percentile(sorted_values, p):
    if not sorted_values:
        return float("nan")
    if len(sorted_values) == 1:
        return float(sorted_values[0])
    pos = (len(sorted_values) - 1) * p / 100.0
    lo = int(pos)
    hi = min(lo + 1, len(sorted_values) - 1)
    frac = pos - lo
    return sorted_values[lo] * (1.0 - frac) + sorted_values[hi] * frac


def wall_ms_per_day(record):
    """Return wall ms/day from either the manual timer or a screen runner.

    The manual timer writes ``wall_ms_per_day``.  The automated Xvfb runner
    writes ``ms_per_day`` (or ``wall_s`` plus ``days``).  Accept all three so
    both sources can be aggregated in one file.
    """
    if "wall_ms_per_day" in record:
        return float(record["wall_ms_per_day"])
    if "ms_per_day" in record:
        return float(record["ms_per_day"])
    if "wall_s" in record and "days" in record:
        return float(record["wall_s"]) * 1000.0 / float(record["days"])
    raise ValueError(f"run has no wall-time field: {sorted(record)}")


def fmt(value, digits=2):
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return "n/a"
    return f"{value:.{digits}f}"


def load_runs(path):
    text = Path(path).read_text().strip()
    if not text:
        return []
    if text.startswith("["):
        return json.loads(text)
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def summarize(records):
    groups = defaultdict(list)
    for r in records:
        groups[r["label"]].append(r)
    out = {}
    for label, runs in sorted(groups.items()):
        wall = sorted(wall_ms_per_day(r) for r in runs)
        cpu = sorted(float(r["cpu_ms_per_day"]) for r in runs
                     if "cpu_ms_per_day" in r)
        rss = sorted(float(r["max_rss_mb"]) for r in runs
                     if "max_rss_mb" in r)
        out[label] = {
            "n": len(runs),
            "wall_median": statistics.median(wall),
            "wall_p95": percentile(wall, 95),
            "cpu_median": statistics.median(cpu) if cpu else float("nan"),
            "cpu_p95": percentile(cpu, 95),
            "rss_median": statistics.median(rss) if rss else float("nan"),
        }
    return out


def markdown(summary, baseline=None, experiment=None):
    lines = [
        "# Benchmark summary",
        "",
        "| label | n | wall ms/day median | wall p95 | CPU ms/day median | CPU p95 | RSS MB |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for label, s in summary.items():
        lines.append(
            f"| {label} | {s['n']} | {fmt(s['wall_median'])} | "
            f"{fmt(s['wall_p95'])} | {fmt(s['cpu_median'])} | "
            f"{fmt(s['cpu_p95'])} | {fmt(s['rss_median'], 1)} |"
        )
    if baseline and experiment and baseline in summary and experiment in summary:
        b, e = summary[baseline], summary[experiment]
        if b["wall_median"] and not math.isnan(b["wall_median"]) \
                and not math.isnan(e["wall_median"]):
            dw = 100.0 * (e["wall_median"] - b["wall_median"]) / b["wall_median"]
            lines += [
                "",
                f"**{experiment} vs {baseline}**",
                "",
                "| metric | delta |",
                "|---|---:|",
                f"| wall median | {dw:+.2f} % |",
            ]
        if b["cpu_median"] and not math.isnan(b["cpu_median"]) \
                and not math.isnan(e["cpu_median"]):
            dc = 100.0 * (e["cpu_median"] - b["cpu_median"]) / b["cpu_median"]
            lines.append(f"| CPU median | {dc:+.2f} % |")
    return "\n".join(lines) + "\n"


def write_csv(summary, path):
    with open(path, "w", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["label", "n", "wall_median_ms_day", "wall_p95_ms_day",
                    "cpu_median_ms_day", "cpu_p95_ms_day", "rss_median_mb"])
        for label, s in summary.items():
            w.writerow([label, s["n"], fmt(s["wall_median"], 3),
                        fmt(s["wall_p95"], 3), fmt(s["cpu_median"], 3),
                        fmt(s["cpu_p95"], 3), fmt(s["rss_median"], 3)])


def selftest():
    records = []
    for label, base in (("baseline", 200.0), ("experiment", 160.0)):
        for i in range(5):
            wall = base + i
            records.append({
                "label": label,
                "wall_ms_per_day": wall,
                "cpu_ms_per_day": wall * 0.8,
                "max_rss_mb": 900.0 + i,
            })
    summary = summarize(records)
    assert summary["baseline"]["n"] == 5
    assert summary["baseline"]["wall_median"] == 202.0
    assert summary["experiment"]["wall_median"] == 162.0
    text = markdown(summary, "baseline", "experiment")
    assert "-19.80 %" in text or "-19.8" in text

    # Screen-runner records use ms_per_day or wall_s+days and omit CPU/RSS.
    records.append({"label": "screen", "ms_per_day": 321.5})
    records.append({"label": "screen", "wall_s": 9.0, "days": 30})
    summary = summarize(records)
    assert summary["screen"]["n"] == 2
    assert abs(summary["screen"]["wall_median"] - 310.75) < 1e-9
    assert math.isnan(summary["screen"]["cpu_median"])
    assert "n/a" in markdown(summary)
    print("selftest ok")
    print(text)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input", help="JSONL or JSON list of runs")
    ap.add_argument("--baseline", default=None)
    ap.add_argument("--experiment", default=None)
    ap.add_argument("--csv", default=None, help="optional CSV output")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        selftest()
        return 0
    if not args.input:
        ap.error("--input is required unless --selftest is used")
    records = load_runs(args.input)
    if not records:
        print("no runs found", file=sys.stderr)
        return 1
    summary = summarize(records)
    print(markdown(summary, args.baseline, args.experiment))
    if args.csv:
        write_csv(summary, args.csv)
        print(f"wrote {args.csv}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
