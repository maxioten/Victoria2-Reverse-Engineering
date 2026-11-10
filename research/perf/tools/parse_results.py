#!/usr/bin/env python3
"""Aggregate benchmark runs and compare a baseline against an experiment."""
import argparse
import csv
import json
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
        wall = sorted(float(r.get("wall_ms_per_day", 0)) for r in runs)
        cpu = sorted(float(r.get("cpu_ms_per_day", 0)) for r in runs)
        rss = sorted(float(r.get("max_rss_mb", 0)) for r in runs)
        out[label] = {
            "n": len(runs),
            "wall_median": statistics.median(wall),
            "wall_p95": percentile(wall, 95),
            "cpu_median": statistics.median(cpu),
            "cpu_p95": percentile(cpu, 95),
            "rss_median": statistics.median(rss),
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
            f"| {label} | {s['n']} | {s['wall_median']:.2f} | {s['wall_p95']:.2f} | "
            f"{s['cpu_median']:.2f} | {s['cpu_p95']:.2f} | {s['rss_median']:.1f} |"
        )
    if baseline and experiment and baseline in summary and experiment in summary:
        b, e = summary[baseline], summary[experiment]
        dw = 100.0 * (e["wall_median"] - b["wall_median"]) / b["wall_median"] if b["wall_median"] else 0
        dc = 100.0 * (e["cpu_median"] - b["cpu_median"]) / b["cpu_median"] if b["cpu_median"] else 0
        lines += [
            "",
            f"**{experiment} vs {baseline}**",
            "",
            "| metric | delta |",
            "|---|---:|",
            f"| wall median | {dw:+.2f} % |",
            f"| CPU median | {dc:+.2f} % |",
        ]
    return "\n".join(lines) + "\n"


def write_csv(summary, path):
    with open(path, "w", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["label", "n", "wall_median_ms_day", "wall_p95_ms_day",
                    "cpu_median_ms_day", "cpu_p95_ms_day", "rss_median_mb"])
        for label, s in summary.items():
            w.writerow([label, s["n"], f"{s['wall_median']:.3f}", f"{s['wall_p95']:.3f}",
                        f"{s['cpu_median']:.3f}", f"{s['cpu_p95']:.3f}",
                        f"{s['rss_median']:.3f}"])


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
