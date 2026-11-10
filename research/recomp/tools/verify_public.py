#!/usr/bin/env python3
"""Validate the public metadata package without the game binary."""
import csv
import json
import os
import re
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
checks = []


def chk(name, cond, detail=""):
    checks.append(bool(cond))
    print(("PASS" if cond else "FAIL"), name, detail)


summary = json.load(open(BASE / "catalog" / "summary.json"))
chk("functions == 99740", summary["coverage"]["functions"] == 99740,
    summary["coverage"]["functions"])
chk("coverage == 95.3", summary["coverage"]["coverage_pct"] == 95.3,
    summary["coverage"]["coverage_pct"])
chk("hard errors == 0", summary["lift"]["error_lifting"] == 0,
    summary["lift"]["error_lifting"])

with open(BASE / "catalog" / "functions.csv", newline="") as f:
    rows = list(csv.DictReader(f))
chk("functions.csv rows == 99740", len(rows) == 99740, len(rows))
chk("functions.csv columns",
    list(rows[0]) == ["address", "size", "entry_kind", "blocks", "instructions",
                      "is_thunk", "calls"], list(rows[0]))

for name, expected in (("difftest_results.json", 120),
                       ("difftest_nonleaf_results.json", 15),
                       ("difftest_imports_results.json", 30)):
    data = json.load(open(BASE / "analysis" / name))
    chk(f"{name} cases == {expected}", len(data) == expected, len(data))
    chk(f"{name} all ok", all(x["status"] == "ok" for x in data),
        sum(1 for x in data if x["status"] == "ok"))

review = json.load(open(BASE / "analysis" / "unimplemented_review.json"))
chk("unimplemented definitions == 13", len(review) == 13, len(review))
chk("data-like == 9", sum(1 for x in review if x["verdict"].startswith("data-like")) == 9,
    sum(1 for x in review if x["verdict"].startswith("data-like")))
chk("pause benign == 4", sum(1 for x in review if "pause benign" in x["verdict"]) == 4,
    sum(1 for x in review if "pause benign" in x["verdict"]))

bad_ext = []
bad_paths = []
for p in BASE.rglob("*"):
    if not p.is_file():
        continue
    if p.suffix.lower() in (".exe", ".dll", ".o", ".obj", ".pdb", ".lib"):
        bad_ext.append(str(p.relative_to(BASE)))
    if p.stat().st_size > 5_000_000:
        bad_ext.append(f"large:{p.relative_to(BASE)}")
    if p.name == "verify_public.py":
        continue
    if p.suffix.lower() in (".md", ".json", ".csv", ".py", ".sh"):
        text = p.read_text(errors="replace")
        if re.search(r"/tmp/|/home/", text):
            bad_paths.append(str(p.relative_to(BASE)))

chk("no binaries or files >5MB", not bad_ext, bad_ext)
chk("no local absolute paths", not bad_paths, bad_paths)

print(f"\nSUMMARY {sum(checks)}/{len(checks)} checks passed")
sys.exit(0 if all(checks) else 1)
