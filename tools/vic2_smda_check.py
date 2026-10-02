"""Independent cross-check of docs/ai/bodies/*.json against SMDA recursive disassembly.

Usage: python3 tools/vic2_smda_check.py  (requires: pip install smda)

For each inventoried function compares:
  - entry: SMDA must have a function starting exactly at the claimed VA.
  - end: SMDA coverage end vs claimed end (flags earlier/larger).
  - calls: claimed direct-call targets must appear in SMDA outrefs
    (missing ones are triaged separately: real E8 in range = SMDA gap).

Writes /tmp/opencode/smda_diff.json. Exit 0 always; interpret JSON.
"""
import json
import sys


def main() -> int:
    from smda.Disassembler import Disassembler

    d = Disassembler()
    rep = d.disassembleFile("binaries/vanilla/v2game.exe")
    by_off = {f.offset: f for f in rep.getFunctions()}
    out = []
    for region in ["army", "diplomacy", "king_peace", "ministers"]:
        items = json.load(open(f"docs/ai/bodies/bodies_{region}.json"))
        for it in items:
            va = int(it["va"], 16)
            end = int(it["end"], 16)
            rec = {"va": it["va"], "region": region}
            fn = by_off.get(va)
            if fn is None:
                rec["smda"] = "missing"
                rec["issues"] = ["no-smda-function-at-entry"]
            else:
                ins = list(fn.getInstructions())
                cov = max(i.offset + len(i.bytes) for i in ins)
                try:
                    outs = {x.to_instruction.offset for x in fn.getCodeOutrefs()}
                except Exception:
                    outs = set()
                issues = []
                if cov < end:
                    issues.append(f"smda-ends-earlier@{hex(cov)}-vs-claimed@{it['end']}")
                if cov > end + 0x400:
                    issues.append(f"smda-much-larger@{hex(cov)}")
                missing = sorted(
                    hex(c) for c in (int(c, 16) for c in it.get("calls", []))
                    if c not in outs and 0x401000 <= c < 0x489120
                )
                if missing:
                    issues.append(f"calls-not-in-smda:{missing[:10]}")
                rec["smda"] = "exact"
                rec["smda_end"] = hex(cov)
                rec["issues"] = issues
            out.append(rec)
    json.dump(out, open("/tmp/opencode/smda_diff.json", "w"), indent=1)
    n = sum(1 for r in out if r["issues"])
    print(f"{len(out)} checked, {n} with issues")
    return 0


if __name__ == "__main__":
    sys.exit(main())
