#!/usr/bin/env python3
"""3s scan: identify the behavior of code by matching it against the 3S database.

    python 3s/scan.py file.js file.py ...          # human-readable table
    python 3s/scan.py --json file.js               # one JSON object per file
    python 3s/scan.py --fail-on block *.js *.py     # exit 1 if any file hits a block family

Picks the JavaScript or Python database by file extension, signs each file once, matches
it to the nearest behavioral family, and attaches a severity from 3s/policy.py. This
identifies *what code does*; for a calibrated malicious-versus-benign gate at a chosen
precision, use the trained probe in supply-chain/. Deobfuscate packed code first (see
supply-chain/).

Exit code is 0 when nothing meets the --fail-on threshold and 1 when something does, so
the command drops into CI and pre-commit hooks directly.
"""
from __future__ import annotations
import sys, json, argparse
from pathlib import Path
import numpy as np

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "engine"))
sys.path.insert(0, str(ROOT))
from precollapse.signature import ModelBackend, cosine  # noqa: E402
import policy  # noqa: E402


def load_db(path):
    db = json.loads(Path(path).read_text())
    return {f["family"]: (np.asarray(f["centroid"], dtype=np.float64), f.get("cwe", ""))
            for f in db["families"]}


def match(vec, cent):
    ranked = sorted(((f, cosine(vec, c)) for f, (c, _) in cent.items()),
                    key=lambda t: t[1], reverse=True)
    fam, score = ranked[0]
    margin = score - ranked[1][1] if len(ranked) > 1 else score
    return fam, score, margin


def main():
    ap = argparse.ArgumentParser(description="match code files against the 3S database")
    ap.add_argument("files", nargs="+")
    ap.add_argument("--json", action="store_true", help="emit one JSON object per file")
    ap.add_argument("--fail-on", choices=["block", "warn", "none"], default="block",
                    help="exit 1 if any file matches a family at or above this severity "
                         "(default: block)")
    ap.add_argument("--min-margin", type=float, default=0.0,
                    help="treat matches whose margin to the runner-up is below this as "
                         "inconclusive rather than a hit")
    ap.add_argument("--model", default="microsoft/phi-1_5")
    a = ap.parse_args()

    dbs = {"js": load_db(ROOT / "database.json"),
           "py": load_db(ROOT / "database_python.json")}
    mb = ModelBackend(a.model, device="cpu")

    if not a.json:
        print(f"3s scan  {a.model}  js {len(dbs['js'])} families  "
              f"py {len(dbs['py'])} families\n")

    triggered = False
    for fp in a.files:
        fp = Path(fp)
        lang = "py" if fp.suffix in (".py", ".pyw") else "js"
        cent = dbs[lang]
        vec = mb.encode(fp.read_text(errors="ignore"))
        fam, score, margin = match(vec, cent)
        cwe = cent[fam][1]
        level, note = policy.severity(fam)
        inconclusive = margin < a.min_margin
        if inconclusive:
            level = "none"
        hits = (not inconclusive) and a.fail_on != "none" \
            and policy.at_or_above(level, a.fail_on)
        triggered = triggered or hits

        if a.json:
            print(json.dumps({
                "file": str(fp), "lang": lang,
                "signature": None if inconclusive else f"3S:{mb.model_name}/{fam}",
                "family": None if inconclusive else fam,
                "cwe": None if inconclusive else cwe,
                "cosine": round(score, 4), "margin": round(margin, 4),
                "severity": level, "note": None if inconclusive else note,
                "fail": hits,
            }))
        else:
            tag = {"block": "BLOCK", "warn": "warn ", "none": "  -  "}[level]
            if inconclusive:
                print(f"  [{tag}] {fp.name:22s} [{lang}]  inconclusive "
                      f"(cos {score:.2f}, margin {margin:.2f} < {a.min_margin})")
            else:
                print(f"  [{tag}] {fp.name:22s} [{lang}]  3S:{mb.model_name}/{fam}  "
                      f"cos {score:.2f}  margin {margin:.2f}  {cwe}")
                print(f"          {note}")

    if not a.json and a.fail_on != "none":
        print(f"\n{'FAIL' if triggered else 'ok'}: "
              f"{'at least one file' if triggered else 'no file'} matched a "
              f"{a.fail_on}-severity family")
    sys.exit(1 if triggered else 0)


if __name__ == "__main__":
    main()
