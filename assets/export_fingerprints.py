#!/usr/bin/env python3
"""Export real signature data for the console: each snippet's vector and its matched
family centroid, downsampled to a fingerprint of BINS bars for display."""
from __future__ import annotations
import sys, json
from pathlib import Path
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT / "3s"))
from precollapse.signature import ModelBackend, cosine  # noqa: E402
import policy  # noqa: E402

BINS = 128
SRC = ROOT / "assets" / "playground_src"
FILES = ["wallet_hook.js", "send_env.js", "sanitize.js", "merge.js",
         "loader.py", "proxy.py", "digest.py", "postinstall.py"]
GUARD = 0.005


def load_db(path):
    db = json.loads(Path(path).read_text())
    return {f["family"]: (np.asarray(f["centroid"], float), f.get("cwe", "")) for f in db["families"]}


def downsample(vec, bins=BINS):
    v = np.asarray(vec, float)
    step = len(v) // bins
    return [round(float(v[i*step:(i+1)*step].mean()), 5) for i in range(bins)]


def main():
    dbs = {"js": load_db(ROOT/"3s"/"database.json"), "py": load_db(ROOT/"3s"/"database_python.json")}
    mb = ModelBackend("microsoft/phi-1_5", device="cpu")
    out = []
    for fn in FILES:
        fp = SRC / fn
        lang = "py" if fp.suffix in (".py", ".pyw") else "js"
        cent = dbs[lang]
        vec = mb.encode(fp.read_text())
        ranked = sorted(((f, cosine(vec, c)) for f, (c, _) in cent.items()),
                        key=lambda t: t[1], reverse=True)
        fam, score = ranked[0]
        margin = score - ranked[1][1]
        inconclusive = margin < GUARD
        level, note = policy.severity(fam)
        out.append({
            "file": fn, "lang": lang,
            "family": None if inconclusive else fam,
            "cwe": None if inconclusive else cent[fam][1],
            "cos": round(float(score), 4), "margin": round(float(margin), 4),
            "sev": "none" if inconclusive else level,
            "note": None if inconclusive else note,
            "code": fp.read_text().rstrip("\n"),
            "fp": downsample(vec),
            "famfp": downsample(cent[fam][0]),
        })
        print("signed", fn, "->", fam, round(score, 3), flush=True)
    (ROOT/"assets"/"fingerprints.json").write_text(json.dumps({"bins": BINS, "samples": out}))
    print("wrote assets/fingerprints.json")


if __name__ == "__main__":
    main()
