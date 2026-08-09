#!/usr/bin/env python3
"""3s scan: identify the behavior of code by matching it against the 3S database.

    python 3s/scan.py file.js file.py ...

Picks the JavaScript or Python database by file extension, signs each file once, and reports
the nearest behavioral family with a cosine and a margin. This identifies *what code does*;
for a malicious-versus-benign gate at a chosen precision, use the trained probe in
supply-chain/. Deobfuscate packed code first (see supply-chain/).
"""
from __future__ import annotations
import sys, json, argparse
from pathlib import Path
import numpy as np
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "engine"))
from precollapse.signature import ModelBackend, cosine  # noqa: E402

def load_db(path):
    db = json.loads(Path(path).read_text())
    return {f["family"]: (np.asarray(f["centroid"], dtype=np.float64), f.get("cwe", "")) for f in db["families"]}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    a = ap.parse_args()
    dbs = {"js": load_db(ROOT / "database.json"), "py": load_db(ROOT / "database_python.json")}
    mb = ModelBackend("microsoft/phi-1_5", device="cpu")
    print(f"3s scan · microsoft/phi-1_5 · js {len(dbs['js'])} families · py {len(dbs['py'])} families\n")
    for fp in a.files:
        fp = Path(fp)
        lang = "py" if fp.suffix in (".py", ".pyw") else "js"
        cent = dbs[lang]
        v = mb.encode(fp.read_text(errors="ignore"))
        ranked = sorted(((f, cosine(v, c)) for f, (c, _) in cent.items()), key=lambda t: t[1], reverse=True)
        fam, score = ranked[0]
        margin = score - ranked[1][1]
        cwe = cent[fam][1]
        print(f"  {fp.name:22s} [{lang}]  →  3S:phi-1_5/{fam:26s} cos {score:.2f}  margin {margin:.2f}  {cwe}")

if __name__ == "__main__":
    main()
