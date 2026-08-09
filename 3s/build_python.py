#!/usr/bin/env python3
"""Build the Python 3S database and measure its internal separation.

Signatures are per-language (Python -> JavaScript cross-matching is low, as expected, since
the model represents os.system and child_process.exec differently). So 3S carries a
per-language database, the way YARA carries per-format rules. This builds the Python
centroids and reports Python-internal leave-one-out separation, comparable to the 91% the
JavaScript families reach.
"""
from __future__ import annotations
import sys, json, hashlib
from pathlib import Path
import numpy as np
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "engine"))
sys.path.insert(0, str(ROOT))
from precollapse.signature import ModelBackend, cosine  # noqa: E402
import policy  # noqa: E402
from cross_language import PY  # reuse the Python examples

CWE = {"command_injection":"CWE-78","code_injection_eval":"CWE-95","path_traversal":"CWE-22",
 "unsafe_deserialization":"CWE-502","server_side_request_forgery":"CWE-918","weak_crypto":"CWE-327",
 "hardcoded_secret":"CWE-798","data_exfiltration":"CWE-200","install_exec":"CWE-829"}

def key(code): return hashlib.sha256("\n".join(l.rstrip() for l in code.strip().splitlines()).encode()).hexdigest()[:16]

def main():
    mb = ModelBackend("microsoft/phi-1_5", device="cpu")
    fam_dir = ROOT / "families_python"
    sigs, labels, entries = [], [], []
    for fam, variants in PY.items():
        d = fam_dir / fam; d.mkdir(parents=True, exist_ok=True)
        for old in d.glob("example_*.py"): old.unlink()
        vecs, hashes = [], []
        for i, code in enumerate(variants, 1):
            (d / f"example_{i}.py").write_text(code + "\n")
            v = mb.encode(code); vecs.append(v); sigs.append(v); labels.append(fam); hashes.append(key(code))
        c = np.mean(vecs, axis=0); c = c/(np.linalg.norm(c)+1e-9)
        level, note = policy.severity(fam)
        entries.append({"family": fam, "cwe": CWE[fam],
                        "action": {"kind": level, "note": note}, "members": hashes,
                        "centroid": [round(float(x),6) for x in c]})
    fams = sorted(set(labels)); correct = 0; per = {f:[0,0] for f in fams}
    for i in range(len(sigs)):
        cent = {}
        for f in fams:
            vs = [sigs[j] for j in range(len(sigs)) if labels[j]==f and j!=i]
            m = np.mean(vs,axis=0); cent[f] = m/(np.linalg.norm(m)+1e-9)
        pred = max(cent, key=lambda f: cosine(sigs[i], cent[f]))
        ok = pred==labels[i]; correct += ok; per[labels[i]][0]+=ok; per[labels[i]][1]+=1
    print(f"Python-internal leave-one-out: {correct}/{len(sigs)} = {correct/len(sigs):.1%}")
    for f in fams: print(f"  {f:32s} {per[f][0]}/{per[f][1]}")
    db = {"spec_version":"0.1","language":"python",
          "model":{"name":"microsoft/phi-1_5","dtype":"float32","pooling":"mean","layer_band":"deep-0.5","dim":int(sigs[0].shape[0])},
          "families": sorted(entries, key=lambda e: e["family"])}
    (ROOT/"database_python.json").write_text(json.dumps(db, indent=1))
    print(f"wrote {len(entries)} python families -> 3s/database_python.json")

if __name__ == "__main__":
    main()
