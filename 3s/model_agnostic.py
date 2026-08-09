#!/usr/bin/env python3
"""Reproduce family separation under a second model, to show the signal is not a quirk.

3S signatures are model-relative by construction (a signature is written 3S:<model>/...),
but the *claim* is that the behavioral structure the model exposes is real, not an artifact
of one particular network. If a second model from a different lineage separates the same
families, that claim holds; if only phi-1_5 does, the result is weaker and we should say so.

    python 3s/model_agnostic.py --model Qwen/Qwen2.5-Coder-0.5B

Signs the JavaScript family corpus (build_families.FAMILIES) under the given model and reports
leave-one-out family separation, directly comparable to the 91.0% phi-1_5 reaches.
"""
from __future__ import annotations
import sys, argparse
from pathlib import Path
import numpy as np

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "engine"))
sys.path.insert(0, str(ROOT))
from precollapse.signature import ModelBackend, cosine  # noqa: E402
from build_families import FAMILIES  # noqa: E402


def separation(sigs, labels):
    fams = sorted(set(labels))
    correct = 0
    per = {f: [0, 0] for f in fams}
    for i in range(len(sigs)):
        cent = {}
        for f in fams:
            vs = [sigs[j] for j in range(len(sigs)) if labels[j] == f and j != i]
            m = np.mean(vs, axis=0)
            cent[f] = m / (np.linalg.norm(m) + 1e-9)
        pred = max(cent, key=lambda f: cosine(sigs[i], cent[f]))
        ok = pred == labels[i]
        correct += ok
        per[labels[i]][0] += ok
        per[labels[i]][1] += 1
    return correct, len(sigs), per


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="Qwen/Qwen2.5-Coder-0.5B")
    a = ap.parse_args()

    print(f"signing {sum(len(v[2]) for v in FAMILIES.values())} examples under {a.model} ...",
          flush=True)
    mb = ModelBackend(a.model, device="cpu")
    sigs, labels = [], []
    for fam, (_cwe, _desc, variants) in FAMILIES.items():
        for code in variants:
            sigs.append(mb.encode(code))
            labels.append(fam)
        print(f"  signed {fam}", flush=True)

    c, n, per = separation(sigs, labels)
    print(f"\n{a.model}")
    print(f"leave-one-out family separation: {c}/{n} = {c/n:.1%}")
    for f in sorted(per):
        ok, tot = per[f]
        print(f"  {f:32s} {ok}/{tot}")


if __name__ == "__main__":
    main()
