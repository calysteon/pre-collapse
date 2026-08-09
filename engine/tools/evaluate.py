#!/usr/bin/env python3
"""Honest evaluation of the (signature -> patch) loop over the corpus.

Two numbers matter:

  * held-out detection accuracy -- leave-one-out: rebuild the class centroids with the
    query removed, then match. This is the only fair test of "does the signature find the
    right class", because a member trivially matches a centroid it helped define.

  * verification rate -- for each recipient, apply the patch the match selected and run
    the oracle. This is the end-to-end claim: signature picked a patch that actually works.

Runs fully offline from committed signatures + DB (no model weights needed).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

ENGINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ENGINE))

from precollapse import corpus, oracle, patch  # noqa: E402
from precollapse.database import SignaturePatchDB  # noqa: E402
from precollapse.signature import cosine  # noqa: E402


def leave_one_out(signatures: list[dict]) -> tuple[int, int, list[str]]:
    classes = sorted({e["class_id"] for e in signatures})
    correct = 0
    lines = []
    for i, q in enumerate(signatures):
        qv = np.asarray(q["signature"], dtype=np.float64)
        cent = {}
        for c in classes:
            vecs = [np.asarray(e["signature"], dtype=np.float64)
                    for j, e in enumerate(signatures) if e["class_id"] == c and j != i]
            if not vecs:
                continue
            m = np.mean(vecs, axis=0)
            n = np.linalg.norm(m)
            cent[c] = m / n if n > 0 else m
        ranked = sorted(((c, cosine(qv, v)) for c, v in cent.items()),
                        key=lambda t: t[1], reverse=True)
        pred, score = ranked[0]
        margin = score - (ranked[1][1] if len(ranked) > 1 else 0.0)
        ok = pred == q["class_id"]
        correct += ok
        lines.append(f"  [{'OK ' if ok else 'MISS'}] {q['id']:44s} -> {pred:22s} "
                     f"score={score:.3f} margin={margin:.3f}")
    return correct, len(signatures), lines


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--signatures", default=str(ENGINE / "signatures" / "corpus_signatures.json"))
    ap.add_argument("--db", default=str(ENGINE / "db" / "signature_patch_db.json"))
    a = ap.parse_args()

    blob = json.loads(Path(a.signatures).read_text())
    sigs = blob["signatures"]
    db = SignaturePatchDB.load(a.db)

    print(f"=== held-out detection (leave-one-out), model {blob['model_name']} ===")
    correct, total, lines = leave_one_out(sigs)
    print("\n".join(lines))
    print(f"\n  detection accuracy = {correct}/{total} = {correct/total:.1%}\n")

    print("=== end-to-end verification (signature-selected patch vs oracle) ===")
    key2sig = {e["key"]: e for e in sigs}
    verified = 0
    total_v = 0
    for r in corpus.iter_recipients():
        from precollapse.signature import code_key
        entry = key2sig[code_key(r.source)]
        qv = np.asarray(entry["signature"], dtype=np.float64)
        m = db.match(qv)                       # detection + patch selection (one op)
        p = patch.get(m.patch_class)
        patched = p.apply(r.source)
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            ps = Path(td) / "p.c"
            ps.write_text(patched or "")
            ok, before, after = oracle.confirms_fix(r.src_path, ps, r.poc_path)
        total_v += 1
        verified += ok
        print(f"  [{'VERIFIED' if ok else 'FAILED  '}] {r.id:44s} "
              f"match={m.class_id:22s} patch={m.patch_class}")
    print(f"\n  verification rate = {verified}/{total_v} = {verified/total_v:.1%}")


if __name__ == "__main__":
    main()
