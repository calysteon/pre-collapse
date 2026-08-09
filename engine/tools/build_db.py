#!/usr/bin/env python3
"""Build the (signature -> patch) database from computed corpus signatures.

    python tools/build_db.py \
        --signatures signatures/corpus_signatures.json \
        --out db/signature_patch_db.json

Class metadata (CWE, patch class, description) is taken from the corpus meta.json files
and the patch registry, so the DB stays consistent with what the oracle actually runs.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ENGINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ENGINE))

from precollapse import corpus, patch  # noqa: E402
from precollapse.database import SignaturePatchDB  # noqa: E402


def class_metadata() -> dict[str, dict]:
    meta: dict[str, dict] = {}
    for r in corpus.iter_recipients():
        if r.class_id in meta:
            continue
        meta[r.class_id] = {
            "cwe": r.cwe,
            "patch_class": r.patch_class,
            "description": patch.get(r.patch_class).summary,
        }
    return meta


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--signatures", default=str(ENGINE / "signatures" / "corpus_signatures.json"))
    ap.add_argument("--out", default=str(ENGINE / "db" / "signature_patch_db.json"))
    a = ap.parse_args()

    blob = json.loads(Path(a.signatures).read_text())
    members = [
        {"id": e["id"], "class_id": e["class_id"], "signature": e["signature"]}
        for e in blob["signatures"]
    ]
    db = SignaturePatchDB.build(blob["model_name"], members, class_metadata())
    db.save(a.out)
    print(f"[db] built {len(db.entries)} class entries from {len(members)} members "
          f"({blob['model_name']}, dim {db.to_json()['dim']}) -> {a.out}")
    for e in db.entries:
        print(f"  {e.cwe:8s} {e.class_id:22s} patch={e.patch_class:22s} "
              f"members={len(e.members)}")


if __name__ == "__main__":
    main()
