#!/usr/bin/env python3
"""Walk the full loop on the corpus and print it, stage by stage.

    python scripts/demo.py                 # offline: committed signatures + DB
    python scripts/demo.py --model microsoft/phi-1_5   # sign the code live with the model

With --model, signatures are computed from the model at runtime (this is the real
pre-collapse read); without it, the committed fixtures are served so the loop runs with
no weights. Either way the oracle really compiles and runs each program.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ENGINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ENGINE))

from precollapse import corpus, pipeline  # noqa: E402
from precollapse.database import SignaturePatchDB  # noqa: E402
from precollapse.signature import FixtureBackend, ModelBackend  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=None, help="HF model id; omit to use committed fixtures")
    ap.add_argument("--db", default=str(ENGINE / "db" / "signature_patch_db.json"))
    ap.add_argument("--signatures", default=str(ENGINE / "signatures" / "corpus_signatures.json"))
    ap.add_argument("--only", default=None, help="substring filter on recipient id")
    a = ap.parse_args()

    db = SignaturePatchDB.load(a.db)
    if a.model:
        print(f"[demo] signing live with {a.model}")
        backend = ModelBackend(a.model)
    else:
        backend = FixtureBackend(a.signatures)
        print(f"[demo] offline; serving committed signatures ({backend.model_name})")
    print(f"[demo] database: {len(db.entries)} classes, model {db.model_name}\n")

    recipients = corpus.iter_recipients()
    if a.only:
        recipients = [r for r in recipients if a.only in r.id]

    verified = 0
    for r in recipients:
        res = pipeline.run(r.source, backend, db, poc_path=r.poc_path)
        verified += 1 if res.verified else 0
        m = res.match
        print(f"### {r.id}  ({r.kind}, ground-truth {r.cwe})")
        print(f"  signature -> match : {m.class_id}  (cosine {m.score:.3f}, "
              f"margin {m.margin:.3f})")
        print(f"  ranking            : "
              + ", ".join(f"{c}:{s:.3f}" for c, s in m.ranking))
        print(f"  selected patch     : {m.patch_class} -- {res.patch_summary}")
        if res.before is not None:
            print(f"  oracle before      : {res.before.verdict.value} "
                  f"({res.before.asan_error})")
            print(f"  oracle after patch : {res.after.verdict.value}")
        print(f"  RESULT             : {'VERIFIED FIX' if res.verified else 'NOT VERIFIED'}\n")

    print(f"[demo] verified {verified}/{len(recipients)} recipients "
          f"(signature-selected patch confirmed by the oracle)")


if __name__ == "__main__":
    main()
