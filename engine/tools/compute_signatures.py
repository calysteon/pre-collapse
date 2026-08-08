#!/usr/bin/env python3
"""Compute pre-collapse signatures for every corpus recipient with a real model.

    python tools/compute_signatures.py --model microsoft/phi-1_5 \
        --out signatures/corpus_signatures.json

This is the step that needs model weights. It writes one signature per recipient
(canonical + variants), keyed by whitespace-normalized source so the FixtureBackend can
serve them offline afterward. The committed signatures/corpus_signatures.json was produced
this way; signatures/MODEL_CARD.md records the exact model and settings.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ENGINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ENGINE))

from precollapse import corpus  # noqa: E402
from precollapse.signature import ModelBackend, code_key, save_signatures  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="microsoft/phi-1_5")
    ap.add_argument("--device", default="cpu")
    ap.add_argument("--dtype", default=None)
    ap.add_argument("--deep-fraction", type=float, default=0.5)
    ap.add_argument("--out", default=str(ENGINE / "signatures" / "corpus_signatures.json"))
    a = ap.parse_args()

    print(f"[signatures] loading {a.model} on {a.device} ...", flush=True)
    backend = ModelBackend(a.model, device=a.device, dtype=a.dtype,
                           deep_fraction=a.deep_fraction)

    recipients = corpus.iter_recipients()
    entries = []
    for r in recipients:
        src = r.source
        vec = backend.encode(src)
        entries.append({
            "key": code_key(src),
            "id": r.id,
            "class_id": r.class_id,
            "cwe": r.cwe,
            "patch_class": r.patch_class,
            "kind": r.kind,
            "signature": [round(float(x), 6) for x in vec],
        })
        print(f"  signed {r.id:44s} dim={len(vec)}", flush=True)

    save_signatures(a.out, a.model, entries)
    print(f"[signatures] wrote {len(entries)} signatures -> {a.out}")


if __name__ == "__main__":
    main()
