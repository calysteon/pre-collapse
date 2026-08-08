"""The database side: committed signatures load, class centroids separate, and held-out
(leave-one-out) detection clears a floor well above chance. Runs offline from fixtures."""

import json
import sys
from pathlib import Path

import numpy as np
import pytest

ENGINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ENGINE))

from precollapse.database import SignaturePatchDB  # noqa: E402
from precollapse.signature import FixtureBackend, cosine  # noqa: E402

SIG_PATH = ENGINE / "signatures" / "corpus_signatures.json"
DB_PATH = ENGINE / "db" / "signature_patch_db.json"
SIGS = json.loads(SIG_PATH.read_text())["signatures"]
CLASSES = sorted({e["class_id"] for e in SIGS})


def _loo_predict(i):
    q = np.asarray(SIGS[i]["signature"], dtype=np.float64)
    best, best_s = None, -2.0
    for c in CLASSES:
        vecs = [np.asarray(e["signature"], dtype=np.float64)
                for j, e in enumerate(SIGS) if e["class_id"] == c and j != i]
        if not vecs:
            continue
        m = np.mean(vecs, axis=0)
        s = cosine(q, m)
        if s > best_s:
            best, best_s = c, s
    return best


def test_db_loads_and_covers_all_classes():
    db = SignaturePatchDB.load(DB_PATH)
    assert {e.class_id for e in db.entries} == set(CLASSES)
    for e in db.entries:
        assert e.centroid.shape[0] == db.to_json()["dim"]
        assert abs(np.linalg.norm(e.centroid) - 1.0) < 1e-6  # centroids are normalized


def test_each_member_matches_its_own_class_in_full_db():
    """With the full DB (member present in its centroid), every member matches its class."""
    db = SignaturePatchDB.load(DB_PATH)
    for e in SIGS:
        m = db.match(np.asarray(e["signature"], dtype=np.float64))
        assert m.class_id == e["class_id"], f"{e['id']} matched {m.class_id}"
        assert m.patch_class  # a patch is always selected alongside detection


def test_held_out_detection_beats_floor():
    """Leave-one-out accuracy must clear a floor far above 4-way chance (25%)."""
    correct = sum(_loo_predict(i) == SIGS[i]["class_id"] for i in range(len(SIGS)))
    acc = correct / len(SIGS)
    assert acc >= 0.7, f"held-out detection accuracy {acc:.1%} below floor"


def test_fixture_backend_serves_and_refuses():
    backend = FixtureBackend(SIG_PATH)
    from precollapse import corpus
    r = corpus.iter_recipients()[0]
    v = backend.encode(r.source)          # known corpus code -> served
    assert v.shape[0] == json.loads(SIG_PATH.read_text())["dim"]
    with pytest.raises(KeyError):          # novel code -> honest refusal (needs a model)
        backend.encode("int main(void){ return 0; }")
