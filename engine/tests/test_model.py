"""Real-model path. Skipped unless torch + transformers are installed and a model is
available (set PRECOLLAPSE_TEST_MODEL). Not run in CI; run it where weights live."""

import os
import sys
from pathlib import Path

import pytest

ENGINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ENGINE))

torch = pytest.importorskip("torch")
pytest.importorskip("transformers")

MODEL = os.environ.get("PRECOLLAPSE_TEST_MODEL")
pytestmark = pytest.mark.skipif(not MODEL, reason="set PRECOLLAPSE_TEST_MODEL to run")


def test_model_signature_matches_committed_class():
    from precollapse import corpus
    from precollapse.database import SignaturePatchDB
    from precollapse.signature import ModelBackend

    db = SignaturePatchDB.load(ENGINE / "db" / "signature_patch_db.json")
    backend = ModelBackend(MODEL)
    # A novel snippet the fixtures do not contain: renamed stack-overflow idiom.
    novel = ('#include <string.h>\n'
             'static int f(const char *q){ char slot[20]; strcpy(slot, q); return 0; }\n')
    v = backend.encode(novel)
    m = db.match(v)
    assert m.class_id == "stack_buffer_overflow", m.ranking
