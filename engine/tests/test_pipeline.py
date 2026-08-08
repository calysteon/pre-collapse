"""The whole loop, offline: signature -> match -> patch -> oracle. The signature-selected
patch must be confirmed by the oracle for every recipient, including the renamed and
refactored variants (the modification-survival claim)."""

import sys
from pathlib import Path

import pytest

ENGINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ENGINE))

from precollapse import corpus, pipeline  # noqa: E402
from precollapse.database import SignaturePatchDB  # noqa: E402
from precollapse.signature import FixtureBackend  # noqa: E402

DB = SignaturePatchDB.load(ENGINE / "db" / "signature_patch_db.json")
BACKEND = FixtureBackend(ENGINE / "signatures" / "corpus_signatures.json")
RECIPIENTS = corpus.iter_recipients()
VARIANTS = [r for r in RECIPIENTS if r.kind == "variant"]


@pytest.mark.parametrize("r", RECIPIENTS, ids=[r.id for r in RECIPIENTS])
def test_loop_verifies(r):
    res = pipeline.run(r.source, BACKEND, DB, poc_path=r.poc_path)
    assert res.patch_applied, f"{r.id}: no patch applied"
    assert res.verified is True, f"{r.id}: {res.summary_line()}"


def test_detection_and_patch_selection_are_one_operation():
    """The match object carries both the class and the patch -- no second lookup."""
    r = RECIPIENTS[0]
    res = pipeline.run(r.source, BACKEND, DB, poc_path=None)
    assert res.match.class_id and res.match.patch_class
    assert res.verified is None  # detection-only when no PoC is supplied


@pytest.mark.parametrize("r", VARIANTS, ids=[r.id for r in VARIANTS])
def test_modified_clone_still_gets_the_right_patch(r):
    """Renamed/refactored clones share no identifiers with the canonical member yet must
    still route to the same class patch and verify -- the property syntax matching lacks."""
    res = pipeline.run(r.source, BACKEND, DB, poc_path=r.poc_path)
    assert res.verified is True, f"{r.id}: {res.summary_line()}"
