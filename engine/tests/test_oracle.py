"""The oracle is the ground truth, so it gets tested first: it must call the vulnerable
program VULNERABLE and a genuinely-fixed program SAFE, and it must reject a fake patch."""

import sys
from pathlib import Path

import pytest

ENGINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ENGINE))

from precollapse import corpus, oracle, patch  # noqa: E402
from precollapse.oracle import Verdict  # noqa: E402

RECIPIENTS = corpus.iter_recipients()


@pytest.mark.parametrize("r", RECIPIENTS, ids=[r.id for r in RECIPIENTS])
def test_vuln_is_vulnerable(r):
    res = oracle.run(r.src_path, r.poc_path)
    assert res.verdict is Verdict.VULNERABLE, f"{r.id}: {res.detail}"
    assert res.asan_error, "expected a sanitizer error class"


@pytest.mark.parametrize("r", RECIPIENTS, ids=[r.id for r in RECIPIENTS])
def test_patch_makes_it_safe(r, tmp_path):
    patched = patch.get(r.patch_class).apply(r.source)
    assert patched is not None, f"{r.id}: donor patch did not apply"
    ps = tmp_path / "patched.c"
    ps.write_text(patched)
    res = oracle.run(ps, r.poc_path)
    assert res.verdict is Verdict.SAFE, f"{r.id}: after patch -> {res.verdict} ({res.detail})"


def test_no_op_patch_is_rejected(tmp_path):
    """A patch that changes nothing must not be accepted as a fix."""
    r = RECIPIENTS[0]
    ps = tmp_path / "notpatched.c"
    ps.write_text(r.source)  # unchanged source
    ok, before, after = oracle.confirms_fix(r.src_path, ps, r.poc_path)
    assert before.verdict is Verdict.VULNERABLE
    assert after.verdict is Verdict.VULNERABLE
    assert ok is False
