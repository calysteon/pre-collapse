"""The end-to-end loop: code in, verified patch out.

    read code
      -> pre-collapse SIGNATURE            (signature.py backend)
      -> MATCH nearest class centroid       (database.py; this also selects the patch)
      -> APPLY the class's donor patch      (patch.py)
      -> VERIFY the fix under the oracle     (oracle.py; ground truth)

Steps 2 and 3 are the thesis: the same lookup that detects the class hands back the patch.
Step 4 keeps everyone honest -- nothing is called fixed until the same PoC that triggered
the bug runs clean against the patched program.
"""

from __future__ import annotations

import dataclasses
import tempfile
from pathlib import Path

from . import oracle, patch
from .database import Match, SignaturePatchDB
from .oracle import OracleResult
from .signature import SignatureBackend


@dataclasses.dataclass
class PipelineResult:
    match: Match
    patch_applied: bool
    patch_summary: str
    verified: bool | None            # None if no PoC was supplied (detection-only)
    before: OracleResult | None
    after: OracleResult | None
    patched_source: str | None

    def summary_line(self) -> str:
        v = {True: "VERIFIED", False: "NOT VERIFIED", None: "no-oracle"}[self.verified]
        return (f"{self.match.cwe}/{self.match.class_id} "
                f"(score {self.match.score:.3f}, margin {self.match.margin:.3f}) "
                f"-> patch {self.match.patch_class} [{v}]")


def run(source: str, backend: SignatureBackend, db: SignaturePatchDB,
        poc_path: str | Path | None = None, **oracle_kw) -> PipelineResult:
    # 1 + 2: signature, then the single lookup that both detects and selects the patch.
    signature = backend.encode(source)
    m = db.match(signature)

    # 3: apply the donor patch the entry points to.
    p = patch.get(m.patch_class)
    patched = p.apply(source)
    applied = patched is not None

    # 4: verify against the ground-truth oracle, if a PoC is available.
    verified: bool | None = None
    before = after = None
    if poc_path is not None and applied:
        with tempfile.TemporaryDirectory(prefix="precollapse-pipe-") as td:
            vsrc = Path(td) / "vuln.c"
            psrc = Path(td) / "patched.c"
            vsrc.write_text(source)
            psrc.write_text(patched)
            ok, before, after = oracle.confirms_fix(vsrc, psrc, poc_path, **oracle_kw)
            verified = ok
    elif poc_path is not None and not applied:
        verified = False

    return PipelineResult(
        match=m, patch_applied=applied, patch_summary=p.summary,
        verified=verified, before=before, after=after,
        patched_source=patched,
    )
