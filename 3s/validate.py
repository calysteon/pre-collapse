#!/usr/bin/env python3
"""Validate the 3S signature registry without a model.

Every contribution to the database is checked for integrity here, cheaply enough to run on
every pull request: the committed centroids and member hashes must be internally consistent
with the example corpus, every family must carry a severity, and no example may be
duplicated. What this does NOT do is recompute centroids (that needs the model); the
model-gated rebuild in .github/workflows/3s-registry.yml does that when a maintainer asks.

    python 3s/validate.py            # exits non-zero on any violation

Checks per database (JavaScript and Python):
  - shape: spec_version, model descriptor, families present; centroid dim consistent
  - each family: family/cwe/action(kind in block,warn)/members(list)/centroid(dim floats)
  - centroid is unit-norm (the format stores normalized vectors)
  - the example directory has exactly one file per declared member
  - each declared member hash equals the hash of an example file (db matches corpus)
  - every family has a severity in policy.py (a new family must declare one)
Global:
  - no example content is duplicated within or across families
"""
from __future__ import annotations
import sys, json, glob, hashlib, math
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import policy  # noqa: E402

MIN_MEMBERS = 3
NORM_TOL = 1e-3


def key(code: str) -> str:
    return hashlib.sha256(
        "\n".join(l.rstrip() for l in code.strip().splitlines()).encode()
    ).hexdigest()[:16]


def check_db(db_path: Path, corpus_dir: Path, ext: str, errors: list, seen: dict):
    label = db_path.name
    db = json.loads(db_path.read_text())
    for field in ("spec_version", "model", "families"):
        if field not in db:
            errors.append(f"{label}: missing top-level '{field}'")
            return
    dim = db["model"].get("dim")
    fams = db["families"]
    if not fams:
        errors.append(f"{label}: no families"); return

    for f in fams:
        fam = f.get("family", "<unnamed>")
        for field in ("family", "cwe", "action", "members", "centroid"):
            if field not in f:
                errors.append(f"{label}/{fam}: missing '{field}'")
        if "action" in f and f["action"].get("kind") not in ("block", "warn"):
            errors.append(f"{label}/{fam}: action.kind must be block or warn")
        if fam not in policy.SEVERITY:
            errors.append(f"{label}/{fam}: no severity in policy.py "
                          f"(a new family must declare one)")

        cent = f.get("centroid", [])
        if dim and len(cent) != dim:
            errors.append(f"{label}/{fam}: centroid dim {len(cent)} != {dim}")
        if cent:
            norm = math.sqrt(sum(x * x for x in cent))
            if abs(norm - 1.0) > NORM_TOL:
                errors.append(f"{label}/{fam}: centroid not unit-norm (|v|={norm:.4f})")

        members = f.get("members", [])
        if len(members) < MIN_MEMBERS:
            errors.append(f"{label}/{fam}: {len(members)} members, need >= {MIN_MEMBERS}")

        files = sorted(glob.glob(str(corpus_dir / fam / f"example_*{ext}")))
        if len(files) != len(members):
            errors.append(f"{label}/{fam}: {len(files)} example files but "
                          f"{len(members)} declared members")
        file_hashes = set()
        for fp in files:
            code = Path(fp).read_text()
            if not code.strip():
                errors.append(f"{label}/{fam}: empty example {Path(fp).name}")
                continue
            h = key(code)
            file_hashes.add(h)
            if h in seen:
                errors.append(f"{label}/{fam}/{Path(fp).name}: duplicate of {seen[h]}")
            else:
                seen[h] = f"{fam}/{Path(fp).name}"
        for m in members:
            if m not in file_hashes:
                errors.append(f"{label}/{fam}: declared member {m} has no matching "
                              f"example file (db out of sync with corpus)")
    return len(fams)


def main():
    errors: list[str] = []
    seen: dict[str, str] = {}
    n_js = check_db(ROOT / "database.json", ROOT / "families", ".js", errors, seen)
    n_py = check_db(ROOT / "database_python.json", ROOT / "families_python", ".py",
                    errors, seen)
    if errors:
        print(f"FAIL: {len(errors)} problem(s)")
        for e in errors:
            print("  -", e)
        sys.exit(1)
    print(f"ok: {n_js} JS families, {n_py} PY families, "
          f"{len(seen)} unique examples, databases consistent with corpus")


if __name__ == "__main__":
    main()
