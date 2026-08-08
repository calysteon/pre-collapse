"""Enumerate the corpus: each class directory holds a canonical vuln.c plus renamed and
refactored variants under variants/. Every one is a real, compilable recipient that the
oracle can run; the variants exist to show the signature and its donor patch survive the
syntactic changes (renaming, refactoring) that defeat token/CFG matching.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

CORPUS_ROOT = Path(__file__).resolve().parent.parent / "corpus"


@dataclasses.dataclass(frozen=True)
class Recipient:
    id: str            # e.g. "cwe121_stack_overflow" or "cwe121_stack_overflow/renamed_login"
    class_id: str      # e.g. "stack_buffer_overflow"
    cwe: str
    patch_class: str
    src_path: Path
    poc_path: Path
    kind: str          # "canonical" | "variant"

    @property
    def source(self) -> str:
        return self.src_path.read_text()


def _load_meta(class_dir: Path) -> dict:
    return json.loads((class_dir / "meta.json").read_text())


def iter_recipients(root: Path | str = CORPUS_ROOT) -> list[Recipient]:
    root = Path(root)
    out: list[Recipient] = []
    for class_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        meta_file = class_dir / "meta.json"
        if not meta_file.exists():
            continue
        meta = _load_meta(class_dir)
        poc = class_dir / meta["poc"]
        out.append(Recipient(
            id=meta["id"], class_id=meta["class_id"], cwe=meta["cwe"],
            patch_class=meta["patch_class"], src_path=class_dir / "vuln.c",
            poc_path=poc, kind="canonical",
        ))
        vdir = class_dir / "variants"
        if vdir.is_dir():
            for v in sorted(vdir.glob("*.c")):
                out.append(Recipient(
                    id=f"{meta['id']}/{v.stem}", class_id=meta["class_id"], cwe=meta["cwe"],
                    patch_class=meta["patch_class"], src_path=v, poc_path=poc, kind="variant",
                ))
    return out


def by_class(root: Path | str = CORPUS_ROOT) -> dict[str, list[Recipient]]:
    groups: dict[str, list[Recipient]] = {}
    for r in iter_recipients(root):
        groups.setdefault(r.class_id, []).append(r)
    return groups
