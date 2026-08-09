"""The (signature -> patch) database.

This is the whole thesis in one object. Each entry is a vulnerability class represented
by a *centroid signature* -- the mean of the pre-collapse signatures of known members of
that class -- together with the patch that fixes the class. Detection is nearest-centroid
lookup on a query signature; the entry it returns already names the patch. Detection and
patch selection are literally the same operation: one cosine argmax.

Because the key is the model's semantic signature rather than the surface form, a renamed
or refactored clone lands on the same centroid as its original -- which is what lets the
same patch reach it.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import numpy as np

from .signature import cosine


@dataclasses.dataclass
class Match:
    class_id: str
    cwe: str
    patch_class: str
    description: str
    score: float           # cosine to the chosen centroid
    margin: float          # score minus the runner-up's score (separation / confidence)
    ranking: list[tuple[str, float]]


@dataclasses.dataclass
class ClassEntry:
    class_id: str
    cwe: str
    patch_class: str
    description: str
    centroid: np.ndarray
    members: list[str]


class SignaturePatchDB:
    def __init__(self, model_name: str, entries: list[ClassEntry]):
        self.model_name = model_name
        self.entries = entries

    # -- construction ----------------------------------------------------------------
    @classmethod
    def build(cls, model_name: str, member_signatures: list[dict],
              class_meta: dict[str, dict]) -> "SignaturePatchDB":
        """member_signatures: [{id, class_id, signature(list|ndarray)}, ...]
        class_meta: {class_id: {cwe, patch_class, description}}"""
        by_class: dict[str, list[np.ndarray]] = {}
        members: dict[str, list[str]] = {}
        for m in member_signatures:
            v = np.asarray(m["signature"], dtype=np.float64)
            by_class.setdefault(m["class_id"], []).append(v)
            members.setdefault(m["class_id"], []).append(m["id"])
        entries = []
        for class_id, vecs in by_class.items():
            centroid = np.mean(vecs, axis=0)
            nrm = np.linalg.norm(centroid)
            if nrm > 0:
                centroid = centroid / nrm
            meta = class_meta[class_id]
            entries.append(ClassEntry(
                class_id=class_id, cwe=meta["cwe"], patch_class=meta["patch_class"],
                description=meta["description"], centroid=centroid,
                members=sorted(members[class_id]),
            ))
        entries.sort(key=lambda e: e.class_id)
        return cls(model_name, entries)

    # -- the core operation ----------------------------------------------------------
    def match(self, query: np.ndarray) -> Match:
        query = np.asarray(query, dtype=np.float64)
        scored = sorted(
            ((e, cosine(query, e.centroid)) for e in self.entries),
            key=lambda t: t[1], reverse=True,
        )
        best, best_score = scored[0]
        runner = scored[1][1] if len(scored) > 1 else 0.0
        return Match(
            class_id=best.class_id, cwe=best.cwe, patch_class=best.patch_class,
            description=best.description, score=best_score, margin=best_score - runner,
            ranking=[(e.class_id, s) for e, s in scored],
        )

    # -- persistence -----------------------------------------------------------------
    def to_json(self) -> dict:
        return {
            "model_name": self.model_name,
            "dim": int(self.entries[0].centroid.shape[0]) if self.entries else 0,
            "classes": [
                {
                    "class_id": e.class_id, "cwe": e.cwe, "patch_class": e.patch_class,
                    "description": e.description, "members": e.members,
                    "centroid": [round(float(x), 6) for x in e.centroid],
                }
                for e in self.entries
            ],
        }

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_json(), indent=2))

    @classmethod
    def load(cls, path: str | Path) -> "SignaturePatchDB":
        blob = json.loads(Path(path).read_text())
        entries = [
            ClassEntry(
                class_id=c["class_id"], cwe=c["cwe"], patch_class=c["patch_class"],
                description=c["description"], centroid=np.asarray(c["centroid"], dtype=np.float64),
                members=c["members"],
            )
            for c in blob["classes"]
        ]
        return cls(blob["model_name"], entries)
