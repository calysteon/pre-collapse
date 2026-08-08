"""Donor patches, keyed by vulnerability class.

In the (signature, patch) model, an entry does not carry a diff against one specific
file -- it carries the *fix for the class*, the way MVP/CodePhage/PatchWeave carry a
donor fix that is transplanted into a recipient. Each patch here is a small, reviewed
source transformation that neutralizes the class's idiom. Crucially the transforms
match on the *idiom*, not on variable names, so they apply unchanged to a renamed or
refactored clone -- the same property the thesis claims for the signature that selects
them.

These are deliberately narrow and honest: each is the canonical hardening for its
class, and its correctness is not asserted -- the oracle recompiles the result under
ASan and proves the bug is gone before anything claims success. Generalizing donor
patches to arbitrary real-world code is the CodePhage/PatchWeave frontier; what runs
here is that machinery on a controlled corpus where the transplant is well defined.
"""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Callable


@dataclasses.dataclass(frozen=True)
class Patch:
    patch_class: str
    cwe: str
    summary: str
    _apply: Callable[[str], str | None]

    def apply(self, source: str) -> str | None:
        """Return patched source, or None if the idiom isn't present (patch is a no-op)."""
        return self._apply(source)


# --- CWE-121 / stack_buffer_overflow: bound every unbounded copy into a sized buffer -------

def _bounded_string_copy(src: str) -> str | None:
    changed = False

    def sub(pattern: str, repl) -> None:
        nonlocal src, changed
        new = re.sub(pattern, repl, src)
        if new != src:
            src, changed = new, True

    # strcpy(dst, src)  ->  snprintf(dst, sizeof(dst), "%s", src)
    sub(r"\bstrcpy\s*\(\s*([A-Za-z_]\w*)\s*,\s*(.+?)\)\s*;",
        lambda m: f'snprintf({m.group(1)}, sizeof({m.group(1)}), "%s", {m.group(2)});')
    # sprintf(dst, fmt, ...)  ->  snprintf(dst, sizeof(dst), fmt, ...)
    sub(r"\bsprintf\s*\(\s*([A-Za-z_]\w*)\s*,",
        lambda m: f"snprintf({m.group(1)}, sizeof({m.group(1)}),")
    # strcat(dst, src)  ->  strncat(dst, src, sizeof(dst) - strlen(dst) - 1)
    sub(r"\bstrcat\s*\(\s*([A-Za-z_]\w*)\s*,\s*(.+?)\)\s*;",
        lambda m: (f"strncat({m.group(1)}, {m.group(2)}, "
                   f"sizeof({m.group(1)}) - strlen({m.group(1)}) - 1);"))
    # gets(dst)  ->  fgets(dst, sizeof(dst), stdin)
    sub(r"\bgets\s*\(\s*([A-Za-z_]\w*)\s*\)\s*;",
        lambda m: f"fgets({m.group(1)}, sizeof({m.group(1)}), stdin);")
    return src if changed else None


# --- CWE-122 / heap_buffer_overflow: clamp the copy to the destination allocation ----------

def _clamp_heap_copy(src: str) -> str | None:
    # Find `DST = malloc(SIZE);` then clamp any later `memcpy(DST, _, LEN)` to SIZE.
    alloc = re.search(r"\b([A-Za-z_]\w*)\s*=\s*(?:\([^)]*\)\s*)?malloc\s*\(\s*(.+?)\s*\)\s*;", src)
    if not alloc:
        return None
    dst, size_expr = alloc.group(1), alloc.group(2)
    pattern = re.compile(
        rf"\bmemcpy\s*\(\s*{re.escape(dst)}\s*,\s*(.+?)\s*,\s*(.+?)\)\s*;")

    def repl(m: re.Match) -> str:
        srcbuf, length = m.group(1), m.group(2)
        return (f"memcpy({dst}, {srcbuf}, "
                f"({length}) < ({size_expr}) ? ({length}) : ({size_expr}));")

    new = pattern.sub(repl, src)
    return new if new != src else None


# --- CWE-190 / integer_overflow: use calloc's checked multiply for the allocation ----------

def _checked_alloc_multiply(src: str) -> str | None:
    # malloc(A * B)  ->  calloc(A, B)  (calloc returns NULL if A*B overflows; the
    # recipient already checks the allocation result, so the overflowing write never
    # happens). Handles an optional cast in front of malloc.
    pattern = re.compile(
        r"\bmalloc\s*\(\s*([A-Za-z_]\w*|\([^()]*\))\s*\*\s*(.+?)\s*\)")
    new = pattern.sub(lambda m: f"calloc({m.group(1)}, {m.group(2)})", src)
    return new if new != src else None


# --- CWE-416 / use_after_free: null the pointer at free so post-free guards take effect -----

def _null_after_free(src: str) -> str | None:
    # free(p);  ->  free(p); p = NULL;
    # The recipient guards uses with `if (p)`; nulling at the free makes those guards
    # effective, turning a use-after-free into a safely-skipped no-op.
    pattern = re.compile(r"\bfree\s*\(\s*([A-Za-z_]\w*)\s*\)\s*;")

    def repl(m: re.Match) -> str:
        ptr = m.group(1)
        return f"free({ptr}); {ptr} = NULL;"

    new = pattern.sub(repl, src)
    return new if new != src else None


_REGISTRY: dict[str, Patch] = {
    p.patch_class: p
    for p in [
        Patch("bounded_string_copy", "CWE-121",
              "Replace unbounded copies (strcpy/sprintf/strcat/gets) with size-bounded forms.",
              _bounded_string_copy),
        Patch("clamp_heap_copy", "CWE-122",
              "Clamp memcpy length to the destination allocation size.",
              _clamp_heap_copy),
        Patch("checked_alloc_multiply", "CWE-190",
              "Route size = a*b through calloc's overflow-checked multiply.",
              _checked_alloc_multiply),
        Patch("null_after_free", "CWE-416",
              "Set the pointer to NULL at free so post-free guards prevent the use.",
              _null_after_free),
    ]
}


def get(patch_class: str) -> Patch:
    if patch_class not in _REGISTRY:
        raise KeyError(f"unknown patch class {patch_class!r}; known: {sorted(_REGISTRY)}")
    return _REGISTRY[patch_class]


def all_classes() -> list[str]:
    return sorted(_REGISTRY)
