# pre-collapse/engine — the (signature → patch) loop, made runnable

The [paper](../README.md) argues the unit of security knowledge should be
**(activation signature, patch)** instead of **(pattern, label)**: when a small model
reads code it forms a representation of the code's latent vulnerability *class*, that
representation is a usable index, and the matching database entry already carries the patch
for the class — so **detection and patch selection become one operation**.

This directory is that claim as working code, on a small corpus, closing the whole loop:

```
   source code
      │
      ▼   read the model's activations (microsoft/phi-1_5)
   pre-collapse SIGNATURE  ──────────────  signature.py
      │
      ▼   nearest class centroid — this lookup ALSO returns the patch
   (class, patch)  ────────────────────── database.py
      │
      ▼   apply the class's donor patch
   patched source  ────────────────────── patch.py
      │
      ▼   compile under AddressSanitizer, run the SAME PoC
   VULNERABLE → SAFE  ??  ──────────────── oracle.py   ← ground truth
```

The oracle is what keeps this honest: nothing is called *fixed* until the exact input that
crashed the original runs clean against the patched program.

## What it does, in one command

```bash
pip install -r requirements.txt          # numpy + pytest; plus gcc/clang for the oracle
python scripts/demo.py                    # offline: committed signatures + DB, real ASan runs
```

Example (integer-overflow class, verbatim output):

```
### cwe190_int_overflow/renamed_table  (variant, ground-truth CWE-190)
  signature -> match : integer_overflow  (cosine 0.992, margin 0.028)
  ranking            : integer_overflow:0.992, heap_buffer_overflow:0.964, ...
  selected patch     : checked_alloc_multiply -- Route size = a*b through calloc's checked multiply.
  oracle before      : VULNERABLE (heap-buffer-overflow)
  oracle after patch : SAFE
  RESULT             : VERIFIED FIX
```

`renamed_table.c` shares no identifiers with the canonical `vuln.c` of its class, yet its
signature lands on the same centroid and the same patch fixes it — the modification-survival
property the paper claims, and the one that syntactic matchers lack.

To sign code with the model live instead of serving fixtures:

```bash
pip install torch --index-url https://download.pytorch.org/whl/cpu && pip install transformers
python scripts/demo.py --model microsoft/phi-1_5
```

## The corpus

Four memory-safety classes, chosen because AddressSanitizer is an unambiguous oracle for
them. Each has a canonical `vuln.c` plus a renamed and a refactored variant (12 recipients
total). Every recipient is a real, compilable program that ASan aborts on its PoC.

| Class | CWE | Donor patch | ASan verdict |
|---|---|---|---|
| `stack_buffer_overflow` | CWE-121 | `bounded_string_copy` — unbounded copy → `snprintf(dst, sizeof dst, …)` | stack-buffer-overflow |
| `heap_buffer_overflow` | CWE-122 | `clamp_heap_copy` — clamp `memcpy` length to the allocation | heap-buffer-overflow |
| `integer_overflow` | CWE-190 | `checked_alloc_multiply` — `malloc(a*b)` → `calloc(a,b)` (checked multiply) | heap-buffer-overflow |
| `use_after_free` | CWE-416 | `null_after_free` — null the pointer at `free` so post-free guards take effect | heap-use-after-free |

The donor patches match on the class *idiom*, not on variable names, so they apply
unchanged to renamed clones — the same invariance the selecting signature has.

## Measured results (microsoft/phi-1_5, 1.3B, CPU)

- **End-to-end: 12/12** recipients — the signature-selected patch is confirmed by the
  oracle (VULNERABLE → SAFE on the same PoC), including all 8 renamed/refactored variants.
- **Held-out detection (leave-one-out): 10/12 (83%)** vs 25% chance. Both misses are
  heap-overflow ↔ integer-overflow, which share a heap OOB write and sit closest in
  signature space. Reproduce: `python tools/evaluate.py`.

The gap between 100% (full DB) and 83% (held-out) is the honest one: with the query removed
from its own centroid, two adjacent classes get confused at razor-thin margins. Larger or
code-specialized models, and more members per class, should widen those margins.

## Layout

```
precollapse/
  signature.py   pre-collapse signature: ModelBackend (real) + FixtureBackend (offline)
  database.py    SignaturePatchDB — centroids keyed to patches; match() = detect + select
  patch.py       per-class donor patches (idiom-matching, name-independent)
  oracle.py      compile under ASan+UBSan, run the PoC → VULNERABLE / SAFE / BROKEN
  pipeline.py    signature → match → patch → verify
  corpus.py      enumerate recipients (canonical + variants)
corpus/          the four classes, each with vuln.c, poc.bin, meta.json, variants/
signatures/      committed real signatures + MODEL_CARD.md (how they were produced)
db/              the built (signature → patch) database
tools/           compute_signatures.py · build_db.py · evaluate.py
scripts/demo.py  the full loop, printed stage by stage
tests/           pytest — oracle, matching, pipeline (offline); test_model.py (needs weights)
```

## Honest state — what is real vs. what is scoped

**Real and verified here (every run):**
- The oracle genuinely compiles and executes; VULNERABLE/SAFE come from ASan, not a label.
- The donor patches genuinely transform source; the patched programs genuinely pass ASan.
- The signatures are genuine Phi-1.5 activations (see `signatures/MODEL_CARD.md`); the
  offline tests replay them, and `--model` recomputes them live. Novel code (not in the
  fixtures) signed live matches the right class (`tests/test_model.py`).

**Deliberately scoped (the paper's frontier, not claimed as solved):**
- **Four classes, tens of examples.** A demonstration of the mechanism, not an
  ecosystem-scale database. The paper's scaling argument (a 1.3B model reading every
  function) is cited, not run.
- **Donor patches are per-class transforms on well-scoped idioms.** Generalizing patch
  *transplantation* to arbitrary real code is the CodePhage/PatchWeave problem; here the
  transforms are narrow and the oracle vets every result. Notably they are intra-procedural:
  a free split from its guarded use across functions needs interprocedural reasoning the
  regex transforms do not attempt.
- **Detection can confuse adjacent classes** (heap vs integer overflow). The signature is a
  proposal; the oracle is ground truth — a wrong class yields a patch the oracle rejects
  rather than a silent bad fix.
- **Fixtures cover the corpus only.** Signing new code needs the model (`--model`); the
  offline backend refuses unknown code rather than inventing a signature.

This mirrors the discipline in the sibling `Scuffle` project: state what closes
autonomously, and never let the model guess where a deterministic check belongs.
