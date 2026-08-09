# 3S: Semantic Signature Specification

**Version 0.1 (draft proposal) · a portable format for obfuscation-invariant code signatures**

**3S** (the three S's of **S**emantic **S**ignature **S**pecification) is a shared, portable
format for code *signatures* keyed on what code **does**, not how it is written. A 3S
signature is written `3S:<model>/<family>`, and a 3S database groups families of behavior.

> This document specifies a **semantic signature**: a fixed-length vector a small model
> derives from *what code does*, together with a portable format for expressing, sharing,
> matching, and classifying such signatures. It reads a signal that surface matching cannot,
> one that survives when code is renamed, refactored, minified, or (once packing is
> deterministically resolved) obfuscated. It is designed to run alongside existing
> byte, string, AST, and taint tooling, adding a behavioral layer where those go quiet.

This is a **proposal with a working reference implementation** ([`engine/`](engine/),
[`supply-chain/`](supply-chain/)), not a finished standard. It is versioned so it can evolve.

---

## 1. Motivation

Syntactic matching has one structural failure: the attacker controls the syntax. MOVERY
measured that **91% of real vulnerable code clones differ syntactically** from their
origin, so a signature keyed on surface form misses them by construction. The same is
true of malware: renaming, control-flow flattening, and string encoding defeat byte/string
rules while leaving *behavior* intact.

A model reading code forms a representation of that behavior **before** it forms any
output, and that representation is (a) linearly decodable, (b) causal, and (c) stable
under transformations that change syntax but not meaning. A **semantic signature** is that
representation, canonicalized into a portable, comparable object. Because it tracks
behavior, it survives what defeats syntax.

**Design goals**

1. **Portable**: a signature is a serializable record, exchanged like a `.yar` file.
2. **Auto-derivable**: computed by reading code, not hand-authored per rule.
3. **Invariant**: semantically-equivalent code yields matching signatures.
4. **Composable**: signatures aggregate into *families* (a semantic taxonomy).
5. **Honest about model-relativity**: a signature is only comparable within the model
   that produced it; the model is part of the signature's identity (§4).

---

## 2. Definitions

- **Semantic signature** `σ(C; M)`: a fixed-length unit vector derived from model `M`'s
  activations while reading code file `C` (§4).
- **Family**: a set of signatures that share a behavior, represented by a **centroid**
  signature and a human label. The semantic analogue of a CWE class.
- **Signature database**: a collection of families under one model `M`.
- **Match**: assignment of a query signature to a family via a calibrated decision
  function (§6).
- **Reference marker / behavior**: the observable a family encodes (e.g. *wallet-hook
  crypto-clipper*, *credential exfiltration*, *stack buffer overflow*).

---

## 3. Conformance

An implementation is **spec-conformant** if it:

1. computes signatures per §4 and emits records per §5;
2. pins the full model descriptor (§4.1) in every record and database;
3. matches per §6, reporting a calibrated confidence and a margin;
4. never compares signatures across differing model descriptors without an explicit,
   declared re-projection.

The keywords MUST / SHOULD / MAY are used in the RFC 2119 sense.

---

## 4. Computing a signature

### 4.1 Model descriptor

A signature is meaningless without the model that produced it. Every signature and
database MUST carry a **model descriptor**:

```json
{
  "name": "microsoft/phi-1_5",
  "revision": "<git or hub revision>",
  "dtype": "float32",
  "pooling": "mean",
  "layer_band": "deep-0.5",
  "dim": 2048
}
```

### 4.2 Extraction procedure (reference)

Given code `C` and model `M`:

1. Tokenize `C` (no behavior-bearing truncation; large files are chunked, §7).
2. Forward pass with hidden states; at each layer, **mean-pool** token hidden states →
   one vector per layer, shape `(n_layers, hidden)`.
3. Reduce over a **deep layer band** (default: the last 50% of layers, dropping the final
   layer, which is pulled toward the output distribution). Deep layers are used because
   abstract-property decodability sharpens with depth while shallow layers still carry
   surface form, precisely what the signature must be invariant to.
4. **L2-normalize** → the signature `σ(C; M)`.

The reference implementation is
[`engine/precollapse/signature.py`](engine/precollapse/signature.py).

### 4.3 Obfuscation and the deterministic front-end

String-array / packing obfuscation encodes behavior behind a decoder; the raw signature
of such code is **below chance** (a measured result, the tells are drowned in decoder
noise). Conformant scanners therefore SHOULD run a **deterministic deobfuscation
front-end** before signing (the reference uses static unpacking; see
[`supply-chain/`](supply-chain/)). This preserves the division of labor the whole approach
depends on: *deterministic tools resolve the arithmetic a model is unreliable at; the
model reads the recovered behavior.*

---

## 5. Signature record format

A single signature record:

```json
{
  "spec_version": "0.1",
  "model": { "name": "microsoft/phi-1_5", "revision": "...", "dtype": "float32",
             "pooling": "mean", "layer_band": "deep-0.5", "dim": 2048 },
  "signature": [/* dim floats, L2-normalized */],
  "family": "crypto_clipper",
  "labels": { "cwe": "CWE-749", "aliases": ["wallet-hook", "eth-clipper"] },
  "provenance": { "sha256": "<hash of the signed (deobfuscated) code>",
                  "source": "npm:debug@4.4.2/src/index.js",
                  "deobfuscated": true },
  "notes": "hooks window.ethereum; overrides fetch/XMLHttpRequest to swap addresses"
}
```

`signature` MAY be transported as a base64-encoded float array for size. Records are
exchanged as JSON (one per line for streams, or arrays).

---

## 6. Matching

### 6.1 Family database

```json
{
  "spec_version": "0.1",
  "model": { /* descriptor, MUST match query's model */ },
  "families": [
    { "family": "crypto_clipper", "cwe": "CWE-749",
      "centroid": [/* dim floats */], "members": ["<sha256>", "..."],
      "action": { "kind": "block", "patch": "neutralize-web3-hooks" },
      "description": "browser wallet-transaction hijack" }
  ]
}
```

The reference format is [`engine/db/signature_patch_db.json`](engine/db/signature_patch_db.json).
Note the **`action`** field: a family entry carries not just a label but the response: 
detection and remediation are the same lookup, which is the paper's `(signature, patch)`
claim.

### 6.2 Decision function

Nearest-centroid cosine is the baseline but is **model-relative and length-sensitive**;
absolute cosine is not interpretable without a floor. Conformant matchers therefore
SHOULD use a **calibrated decision function** (a trained linear probe over signatures)
rather than raw cosine, and MUST report:

- the assigned family,
- a **calibrated confidence**,
- a **margin** to the runner-up,
- the model descriptor used.

A match across differing model descriptors is undefined and MUST be refused.

### 6.3 Invariance property (what the standard buys you)

The defining guarantee: signatures of code that differs **syntactically but not
behaviorally** (renamed, refactored, re-packed, obfuscated-then-resolved) assign to the
**same family**. This is the property no syntactic signature has, and it is what makes one
semantic signature generalize across every modified clone.

---

## 7. Large files and aggregation

A behavior may be a small region inside a large file, and mean-pooling a whole file
dilutes it. Conformant scanners SHOULD **chunk** large inputs (sliding window over tokens)
and represent a file by an aggregation that preserves the strongest region (e.g.
`[mean ‖ max]` over chunk signatures), so a payload is not averaged away. Multiple files
of one package MAY be aggregated into a single package-level signature.

---

## 8. The family taxonomy

Families are the shared vocabulary. A family is **defined by its centroid signature**, not by
prose, so it is machine-readable, auto-derivable (cluster signatures), and it **grows itself**
as new code is read. A family SHOULD carry a human label and, where one exists, a CWE
cross-reference; the CWE link is how a behavioral family and a prose weakness class point at
each other, and the signature is what 3S matches on.

**Family identifiers** are stable lowercase `snake_case` strings, addressed globally as
`3S:<model>/<family>`. The taxonomy is grouped by domain for readability only; the family
identifier is flat.

**Status.** A family is either `ref` (a reference centroid signature is computed and
present in the reference database) or `defined` (the behavior and identifier are specified
as shared vocabulary, and the centroid is open for contribution, per §10). The v0.1
reference database ships seventeen `ref` families: four native memory-safety families in
[`engine/`](engine/) and thirteen JavaScript behaviors in [`3s/`](3s/), which separate at
**91.0% leave-one-out** (eight of thirteen perfectly); see [`3s/README.md`](3s/README.md). The remaining families
fix the vocabulary so contributions and independent implementations agree on identifiers
from day one, exactly as CWE fixes weakness names before any single tool covers them all.

**Memory safety (native code)**

| family | CWE x-ref | status |
|---|---|---|
| `stack_buffer_overflow` | CWE-121 | ref |
| `heap_buffer_overflow` | CWE-122 | ref |
| `integer_overflow` | CWE-190 | ref |
| `use_after_free` | CWE-416 | ref |
| `double_free` | CWE-415 | defined |
| `out_of_bounds_read` | CWE-125 | defined |
| `null_dereference` | CWE-476 | defined |
| `format_string` | CWE-134 | defined |
| `type_confusion` | CWE-843 | defined |

**Injection and traversal**

| family | CWE x-ref | status |
|---|---|---|
| `command_injection` | CWE-78 | ref |
| `code_injection_eval` | CWE-95 | ref |
| `sql_injection` | CWE-89 | defined |
| `path_traversal` | CWE-22 | ref |
| `unsafe_deserialization` | CWE-502 | ref |
| `server_side_request_forgery` | CWE-918 | ref |
| `prototype_pollution` | CWE-1321 | ref |

**Supply-chain and malware behaviors**

| family | CWE x-ref | status |
|---|---|---|
| `crypto_clipper` | CWE-749 | ref |
| `install_exec` | CWE-829 | ref |
| `data_exfiltration` | CWE-200 | ref |
| `staged_loader_dropper` | CWE-506 | defined |
| `self_propagation` | CWE-506 | defined |
| `reverse_shell` | CWE-506 | defined |
| `backdoor_hardcoded_cred` | CWE-798 | defined |
| `cryptominer` | CWE-400 | defined |
| `anti_analysis_evasion` | CWE-511 | defined |

**Web and browser**

| family | CWE x-ref | status |
|---|---|---|
| `xss_sink` | CWE-79 | ref |
| `open_redirect` | CWE-601 | ref |
| `forced_download_drive_by` | CWE-494 | defined |

**Crypto and secrets**

| family | CWE x-ref | status |
|---|---|---|
| `weak_crypto` | CWE-327 | ref |
| `insecure_randomness` | CWE-338 | defined |
| `hardcoded_secret` | CWE-798 | ref |

**Measured granularity.** The taxonomy is measured, not asserted. Credential theft,
environment harvesting, and network exfiltration are one behavior, collect sensitive data
and send it out, so 3S records them as a single `data_exfiltration` family with the source
as metadata. CWE splits this into three classes (CWE-522, CWE-526, CWE-200); the signature
measured them as one, and the taxonomy follows the measurement. On the resulting thirteen
JavaScript families, leave-one-out separation is 91.0%, and eight families separate
perfectly (see [`3s/README.md`](3s/README.md)).

**Per-language.** Signatures are model-relative and language-relative: the same behavior in
Python and JavaScript does not share a centroid (Python-to-JS matching is 29.6%), so 3S
carries a database per language. The JavaScript families
separate at 91.0% and the Python families at 88.9%; both are in [`3s/`](3s/).

The taxonomy is open: the point of the standard is that anyone can contribute a `ref`
signature for a `defined` family, or propose a new family, per §10.

---

## 9. Worked example: catching a real attack through its obfuscation

The September-2025 `chalk/debug` compromise shipped a 76 KB obfuscated crypto-clipper
inside `debug@4.4.2` (benign `index.js` is 12 lines). Under this spec:

1. **Deobfuscate** (deterministic front-end): the obfuscated blob resolves to 414 readable
   lines exposing `checkethereumw`, the `eth_sendTransaction` hijack, and `responseText`
   tampering.
2. **Sign** the recovered code → `σ`.
3. **Match**: `σ` assigns to the **`crypto_clipper`** family, above the chance floor;
   the *raw* obfuscated signature is *below* the floor, demonstrating why §4.3's
   deterministic front-end is mandatory, not optional.

This is one worked example, not the thesis. The thesis is the format: the same procedure
applies to any behavior, any language, any clone.

Measured, held-out reference numbers on real npm malware vs. benign packages live in
[`supply-chain/README.md`](supply-chain/README.md), reported honestly (including where the
method is still weak).

---

## 10. Contributing a family or signature

1. Collect ≥1 example of the behavior; run the deterministic front-end if obfuscated.
2. Compute signatures with a pinned model descriptor (§4).
3. Submit a family record (§6.1) with centroid, member hashes, label, CWE x-ref, and a
   short behavior description, plus the reproduction command.
4. Contributions MUST declare their model descriptor; a maintainer re-projects to the
   canonical model if it differs.

An integrity gate enforces these mechanically: every contribution to the reference registry
runs [`3s/validate.py`](3s/validate.py), which confirms each family carries a severity, each
declared member hash matches an example file, and no example is duplicated, so a database can
never drift out of sync with the corpus it claims to summarize. The full contributor workflow
is [`3s/CONTRIBUTING.md`](3s/CONTRIBUTING.md).

---

## 11. Open problems (honest status)

- **Cross-model portability.** Signatures are model-relative. A canonical model per spec
  version, or a learned projection between models, is unspecified and needed.
- **Calibrated thresholds at scale.** Deployable precision/recall depends on the decision
  function and the benign distribution; low false-positive rates at ecosystem scale are
  not yet demonstrated.
- **Localization.** Whole-file signatures do not yet localize *which line* is the
  behavior; for diff-scoped use (supply-chain updates) the diff supplies location.
- **Adversarial robustness.** Behavior-preserving transforms that also shift the signature
  (deep control-flow obfuscation) are an open adversarial frontier.

Standards evolve. This is v0.1.

---

## 12. Relationship to prior art

3S is complementary to the tools below, not a replacement for any of them; each reads a
signal 3S does not, and 3S adds a behavioral one they lack.

- **YARA**: syntactic string/byte rules, authored by hand and fast to run. A semantic
  signature is derived rather than authored and holds across renaming and refactoring; the
  two pair naturally, syntax for the known payload, behavior for its rewrites.
- **CWE**: a human-authored weakness taxonomy that 3S families cross-reference (§8). CWE
  names the weakness in prose; a 3S family grounds a behavior in a signature you can match.
- **VUDDY / MVP / MOVERY**: vulnerable-clone detection on tokens/slices/CFGs. This spec
  keys the same `(vulnerability, patch)` mechanism on the representation that survives the
  modification those systems fight.
- **EPSS / exploit prediction**: natural-language exploit signals. §4 makes an NL
  description and code project into the *same* signature space, so a description can index
  code (developed further outside this public spec).

---

*Reference implementation: [`engine/`](engine/) · [`supply-chain/`](supply-chain/). Thesis:
[`README.md`](README.md). This specification is a draft proposal, offered for the field to
adopt, extend, and contribute to.*
