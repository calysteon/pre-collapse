# 3S — Semantic Signature Specification

**Version 0.1 (draft proposal) · a portable format for obfuscation-invariant code signatures**

**3S** (the three S's of **S**emantic **S**ignature **S**pecification) is to behavior what
YARA is to bytes: a shared, portable format for *signatures* — but keyed on what code
**does**, not how it is written. A 3S signature is written `3S:<model>/<family>`, and a 3S
database of families is the semantic counterpart to a YARA ruleset.

> For thirty years the unit of security knowledge has been a *syntactic* pair — a **YARA**
> rule (bytes/strings), a **CVE** fingerprint, a **CWE** class written in prose. Syntax
> breaks the moment code is renamed, refactored, minified, or obfuscated. This document
> specifies the alternative the [Pre-Collapse white paper](README.md) argues for: a
> **semantic signature** — a fixed-length vector a small model derives from *what code
> does* — together with a portable format for expressing, sharing, matching, and
> classifying such signatures.
>
> Where a YARA rule says *"these bytes appear,"* a semantic signature says *"this code
> behaves like this,"* and keeps saying it after the bytes change.

This is a **proposal with a working reference implementation** ([`engine/`](engine/),
[`supply-chain/`](supply-chain/)), not a finished standard. It is versioned so it can
evolve, exactly as YARA and CWE did.

---

## 1. Motivation

Syntactic matching has one structural failure: the attacker controls the syntax. MOVERY
measured that **91% of real vulnerable code clones differ syntactically** from their
origin — so a signature keyed on surface form misses them by construction. The same is
true of malware: renaming, control-flow flattening, and string encoding defeat byte/string
rules while leaving *behavior* intact.

A model reading code forms a representation of that behavior **before** it forms any
output, and that representation is (a) linearly decodable, (b) causal, and (c) stable
under transformations that change syntax but not meaning. A **semantic signature** is that
representation, canonicalized into a portable, comparable object. Because it tracks
behavior, it survives what defeats syntax.

**Design goals**

1. **Portable** — a signature is a serializable record, exchanged like a `.yar` file.
2. **Auto-derivable** — computed by reading code, not hand-authored per rule.
3. **Invariant** — semantically-equivalent code yields matching signatures.
4. **Composable** — signatures aggregate into *families* (a semantic taxonomy).
5. **Honest about model-relativity** — a signature is only comparable within the model
   that produced it; the model is part of the signature's identity (§4).

---

## 2. Definitions

- **Semantic signature** `σ(C; M)` — a fixed-length unit vector derived from model `M`'s
  activations while reading code file `C` (§4).
- **Family** — a set of signatures that share a behavior, represented by a **centroid**
  signature and a human label. The semantic analogue of a CWE class.
- **Signature database** — a collection of families under one model `M`.
- **Match** — assignment of a query signature to a family via a calibrated decision
  function (§6).
- **Reference marker / behavior** — the observable a family encodes (e.g. *wallet-hook
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
   surface form — precisely what the signature must be invariant to.
4. **L2-normalize** → the signature `σ(C; M)`.

The reference implementation is
[`engine/precollapse/signature.py`](engine/precollapse/signature.py).

### 4.3 Obfuscation and the deterministic front-end

String-array / packing obfuscation encodes behavior behind a decoder; the raw signature
of such code is **below chance** (a measured result — the tells are drowned in decoder
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
  "model": { /* descriptor — MUST match query's model */ },
  "families": [
    { "family": "crypto_clipper", "cwe": "CWE-749",
      "centroid": [/* dim floats */], "members": ["<sha256>", "..."],
      "action": { "kind": "block", "patch": "neutralize-web3-hooks" },
      "description": "browser wallet-transaction hijack" }
  ]
}
```

The reference format is [`engine/db/signature_patch_db.json`](engine/db/signature_patch_db.json).
Note the **`action`** field: a family entry carries not just a label but the response —
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
behaviorally** — renamed, refactored, re-packed, obfuscated-then-resolved — assign to the
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

## 8. The family taxonomy (a semantic successor to CWE)

Families are the shared vocabulary. Unlike CWE, a family is **defined by its centroid
signature**, not by prose — so it is machine-readable, auto-derivable (cluster signatures),
and it **grows itself** as new code is read. A family SHOULD carry a human label and, where
one exists, a CWE cross-reference — but the signature is authoritative.

**Seed families (reference database):**

| family | domain | CWE x-ref |
|---|---|---|
| `stack_buffer_overflow` | memory-safety | CWE-121 |
| `heap_buffer_overflow` | memory-safety | CWE-122 |
| `integer_overflow` | memory-safety | CWE-190 |
| `use_after_free` | memory-safety | CWE-416 |
| `crypto_clipper` | supply-chain / browser | CWE-749 |
| `credential_exfil` | supply-chain / CI | CWE-522 |
| `install_exec` | supply-chain / npm | CWE-829 |

The taxonomy is open — the point of the standard is that anyone can contribute a family.

---

## 9. Worked example — catching a real attack through its obfuscation

The September-2025 `chalk/debug` compromise shipped a 76 KB obfuscated crypto-clipper
inside `debug@4.4.2` (benign `index.js` is 12 lines). Under this spec:

1. **Deobfuscate** (deterministic front-end): the obfuscated blob resolves to 414 readable
   lines exposing `checkethereumw`, the `eth_sendTransaction` hijack, and `responseText`
   tampering.
2. **Sign** the recovered code → `σ`.
3. **Match**: `σ` assigns to the **`crypto_clipper`** family, above the chance floor;
   the *raw* obfuscated signature is *below* the floor — demonstrating why §4.3's
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
   short behavior description — plus the reproduction command.
4. Contributions MUST declare their model descriptor; a maintainer re-projects to the
   canonical model if it differs.

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

- **YARA** — syntactic string/byte rules. Semantic signatures are the behavioral
  counterpart: derived not authored, invariant not brittle.
- **CWE** — a human-authored weakness taxonomy. The family taxonomy (§8) is its
  machine-derivable, signature-defined successor.
- **VUDDY / MVP / MOVERY** — vulnerable-clone detection on tokens/slices/CFGs. This spec
  keys the same `(vulnerability, patch)` mechanism on the representation that survives the
  modification those systems fight.
- **EPSS / exploit prediction** — natural-language exploit signals. §4 makes an NL
  description and code project into the *same* signature space, so a description can index
  code (developed further outside this public spec).

---

*Reference implementation: [`engine/`](engine/) · [`supply-chain/`](supply-chain/). Thesis:
[`README.md`](README.md). This specification is a draft proposal, offered for the field to
adopt, extend, and contribute to.*
