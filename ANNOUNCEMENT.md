# Announcing 3S: semantic signatures for code

Most ways we describe malicious or vulnerable code read the surface: a rule lists bytes and
strings, a CVE fingerprints one build, a CWE class is a sentence a human wrote. These read
real signals and they are worth running. They also share a blind spot, one the attacker
controls directly: rename a variable, flatten the control flow, encode the strings, and the
description no longer matches, even though the code does exactly what it did before.

The 2025 and 2026 npm supply-chain attacks made this concrete at scale. The compromised
`chalk` and `debug` releases shipped a crypto-clipper as a 76 KB obfuscated blob. The
Shai-Hulud and keyv worms hid credential stealers behind packing and inside files scanners
do not read. What stayed constant through every rewrite was the behavior.

## The proposal

**3S**, the Semantic Signature Specification, defines a unit keyed on behavior. A semantic
signature is a fixed-length vector that a small model derives from what code does, read from
the model's own representation rather than from the surface text. Because it tracks behavior,
it survives the transformations that defeat surface matching: renaming, refactoring,
minification, and, once the packing is deterministically resolved, obfuscation.

3S is meant to sit alongside the tools you already run, not to replace them. It adds a
behavioral layer, and it earns its keep exactly where surface signals go quiet. It brings
three things: a portable format for the signature, a family taxonomy that names what code
does, and a matching procedure with stated invariance guarantees.

## The evidence

3S ships as a specification with a working reference implementation, not as a position.

- On real C vulnerabilities, a signature indexes a database that returns the patch for the
  class, and an AddressSanitizer oracle confirms the patch turns the crashing input safe.
  Twelve of twelve signature-selected patches verified end to end, including on renamed and
  refactored variants that share no identifiers with the original.
- On the real npm attacks, the pipeline deobfuscates, signs, and detects malicious behavior
  through its obfuscation. On 264 real packages, held out, the detector reaches roughly
  0.93 ROC-AUC and catches between two-thirds and three-quarters of real malware at 95
  percent precision. The number holds against obscure benign packages that are smaller than
  the malware, so it is not an artifact of popularity or size.
- As a worked example, the actual compromised `debug@4.4.2` crypto-clipper signs below the
  chance floor while obfuscated and, once statically deobfuscated, lands cleanly on the
  `crypto_clipper` family. That is the whole loop, on the real attack.

We report the limits with the same precision as the results. Deployable recall at high
precision is still modest. Signatures are model-relative. Precise line localization is
unsolved. These are written into the specification, because a standard that hides its
failure modes does not deserve adoption.

## What we are asking

Read the [specification](SPECIFICATION.md). Run the [reference
implementation](engine/). Contribute a signature for a family that is defined but not yet
populated, or propose a new one with the corpus that grounds it. The taxonomy is meant to
grow by many hands agreeing on a shared vocabulary.
