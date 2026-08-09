# Announcing 3S: semantic signatures for code

For thirty years, the way we describe malicious or vulnerable code has been syntactic. A
YARA rule lists bytes and strings. A CVE is a fingerprint of one build. A CWE class is a
sentence a human wrote. All three share a single weakness: the attacker controls the
syntax. Rename a variable, flatten the control flow, encode the strings, and the signature
no longer matches, even though the code does exactly what it did before.

The 2025 and 2026 npm supply-chain attacks made this concrete at scale. The compromised
`chalk` and `debug` releases shipped a crypto-clipper as a 76 KB obfuscated blob. The
Shai-Hulud and keyv worms hid credential stealers behind packing and inside files scanners
do not read. Each of these evaded syntactic detection by construction, because syntactic
detection was never looking at what the code does.

## The proposal

**3S**, the Semantic Signature Specification, defines a different unit. A semantic
signature is a fixed-length vector that a small model derives from what code does, read
from the model's own representation rather than from the surface text. Because it tracks
behavior, it survives the transformations that defeat syntax: renaming, refactoring,
minification, and, once the packing is deterministically resolved, obfuscation.

Where a YARA rule says "these bytes appear," a 3S signature says "this code behaves like
this," and it keeps saying it after the bytes change. 3S is to behavior what YARA is to
bytes: a portable format for signatures, a family taxonomy that plays the role CWE plays
for weaknesses, and a matching procedure with stated invariance guarantees.

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
populated, or propose a new one. The taxonomy is meant to grow the way YARA rulesets and
the CWE list grew, by many hands agreeing on a shared vocabulary.

The syntactic era of security signatures is ending because the attackers ended it. The
representation that survives is the one the model forms when it reads the code. 3S is the
format for writing it down.
