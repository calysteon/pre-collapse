# Supply-chain detector — deobfuscate → sign → probe

Applies the pre-collapse thesis to the npm supply-chain attacks of 2025–26 (chalk/debug,
Shai-Hulud, keyv). The claim under test: a small model's **activation signature** of a
package's code identifies malicious *behavior* semantically, surviving the obfuscation
that defeats syntactic scanners — once the obfuscation is deterministically resolved.

The pipeline is the thesis's division of labor:

```
package code
  → DEOBFUSCATE   deterministic, static (webcrack) — resolve string-array/canary obfuscation
  → SIGN          Phi-1.5 deep-band activation signature (precollapse/signature.py)
  → PROBE         trained, calibrated linear classifier (NOT nearest-centroid cosine)
  → malicious / benign
```

Deobfuscation is deterministic on purpose (the model is at chance on the arithmetic a
string-array decoder needs); the model does the semantic behavior reading it is good at.

## Result (first-pass, held-out 5-fold CV)

Corpus: **264 real packages** — 129 malicious from DataDog's human-vetted
`malicious-software-packages-dataset`, 135 popular benign packages from npm. 20 required
deobfuscation; the rest were plaintext.

| method | ROC-AUC | PR-AUC |
|---|---|---|
| nearest-centroid cosine (baseline) | 0.930 | 0.919 |
| **trained linear probe** | **0.949** | **0.964** |

Trained-probe operating points (held out):

| threshold | precision | recall | FPR |
|---|---|---|---|
| 0.90 | 0.974 | 0.876 | 0.022 |
| @precision ≥ 0.95 | — | 0.891 | — |

**The probe beats cosine** (the thesis's point: a trained decision boundary, not
centroid distance). **It is not a length artifact** — file length alone scores ROC-AUC
0.580, near chance, while the probe scores 0.949.

### Hardening: harder benign set (the confound test)

The 135 benign above are *popular* packages, so the number could reflect
"malware-sample-shaped vs top-npm-shaped." We re-ran against 180 **obscure, mid-tail**
packages (median 1646 bytes — *smaller* than the malware, so size can't help):

| same malware vs … | ROC-AUC | recall @ precision ≥ 0.95 |
|---|---|---|
| popular benign | 0.949 | 0.891 |
| **hard (obscure) benign** | **0.925** | **0.667** |
| popular + hard combined | 0.935 | 0.775 |

**The core signal survives** — ROC-AUC holds at 0.925 against obscure benign, so the probe
detects maliciousness, not popularity or size. **But the deployable operating point is
more modest than the popular-only number suggested:** at ≥95% precision, recall is
**~0.67–0.78**, not 0.89. The high-precision number was flattered by easy, polished benign.
Honest headline: **~0.93 ROC-AUC, ~67–78% of real malware caught at 95% precision.**

## Real-payload receipt (chalk/debug, September 2025)

The actual compromised `debug@4.4.2`: a 76 KB obfuscated crypto-clipper injected into a
package whose benign `index.js` is 12 lines. Static deobfuscation (webcrack) recovered
414 readable lines exposing the documented behavior verbatim — `checkethereumw`, the
`eth_accounts` probe, the `eth_sendTransaction` hijack, and `Object.defineProperty` on
`responseText`. Signed against a behavior taxonomy:

- **raw obfuscated** → below the chance floor (the payload's tells are drowned in
  obfuscation density — you cannot skip deobfuscation),
- **deobfuscated** → tops `crypto_clipper` above the floor.

That is the deobfuscate-then-sign loop, end to end, on the real attack.

## Honest limits (do NOT overclaim)

- **Subset, first-pass.** 264 packages, one representative file per package (install-hook
  → main → index.js → largest .js). Not the full 27,876-sample dataset.
- **Deployable recall is ~67–78% at 95% precision** (against obscure/combined benign), not
  the 89% the popular-only set suggested. The core AUC (~0.93) is confound-robust, but the
  high-precision operating point is where obscure benign packages confuse it.
- **Still a subset.** 129 malware / 315 benign; not the full 27,876-sample dataset, and not
  yet run against the public SynthChain benchmark.
- **Full-npm scale needs a lower FPR** (millions of packages → many false alarms) — a
  second-stage filter or a stronger model.
- **Deobfuscation is lightly exercised here** (20/264); its necessity is shown separately
  on the real chalk/debug payload, not stress-tested across the corpus.
- **Signatures are a whole-file mean-pool.** Precise line-localization is unsolved (see
  the activation-signature experiments); for supply-chain the git diff supplies location.

## Reproduce

```bash
# 1. corpus (DataDog dataset cloned separately; samples are password-'infected' zips)
python pipeline/extract_malicious.py      # → corpus/malicious/*.js  (payloads, gitignored)
python pipeline/fetch_benign.py           # → corpus/benign/*.js
# 2. deobfuscate + sign  (needs torch + transformers + a Phi model; webcrack via node)
python pipeline/sign_corpus.py            # → data/signatures.npz
# 3. train + evaluate
python pipeline/train_eval.py
```

`data/signatures.npz` (activation vectors, not code) is committed so step 3 reproduces
without re-signing. **Payloads are never committed** (see `.gitignore`); handling is
static, defensive, nothing executed.
