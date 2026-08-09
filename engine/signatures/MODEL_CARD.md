# Signature model card

The committed `corpus_signatures.json` (and therefore `db/signature_patch_db.json`) were
produced by reading each corpus program with a real model and reducing its hidden states
to one vector per program.

| | |
|---|---|
| Model | `microsoft/phi-1_5` (1.3B) |
| Precision | float32 (CPU) |
| Pooling | mean over token positions at each layer |
| Reduction | mean over the deep band (last 50% of layers, final layer dropped), then L2-normalized |
| Signature dim | 2048 |
| Inputs | the full source of each recipient (canonical `vuln.c` + variants) |

Phi-1.5 is used because the thesis is specifically about *small* models: a 1.3B model that
can read every function in an ecosystem cheaply. Full precision is used because quantized
activations are noisy. The signature deliberately excludes the shallowest layers, which
still carry surface form; the property we want is invariance to surface form.

## Reproduce

```bash
python tools/compute_signatures.py --model microsoft/phi-1_5 --out signatures/corpus_signatures.json
python tools/build_db.py --signatures signatures/corpus_signatures.json --out db/signature_patch_db.json
python tools/evaluate.py
```

Any causal-LM id works (`--model`); larger or code-specialized models should sharpen the
held-out numbers. Signatures are only comparable within one model, so regenerate the DB
whenever you change the model. The exact float values depend on library versions and CPU
math; the *structure* (classes separate, held-out detection well above chance) is what
should reproduce.

## Measured on this set

- Full-DB match: 12/12 recipients match their class; 12/12 signature-selected patches are
  confirmed by the oracle.
- Held-out (leave-one-out) detection: 10/12 (83%). Both errors are heap-overflow vs
  integer-overflow, which share a heap out-of-bounds write and sit closest in signature
  space. This is expected with two members per class on a 1.3B model and is exactly the
  kind of confusion the oracle exists to catch downstream.
