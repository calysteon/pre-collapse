# 3S reference database

This directory is the reference 3S family database: representative code examples per
behavioral family, their signatures under `microsoft/phi-1_5`, and the built centroids in
[`database.json`](database.json) (format per [SPECIFICATION.md](../SPECIFICATION.md)
section 6.1).

```
3s/
  build_families.py   sign examples, form centroids, run the separation check, emit database.json
  families/<family>/  three examples per family (canonical, renamed, refactored)
  database.json        the 3S reference database: 15 family centroids, dim 2048
```

Rebuild: `python 3s/build_families.py`. Malicious-behavior families are represented
structurally, with harmful specifics (real addresses, endpoints, secrets) left as inert
placeholders. Nothing here is executed.

## Measured separation (leave-one-out, three examples per family)

Overall **31/45 = 68.9%** across 15 fine-grained families, against a 6.7% chance baseline
for a 15-way assignment. Per family:

| separation | families |
|---|---|
| 3/3 | `command_injection`, `path_traversal`, `prototype_pollution`, `xss_sink`, `weak_crypto`, `hardcoded_secret` |
| 2/3 | `code_injection_eval`, `unsafe_deserialization`, `server_side_request_forgery`, `open_redirect`, `crypto_clipper`, `install_exec` |
| 0 to 1 / 3 | `credential_exfil`, `env_secret_harvest`, `network_exfil` |

## The collapsed cluster is a finding, not a failure

The three weak families confuse almost entirely with each other and with nothing else.
That is correct. `credential_exfil` (read tokens), `env_secret_harvest` (read env and
dotfiles), and `network_exfil` (POST data out) are the *same behavior*: collect sensitive
data and send it somewhere. CWE draws three human distinctions here (CWE-522, CWE-526,
CWE-200); the signature draws one.

This is the semantic taxonomy self-organizing to the granularity the behavior actually
has. Where a syntactic taxonomy asserts distinctions by fiat, a signature taxonomy
measures them: families that share a behavior merge, and families that differ separate.
The clean 3/3 families are exactly the ones whose behavior is distinct (command execution,
path handling, prototype mutation, DOM injection, weak hashing, embedded credentials).

The practical reading: these three should be one family, `data_exfiltration`, with the
specific source recorded as metadata rather than as a separate family. The reference
database keeps all three centroids so the measurement is reproducible, and the
specification records the cluster explicitly.

## Honest status

Three examples per family is a seed, not a benchmark. Separation improves with more
examples per family and with a stronger or code-specialized model. The number reported
here is the current, reproducible quality of the reference database at v0.1, not a claim
about the ceiling.
