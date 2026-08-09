# 3S reference database

Representative code examples per behavioral family, their signatures under
`microsoft/phi-1_5`, and the built centroids in [`database.json`](database.json) (format
per [SPECIFICATION.md](../SPECIFICATION.md) section 6.1).

```
3s/
  build_families.py   sign examples, form centroids, run the separation check, emit database.json
  families/<family>/  five or more examples per family (canonical, renamed, refactored, variant)
  database.json        the 3S reference database: 13 family centroids, dim 2048
```

Rebuild: `python 3s/build_families.py`. Malicious-behavior families are represented
structurally, with harmful specifics (real addresses, endpoints, secrets) left as inert
placeholders. Nothing here is executed.

## Result: 13 behavioral families separate at 87.9%

Leave-one-out separation across the 13 families is **58/66 = 87.9%**, against a 7.7%
chance baseline for a 13-way assignment. On a 1.3-billion-parameter model, reading only
what the code does, the signatures tell distinct behaviors apart nearly nine times in ten.

| separation | families |
|---|---|
| 5/5 | `command_injection`, `server_side_request_forgery`, `prototype_pollution`, `xss_sink`, `open_redirect`, `hardcoded_secret`, `install_exec` |
| 4/5 | `code_injection_eval`, `path_traversal`, `weak_crypto`, `crypto_clipper` |
| 4/6 | `data_exfiltration` |
| 3/5 | `unsafe_deserialization` |

Seven of thirteen families are perfect. The signatures are computed once and the families
generalize: renamed and refactored variants land on the same centroid, which is the whole
point of keying on behavior instead of syntax.

## The taxonomy is measured, not asserted

An earlier build carried three separate exfiltration families (credential theft,
environment harvesting, network exfiltration). The signatures placed all three on top of
one another, because they are one behavior: collect sensitive data and send it out. So the
database now carries a single `data_exfiltration` family, with the specific source recorded
as metadata. CWE splits this into three classes by human judgment; the signature measured
it as one, and the taxonomy follows the measurement.

This is the semantic taxonomy doing something a syntactic one cannot: the family boundaries
are drawn by what the model sees, so families that share a behavior merge and families that
differ separate. It is why the clean families are exactly the ones whose behavior is
distinct (command execution, request forgery, prototype mutation, DOM injection, redirect,
embedded credentials, install-time execution).

## Deepening the database

Separation rose from 68.9% to 87.9% by consolidating to distinct behaviors and adding
examples per family. Both levers keep going: more examples per family sharpen the centroids
further, a code-specialized or larger model widens the margins, and each new family
contributed by the community extends coverage. The reference builder makes every step
reproducible from source.
