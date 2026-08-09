# 3S reference database

Representative code examples per behavioral family, their signatures under
`microsoft/phi-1_5`, and the built centroids in [`database.json`](database.json)
(JavaScript) and [`database_python.json`](database_python.json) (Python), in the format of
[SPECIFICATION.md](../SPECIFICATION.md) section 6.1.

```
3s/
  build_families.py   sign JS examples, form centroids, emit database.json
  build_python.py     sign Python examples, form centroids, emit database_python.json
  cross_language.py   match Python behaviors against the JS centroids
  scan.py             match code files against the database, gate on severity
  policy.py           per-family severity (block vs warn), swappable without recompute
  families/<family>/       JS examples per family
  families_python/<family>/ Python examples per family
```

Rebuild: `python 3s/build_families.py`. Malicious-behavior families are represented
structurally, with harmful specifics (real addresses, endpoints, secrets) left as inert
placeholders. Nothing here is executed.

## Scanning code

`scan.py` signs each file, matches it to the nearest behavioral family, and attaches a
severity from `policy.py`. It exits non-zero when something meets the `--fail-on` threshold,
so it drops straight into CI or a pre-commit hook.

```bash
pip install -r 3s/requirements.txt          # numpy + torch + transformers

python 3s/scan.py app.js utils.py            # table, fails on a block family
python 3s/scan.py --json app.js              # one JSON record per file
python 3s/scan.py --fail-on warn src/*.js    # also fail on weaknesses
python 3s/scan.py --min-margin 0.02 app.js   # report ambiguous matches as inconclusive
```

```
  [BLOCK] evil.js       [js]  3S:microsoft/phi-1_5/command_injection  cos 0.96  margin 0.03  CWE-78
          runs a shell command built from input
  [warn ] weakhash.js   [js]  3S:microsoft/phi-1_5/weak_crypto         cos 0.98  margin 0.05  CWE-327
          uses a broken hash or cipher
```

Severity is policy, not signature: `block` is behavior that is malicious by intent in a
dependency (`crypto_clipper`, `data_exfiltration`, `install_exec`, `code_injection_eval`,
`command_injection`); everything else is `warn`. Edit `policy.py` to change what stops a
build without touching a centroid. Deobfuscate packed code first (see
[`../supply-chain/`](../supply-chain/)).

**In CI.** A ready workflow lives at
[`.github/workflows/3s-scan.yml`](../.github/workflows/3s-scan.yml); it scans the JS and
Python changed in a pull request and fails on a block family. The reusable composite action
is [`.github/actions/3s-scan`](../.github/actions/3s-scan). As a pre-commit hook, point
`.pre-commit-config.yaml` at this repo and enable the `3s-scan` hook. The first run
downloads a 1.3B model (~2.7 GB) and signs on CPU, then caches it.

## Result: 13 JavaScript families separate at 91.0%

Leave-one-out separation across the 13 families is **61/67 = 91.0%**, against a 7.7% chance
baseline. Eight of thirteen families are perfect. On a 1.3-billion-parameter model, reading
only what the code does, the signatures tell distinct behaviors apart nine times in ten.

| separation | families |
|---|---|
| perfect | `command_injection`, `server_side_request_forgery`, `prototype_pollution`, `xss_sink`, `open_redirect`, `hardcoded_secret`, `install_exec`, `unsafe_deserialization` |
| one miss | `code_injection_eval`, `path_traversal`, `weak_crypto`, `crypto_clipper`, `data_exfiltration` |

The signatures are computed once and the families generalize: renamed and refactored
variants land on the same centroid, which is the point of keying on behavior over syntax.

## Cross-language: 3S covers npm and PyPI

Signatures are per-language. A Python behavior does not
land on a JavaScript centroid (`command_injection` via `os.system` and via
`child_process.exec` are represented differently); Python-to-JS matching is 29.6%. So 3S
carries a per-language database, and each separates cleanly within its language:

| language | database | internal separation |
|---|---|---|
| JavaScript | `database.json` | 91.0% (13 families) |
| Python | `database_python.json` | 88.9% (9 families, 3 examples each) |

The two families that do transfer across languages are `hardcoded_secret` and
`install_exec`, whose surface is nearly identical in both (credential strings, process
spawns). Everything else is language-specific, which is expected and correct.

## The taxonomy is measured, not asserted

An earlier build carried three separate exfiltration families. The signatures placed all
three on top of one another, because they are one behavior: collect sensitive data and send
it out. So the database carries a single `data_exfiltration` family, with the source as
metadata. CWE splits this into three classes by human judgment; the signature measured it
as one, and the taxonomy follows the measurement.

## Deepening the database

Separation rose from 68.9% to 87.9% to 91.0% by consolidating to distinct behaviors,
adding examples, and replacing examples that belonged to a neighbor (two
`unsafe_deserialization` cases that literally called `eval` were really code injection).
Every lever keeps going: more examples per family, more families, more languages, and a
code-specialized model widen the margins further. The builders make every step reproducible
from source.
