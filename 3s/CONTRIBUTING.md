# Contributing to the 3S signature registry

The registry grows by many hands agreeing on a shared vocabulary of behavior. There are two
kinds of contribution: **deepen a family** (add examples so its centroid is better grounded)
and **add a family** (name a behavior the taxonomy does not cover yet). Both go through the
same integrity gate.

## What a contribution looks like

Every family is a directory of small, self-contained examples of one behavior, plus a row in
the database built from them:

```
3s/families/<family>/example_N.js          # JavaScript corpus
3s/families_python/<family>/example_N.py    # Python corpus
3s/database.json  /  database_python.json   # built centroids + member hashes + action
```

Examples are **representative, not weaponized**. Show the shape of the behavior; leave harmful
specifics (real wallet addresses, live endpoints, real secrets) as inert placeholders.
Nothing in the corpus is ever executed, by the tooling or by CI.

## Deepen an existing family

1. Add one or more `example_N.<ext>` files under the family directory. Each should be a
   distinct realization of the behavior (a different API, a different framing), not a
   reworded copy, so it moves the centroid rather than just reweighting it.
2. Rebuild so the centroid and member hashes pick up the new examples:
   ```bash
   pip install -r 3s/requirements.txt
   python 3s/build_families.py      # or build_python.py for Python
   ```
3. Check nothing regressed:
   ```bash
   python 3s/validate.py
   ```
4. Commit the new examples **and** the rebuilt `database*.json` together.

## Add a new family

1. Pick a stable `snake_case` identifier and add at least **three** examples under a new
   directory (`3s/families/<family>/` or `3s/families_python/<family>/`).
2. Declare its severity in [`policy.py`](policy.py): `block` if the behavior is malicious by
   intent in a dependency, `warn` if it is a weakness. A family with no severity fails
   validation, on purpose.
3. Add the family to the builder's `FAMILIES` map (JavaScript, in
   [`build_families.py`](build_families.py)) or `PY`/`CWE` maps (Python, in
   [`cross_language.py`](cross_language.py)), with a CWE cross-reference where one fits.
4. Rebuild and validate as above.
5. If the new family lands on top of an existing one (they are the same behavior), the
   taxonomy should follow the measurement and merge them, the way three exfiltration
   families collapsed into one `data_exfiltration`. See [`README.md`](README.md).

## What CI checks

`.github/workflows/3s-registry.yml` runs on every pull request that touches `3s/`:

- **Integrity (every PR, no model):** [`validate.py`](validate.py) confirms each database is
  well-formed, every family has a severity, every declared member hash matches an example
  file, and no example is duplicated. This is the gate a contributor must pass.
- **Separation (maintainer-dispatched):** a model-gated job recomputes centroids and fails if
  leave-one-out separation regresses. Recomputing needs the 1.3B model, so it does not run on
  each contributor PR; a maintainer triggers it before merging a change to the corpus.

Run both locally before opening a pull request: `python 3s/validate.py`, then a rebuild if
you touched the corpus.
