"""Severity policy for 3S families: which behaviors block a dependency, which warn.

Kept separate from the signature database on purpose. A centroid says *what code
does*; whether that behavior should stop a build is a deployment decision, and a
site can swap this policy without recomputing a single signature. Two levels:

  block  behavior that is malicious by intent when it shows up in a third-party
         dependency (steal funds, steal data, run on install, evaluate remote source).
  warn   a weakness or risky pattern worth surfacing but not inherently hostile.

This mirrors the spec's per-family ``action.kind`` field (SPECIFICATION.md section 6.1);
build_families.py and build_python.py stamp it into the emitted databases.
"""
from __future__ import annotations

SEVERITY = {
    # block: malicious intent in a dependency
    "crypto_clipper":              ("block", "hijacks wallet or transaction targets"),
    "data_exfiltration":           ("block", "sends local data to a remote host"),
    "install_exec":                ("block", "executes on install or drops a payload"),
    "code_injection_eval":         ("block", "evaluates caller- or network-supplied source"),
    "command_injection":           ("block", "runs a shell command built from input"),
    # warn: weakness or risky pattern
    "server_side_request_forgery": ("warn", "fetches a caller-controlled URL"),
    "unsafe_deserialization":      ("warn", "reconstructs objects from untrusted data"),
    "path_traversal":              ("warn", "opens a caller-controlled filesystem path"),
    "prototype_pollution":         ("warn", "writes through __proto__ or constructor"),
    "xss_sink":                    ("warn", "writes unescaped input into the DOM"),
    "open_redirect":               ("warn", "redirects to a caller-controlled location"),
    "hardcoded_secret":            ("warn", "embeds a credential in source"),
    "weak_crypto":                 ("warn", "uses a broken hash or cipher"),
}

DEFAULT = ("warn", "behavioral family without a severity mapping")

LEVELS = {"block": 2, "warn": 1, "none": 0}


def severity(family: str):
    """Return (level, note) for a family; unknown families default to warn."""
    return SEVERITY.get(family, DEFAULT)


def at_or_above(level: str, threshold: str) -> bool:
    """True if ``level`` is at least as severe as ``threshold``."""
    return LEVELS.get(level, 0) >= LEVELS.get(threshold, 0)
