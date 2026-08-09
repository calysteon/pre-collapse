"""Ground-truth oracle: does a patch actually eliminate the vulnerability?

The thesis's whole point is that a signature indexes a patch that *works*. "Works"
cannot be asserted; it has to be measured. This oracle measures it the only honest
way: compile the C under AddressSanitizer, feed it the proof-of-concept input, and
watch what the program actually does.

  - VULNERABLE : the program hit a memory-safety error (ASan aborted). The bug is live.
  - SAFE       : the program ran the same PoC to a clean exit. The bug is gone.
  - BROKEN     : it would not compile, or it failed some way that is neither of the
                 above (a patch that doesn't build is not a patch).

A patch "works against" a vulnerability iff the *same* PoC that makes the original
VULNERABLE makes the patched program SAFE. Nothing about the model is trusted here;
this is the part of the loop that keeps the rest honest.
"""

from __future__ import annotations

import dataclasses
import os
import shutil
import subprocess
import tempfile
from enum import Enum
from pathlib import Path


class Verdict(str, Enum):
    VULNERABLE = "VULNERABLE"
    SAFE = "SAFE"
    BROKEN = "BROKEN"


@dataclasses.dataclass
class OracleResult:
    verdict: Verdict
    returncode: int | None
    asan_error: str | None  # the ASan error class, e.g. "stack-buffer-overflow", if any
    detail: str

    @property
    def is_memory_error(self) -> bool:
        return self.verdict is Verdict.VULNERABLE


# ASan prints a banner line "ERROR: AddressSanitizer: <class> on address ...".
_ASAN_MARKER = "ERROR: AddressSanitizer:"
_UBSAN_MARKER = "runtime error:"


def _pick_compiler(preferred: str | None = None) -> str:
    candidates = [preferred] if preferred else []
    candidates += ["gcc", "clang", "cc"]
    for c in candidates:
        if c and shutil.which(c):
            return c
    raise RuntimeError("no C compiler with sanitizer support found (need gcc or clang)")


def _extract_asan_class(stderr: str) -> str | None:
    idx = stderr.find(_ASAN_MARKER)
    if idx == -1:
        return None
    rest = stderr[idx + len(_ASAN_MARKER):].strip()
    # e.g. "stack-buffer-overflow on address 0x... " -> "stack-buffer-overflow"
    return rest.split()[0] if rest else "unknown"


def run(
    src_path: str | Path,
    poc_path: str | Path,
    *,
    compiler: str | None = None,
    timeout: float = 30.0,
    extra_cflags: tuple[str, ...] = (),
) -> OracleResult:
    """Compile ``src_path`` under ASan+UBSan and run it with ``poc_path`` on stdin."""
    src_path = Path(src_path)
    poc = Path(poc_path).read_bytes() if Path(poc_path).exists() else b""
    cc = _pick_compiler(compiler)

    with tempfile.TemporaryDirectory(prefix="precollapse-oracle-") as td:
        binary = Path(td) / "target"
        cflags = [
            "-g",
            "-O0",
            "-fsanitize=address,undefined",
            "-fno-omit-frame-pointer",
            *extra_cflags,
        ]
        compile_cmd = [cc, *cflags, str(src_path), "-o", str(binary)]
        cp = subprocess.run(compile_cmd, capture_output=True, text=True, timeout=timeout)
        if cp.returncode != 0 or not binary.exists():
            return OracleResult(
                Verdict.BROKEN, cp.returncode, None,
                f"compilation failed:\n{cp.stderr.strip()[:2000]}",
            )

        env = dict(os.environ)
        # Deterministic, no leak-check noise; keep the report on stderr.
        # allocator_may_return_null=1 makes an overflowing/huge allocation return NULL
        # (as real libc calloc/malloc do) instead of ASan aborting -- so a checked-
        # allocation patch is judged on real runtime semantics, not on ASan's stricter
        # allocator policy. The out-of-bounds *access* is still caught as normal.
        env["ASAN_OPTIONS"] = (
            "detect_leaks=0:abort_on_error=0:exitcode=99:allocator_may_return_null=1"
        )
        env["UBSAN_OPTIONS"] = "print_stacktrace=0:halt_on_error=1:exitcode=99"
        try:
            rp = subprocess.run(
                [str(binary)], input=poc, capture_output=True,
                timeout=timeout, env=env,
            )
        except subprocess.TimeoutExpired:
            return OracleResult(Verdict.BROKEN, None, None, "target timed out")

        stderr = rp.stderr.decode("utf-8", "replace")
        asan_class = _extract_asan_class(stderr)
        hit_sanitizer = (_ASAN_MARKER in stderr) or (_UBSAN_MARKER in stderr)

        if hit_sanitizer:
            return OracleResult(
                Verdict.VULNERABLE, rp.returncode, asan_class,
                f"sanitizer fired: {asan_class or 'undefined-behavior'}",
            )
        if rp.returncode == 0:
            return OracleResult(Verdict.SAFE, 0, None, "clean exit on the PoC input")
        # Non-zero exit with no sanitizer report: a plain crash or a bad patch.
        return OracleResult(
            Verdict.BROKEN, rp.returncode, None,
            f"non-sanitizer failure (rc={rp.returncode})",
        )


def confirms_fix(vuln_src: str | Path, patched_src: str | Path, poc_path: str | Path,
                 **kw) -> tuple[bool, OracleResult, OracleResult]:
    """True iff the PoC makes ``vuln_src`` VULNERABLE and ``patched_src`` SAFE."""
    before = run(vuln_src, poc_path, **kw)
    after = run(patched_src, poc_path, **kw)
    ok = before.verdict is Verdict.VULNERABLE and after.verdict is Verdict.SAFE
    return ok, before, after
