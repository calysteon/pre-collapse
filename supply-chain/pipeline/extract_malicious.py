import os, json, zipfile, tempfile, shutil, hashlib, re
from pathlib import Path

DD = Path("/home/user/dd")
OUT = Path("/home/user/corpus/malicious"); OUT.mkdir(parents=True, exist_ok=True)
picks = [l.strip() for l in open("/tmp/pick_mal.txt") if l.strip()]

def pick_payload(pkgdir: Path):
    """Return (relpath, text) of the most detection-relevant JS file, or None."""
    pj = pkgdir / "package.json"
    scripts, main = {}, None
    if pj.exists():
        try:
            j = json.loads(pj.read_text(errors="ignore"))
            scripts = j.get("scripts", {}) or {}
            main = j.get("main")
        except Exception:
            pass
    js_files = [p for p in pkgdir.rglob("*.js")] + [p for p in pkgdir.rglob("*.cjs")] + [p for p in pkgdir.rglob("*.mjs")]
    if not js_files:
        return None
    # 1) file referenced by an install hook
    hook_blob = " ".join(scripts.get(k, "") for k in ("preinstall","install","postinstall"))
    for p in js_files:
        if p.name in hook_blob or str(p.relative_to(pkgdir)) in hook_blob:
            return p.relative_to(pkgdir), p.read_text(errors="ignore")
    # 2) main
    if main:
        cand = (pkgdir / main)
        if cand.exists() and cand.suffix in (".js",".cjs",".mjs"):
            return cand.relative_to(pkgdir), cand.read_text(errors="ignore")
    # 3) index.js
    for p in js_files:
        if p.name == "index.js":
            return p.relative_to(pkgdir), p.read_text(errors="ignore")
    # 4) largest .js
    p = max(js_files, key=lambda x: x.stat().st_size)
    return p.relative_to(pkgdir), p.read_text(errors="ignore")

manifest = []
ok = 0
for zp in picks:
    zabs = DD / zp
    if not zabs.exists(): continue
    with tempfile.TemporaryDirectory() as td:
        try:
            with zipfile.ZipFile(zabs) as z:
                z.extractall(td, pwd=b"infected")
        except Exception as e:
            continue
        # find package/ dirs (npm root has package.json)
        roots = [Path(dp) for dp,_,fs in os.walk(td) if "package.json" in fs and Path(dp).name == "package"]
        if not roots:
            roots = [Path(dp) for dp,_,fs in os.walk(td) if "package.json" in fs]
        if not roots: continue
        res = pick_payload(roots[0])
        if not res: continue
        rel, text = res
        if not text or len(text) < 20: continue
        sid = hashlib.sha1(zp.encode()).hexdigest()[:12]
        (OUT / f"{sid}.js").write_text(text[:200000])
        manifest.append({"id": sid, "label": "malicious", "sample": zp, "file": str(rel), "bytes": len(text)})
        ok += 1

json.dump(manifest, open("/home/user/corpus/malicious_manifest.json","w"), indent=1)
print(f"extracted {ok} malicious payload files -> {OUT}")
# quick behavior-tell histogram (sanity)
import collections
tells = collections.Counter()
for m in manifest:
    t = (OUT / f"{m['id']}.js").read_text(errors="ignore")
    for k in ["ethereum","child_process","process.env","http","eval","fetch","exec","atob","require("]:
        if k in t: tells[k]+=1
print("tells across corpus:", dict(tells))