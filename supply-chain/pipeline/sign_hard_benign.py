import sys, json, re, subprocess, time
import numpy as np
from pathlib import Path
sys.path.insert(0, "/home/user/pre-collapse/engine")
from precollapse.signature import ModelBackend

CORP = Path("/home/user/corpus")
hb = json.load(open(CORP/"hard_benign_manifest.json"))

def looks_obfuscated(t):
    if not t: return False
    if re.search(r"_0x[0-9a-fA-F]{4,}", t): return True
    longest = max((len(l) for l in t.splitlines()), default=0)
    return longest > 2000 or (len(t) > 4000 and t.count("\n") < len(t)/400)

def deob(path):
    try:
        r = subprocess.run(["node","/home/user/deob/webcrack_cli.js",str(path)],
                           capture_output=True, timeout=30)
        if r.returncode==0 and len(r.stdout)>20: return r.stdout.decode("utf-8","replace")
    except Exception: pass
    return None

print("loading model ...", flush=True)
mb = ModelBackend("microsoft/phi-1_5", device="cpu", max_length=2048)
X, ids = [], []
t0=time.time()
for i,m in enumerate(hb):
    p = CORP/"hard_benign"/f"{m['id']}.js"
    if not p.exists(): continue
    text = p.read_text(errors="ignore")
    if looks_obfuscated(text):
        d = deob(p)
        if d: text = d
    try: v = mb.encode(text)
    except Exception: continue
    X.append(v); ids.append(m["id"])
    if (i+1)%25==0: print(f"  {i+1}/{len(hb)}  {time.time()-t0:.0f}s", flush=True)
np.savez(CORP/"hard_benign_sig.npz", X=np.stack(X), ids=np.array(ids))
print(f"DONE: {len(ids)} hard-benign signatures -> hard_benign_sig.npz")
