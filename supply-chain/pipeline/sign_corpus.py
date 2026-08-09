import sys, os, json, re, subprocess, time
import numpy as np
from pathlib import Path
sys.path.insert(0, "/home/user/pre-collapse/engine")
from precollapse.signature import ModelBackend

CORP = Path("/home/user/corpus")
mal = json.load(open(CORP/"malicious_manifest.json"))
ben = json.load(open(CORP/"benign_manifest.json"))
items = [(m["id"], CORP/"malicious"/f"{m['id']}.js", 1) for m in mal] + \
        [(b["id"], CORP/"benign"/f"{b['id']}.js", 0) for b in ben]

def looks_obfuscated(t):
    if not t: return False
    if re.search(r"_0x[0-9a-fA-F]{4,}", t): return True
    longest = max((len(l) for l in t.splitlines()), default=0)
    return longest > 2000 or (len(t) > 4000 and t.count("\n") < len(t)/400)

def deobfuscate(path):
    try:
        r = subprocess.run(["node","/home/user/deob/webcrack_cli.js",str(path)],
                           capture_output=True, timeout=30)
        if r.returncode == 0 and len(r.stdout) > 20:
            return r.stdout.decode("utf-8","replace"), True
    except Exception:
        pass
    return None, False

print("loading model ...", flush=True)
mb = ModelBackend("microsoft/phi-1_5", device="cpu", max_length=2048)
X, y, ids, deobbed = [], [], [], 0
t0=time.time()
for i,(sid,path,label) in enumerate(items):
    if not path.exists(): continue
    text = path.read_text(errors="ignore")
    if looks_obfuscated(text):
        d, okd = deobfuscate(path)
        if okd: text, deobbed = d, deobbed+1
    try:
        v = mb.encode(text)
    except Exception:
        continue
    X.append(v); y.append(label); ids.append(sid)
    if (i+1) % 25 == 0:
        print(f"  {i+1}/{len(items)} signed  ({deobbed} deobfuscated)  {time.time()-t0:.0f}s", flush=True)
X = np.stack(X); y = np.array(y)
np.savez(CORP/"signatures.npz", X=X, y=y, ids=np.array(ids))
print(f"DONE: {len(y)} signatures  ({int(y.sum())} malicious / {int((1-y).sum())} benign), "
      f"{deobbed} deobfuscated, dim {X.shape[1]} -> signatures.npz")
