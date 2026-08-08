import json, hashlib, subprocess, random
from pathlib import Path

OUT = Path("/home/user/corpus/hard_benign"); OUT.mkdir(parents=True, exist_ok=True)
random.seed(7)
# diverse topics so we sample broadly across the long tail, not one niche
KW = ["parser","stream","color","math","date","logger","format","config","random",
      "string","array","file","queue","cache","ascii","terminal","markdown","csv",
      "yaml","time","geo","unit","hash","tree","emoji","slug","retry","throttle",
      "sort","diff","escape","token","pad","range","clamp","uuid","enum","matrix"]
existing = set()
for mf in ("/home/user/corpus/benign_manifest.json",):
    try: existing = {b["package"] for b in json.load(open(mf))}
    except Exception: pass

def search(kw, frm):
    try:
        r = subprocess.run(["curl","-sS","--max-time","20",
            f"https://registry.npmjs.org/-/v1/search?text={kw}&size=20&from={frm}"],
            capture_output=True, timeout=25)
        d = json.loads(r.stdout.decode("utf-8","replace"))
        out=[]
        for o in d.get("objects",[]):
            pop = o.get("score",{}).get("detail",{}).get("popularity",1.0)
            name = o["package"]["name"]
            if name not in existing:      # mid/long-tail only
                out.append(name)
        return out
    except Exception:
        return []

cands=[]
for kw in KW:
    cands += search(kw, random.choice([250,350,450,600]))
cands = list(dict.fromkeys(cands))   # dedup, keep order
random.shuffle(cands)
print("candidate obscure packages:", len(cands))

def fetch(pkg):
    try:
        r = subprocess.run(["curl","-sSL","--max-time","20", f"https://unpkg.com/{pkg}"],
                           capture_output=True, timeout=25)
        t = r.stdout.decode("utf-8","replace")
        if len(t) < 40 or len(t) > 30000: return None       # small, to match malicious size
        if "Cannot find" in t[:200] or "<!DOCTYPE" in t[:200]: return None
        return t
    except Exception: return None

manifest, ok = [], 0
for pkg in cands:
    if ok >= 180: break
    t = fetch(pkg)
    if not t: continue
    sid = hashlib.sha1(("hardbenign:"+pkg).encode()).hexdigest()[:12]
    (OUT/f"{sid}.js").write_text(t[:200000])
    manifest.append({"id":sid,"label":"benign","package":pkg,"bytes":len(t)})
    ok += 1
json.dump(manifest, open("/home/user/corpus/hard_benign_manifest.json","w"), indent=1)
import statistics as s
print(f"fetched {ok} hard-benign; median bytes {int(s.median([m['bytes'] for m in manifest])) if manifest else 0}")
