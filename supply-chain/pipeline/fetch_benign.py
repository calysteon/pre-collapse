import json, hashlib, subprocess, time
from pathlib import Path

OUT = Path("/home/user/corpus/benign"); OUT.mkdir(parents=True, exist_ok=True)

# popular, widely-installed npm packages (genuinely benign)
PKGS = """lodash express react react-dom vue axios moment chalk debug commander
async request bluebird underscore jquery classnames prop-types redux rxjs
webpack babel-core eslint prettier typescript typescript-eslint jest mocha chai
sinon uuid dotenv cors body-parser mongoose sequelize pg mysql2 redis ioredis
node-fetch cross-env rimraf glob minimatch semver yargs inquirer ora
cli-progress colors ansi-styles strip-ansi wrap-ansi string-width figures
date-fns dayjs luxon numeral validator joi yup zod ajv qs query-string
form-data formidable multer nodemailer socket.io ws jsonwebtoken bcrypt
crypto-js node-forge helmet morgan winston pino bunyan log4js
handlebars ejs pug marked highlight.js prismjs cheerio jsdom puppeteer
playwright sharp jimp fs-extra chokidar nanoid shortid slugify pluralize
camelcase kebab-case lodash.merge lodash.get deepmerge immer lru-cache
p-limit p-queue p-retry delay ms bytes pretty-bytes filesize mime mime-types
content-type accepts negotiator on-finished destroy ee-first statuses
escape-html encodeurl cookie cookie-parser express-session connect-redis
passport passport-local jsonschema fast-json-stringify secure-json-parse""".split()

def fetch(pkg):
    # unpkg serves the package main file; -L follows the redirect to the resolved file
    try:
        r = subprocess.run(["curl","-sSL","--max-time","20", f"https://unpkg.com/{pkg}"],
                           capture_output=True, timeout=25)
        txt = r.stdout.decode("utf-8","replace")
        if len(txt) < 40 or "Cannot find" in txt[:200] or "<!DOCTYPE" in txt[:200]:
            return None
        return txt
    except Exception:
        return None

manifest, ok = [], 0
for pkg in PKGS:
    txt = fetch(pkg)
    if not txt: continue
    sid = hashlib.sha1(("benign:"+pkg).encode()).hexdigest()[:12]
    (OUT/f"{sid}.js").write_text(txt[:200000])
    manifest.append({"id":sid,"label":"benign","package":pkg,"bytes":len(txt)})
    ok += 1
json.dump(manifest, open("/home/user/corpus/benign_manifest.json","w"), indent=1)
print(f"fetched {ok} benign package main files -> {OUT}")
