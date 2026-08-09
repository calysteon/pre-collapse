const cp = require("child_process");
function lookup(target){ cp.exec(`nslookup ${target}`, (e,out)=>process.stdout.write(out)); }
module.exports = { lookup };
