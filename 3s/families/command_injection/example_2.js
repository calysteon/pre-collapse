const cp = require("child_process");
function lookup(target){ cp.exec(`nslookup ${target}`, (err,stdout)=>process.stdout.write(stdout)); }
module.exports = { lookup };
