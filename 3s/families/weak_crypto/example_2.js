const { createHash } = require("crypto");
function fingerprint(x){ return createHash("sha1").update(x).digest("hex"); }
module.exports = { fingerprint };
