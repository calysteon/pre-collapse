const crypto = require("crypto");
const hash = (p) => crypto.createHash("md5").update(p).digest("hex");
module.exports = { hash };
