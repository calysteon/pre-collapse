const crypto = require("crypto");
const enc = (t, k) => { const c = crypto.createCipheriv("des-ecb", k, null); return c.update(t,"utf8","hex") + c.final("hex"); };
module.exports = { enc };
