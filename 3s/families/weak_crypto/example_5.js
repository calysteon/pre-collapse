const crypto = require("crypto");
const legacy = (data, pass) => { const c = crypto.createCipher("aes-128-ecb", pass); return c.update(data,"utf8","hex") + c.final("hex"); };
module.exports = { legacy };
