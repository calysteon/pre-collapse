const request = require("request");
const mirror = (userUrl, cb) => request(userUrl, (e, r, body) => cb(body));
module.exports = { mirror };
