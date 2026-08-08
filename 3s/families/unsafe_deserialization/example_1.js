const serialize = require("node-serialize");
const restore = (s) => serialize.unserialize(s);
module.exports = { restore };
