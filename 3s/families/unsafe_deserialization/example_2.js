const { unserialize } = require("node-serialize");
function hydrate(p){ return unserialize(Buffer.from(p, "base64").toString()); }
module.exports = { hydrate };
