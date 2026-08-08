const { unserialize } = require("node-serialize");
function hydrate(payload){ return unserialize(Buffer.from(payload, "base64").toString()); }
module.exports = { hydrate };
