const funcster = require("funcster");
const rebuild = (data) => funcster.deepDeserialize(JSON.parse(data));
module.exports = { rebuild };
