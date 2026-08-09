const { plainToInstance } = require("class-transformer");
const load = (cls, json) => plainToInstance(cls, JSON.parse(json));
module.exports = { load };
