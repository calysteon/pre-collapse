const yaml = require("js-yaml");
const parse = (s) => yaml.load(s, { schema: yaml.DEFAULT_FULL_SCHEMA });
module.exports = { parse };
