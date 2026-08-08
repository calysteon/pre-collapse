const { readFile } = require("fs/promises");
const load = async (p) => readFile(`./public/${p}`);
module.exports = { load };
