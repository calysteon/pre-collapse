const fs = require("fs");
const read = (name) => fs.readFileSync("./uploads/" + name);
module.exports = { read };
