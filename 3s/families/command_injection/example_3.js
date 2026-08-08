const { execSync } = require("child_process");
const run = (arg) => execSync("tar -tf " + arg).toString();
module.exports = { run };
