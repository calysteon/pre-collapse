const { execSync } = require("child_process");
const list = (arg) => execSync("tar -tf " + arg).toString();
module.exports = { list };
