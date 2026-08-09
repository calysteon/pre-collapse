const { spawn } = require("child_process");
function convert(file){ spawn("sh", ["-c", "convert " + file + " out.png"]); }
module.exports = { convert };
