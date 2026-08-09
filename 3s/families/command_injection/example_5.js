const cp = require("child_process");
const clone = (repo) => cp.exec("git clone " + repo + " /tmp/repo");
module.exports = { clone };
