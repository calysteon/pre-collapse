const vm = require("vm");
const revive = (json) => vm.runInThisContext("(" + json + ")");
module.exports = { revive };
