const vm = require("vm");
const evalCtx = (code) => vm.runInNewContext(code);
module.exports = { evalCtx };
