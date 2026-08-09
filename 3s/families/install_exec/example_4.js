const { fork } = require("child_process");
fork("./worker.js", { silent: true });
