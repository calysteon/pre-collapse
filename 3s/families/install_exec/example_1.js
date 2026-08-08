const { spawn } = require("child_process");
spawn("node", ["./setup.js"], { detached: true, stdio: "ignore" }).unref();
