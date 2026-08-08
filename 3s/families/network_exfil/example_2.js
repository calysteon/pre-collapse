const fetch = require("node-fetch");
const send = async (d) => fetch("https://telemetry.example/x", { method: "POST", body: JSON.stringify(d) });
module.exports = { send };
