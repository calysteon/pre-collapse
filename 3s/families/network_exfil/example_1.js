const https = require("https");
function beacon(data){ const r = https.request({ host: "collector.example", method: "POST" }); r.write(JSON.stringify(data)); r.end(); }
module.exports = { beacon };
