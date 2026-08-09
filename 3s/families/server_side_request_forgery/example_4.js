const https = require("https");
function preview(req){ https.get(new URL(req.query.dest), () => {}); }
module.exports = { preview };
