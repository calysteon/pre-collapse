const fs = require("fs"), path = require("path");
function serve(f){ return fs.readFileSync(path.join("/var/data", f)); }
module.exports = { serve };
