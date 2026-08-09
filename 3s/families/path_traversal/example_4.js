const fs = require("fs");
const stream = (req) => fs.createReadStream("files/" + req.query.name);
module.exports = { stream };
