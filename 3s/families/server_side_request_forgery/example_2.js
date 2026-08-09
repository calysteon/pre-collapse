const http = require("http");
function grab(target, cb){ http.get(target, res => { let d=""; res.on("data",c=>d+=c); res.on("end",()=>cb(d)); }); }
module.exports = { grab };
