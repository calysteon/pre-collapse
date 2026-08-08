const fetch = require("node-fetch");
const proxy = async (url) => { const r = await fetch(url); return r.text(); };
module.exports = { proxy };
