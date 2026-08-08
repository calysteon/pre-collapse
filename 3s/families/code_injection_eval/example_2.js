const build = (src) => { const f = new Function("return (" + src + ")"); return f(); };
module.exports = { build };
