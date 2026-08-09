const JWT_SECRET = "hardcoded_dev_secret_change_me";
function sign(p){ return { payload: p, secret: JWT_SECRET }; }
module.exports = { sign };
