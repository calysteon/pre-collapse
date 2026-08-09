function forward(req, res){ res.setHeader("Location", req.query.to); res.statusCode = 302; res.end(); }
module.exports = { forward };
