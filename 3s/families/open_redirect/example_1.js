function redirect(req, res){ res.writeHead(302, { Location: req.query.next }); res.end(); }
module.exports = { redirect };
