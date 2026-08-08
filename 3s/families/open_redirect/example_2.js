const go = (req, res) => res.redirect(req.query.url);
module.exports = { go };
