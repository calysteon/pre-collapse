function bounce(ctx){ ctx.status = 302; ctx.set("Location", ctx.query.returnTo); }
module.exports = { bounce };
