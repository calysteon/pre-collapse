const STRIPE_SECRET = "sk_live_REDACTED_EXAMPLE_KEY";
function client(){ return { key: STRIPE_SECRET }; }
module.exports = { client };
