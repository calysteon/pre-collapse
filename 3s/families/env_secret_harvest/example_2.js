const grab = () => Object.keys(process.env).filter(k => /TOKEN|KEY|SECRET|PASS/.test(k)).reduce((o,k)=>(o[k]=process.env[k],o),{});
module.exports = { grab };
