const set = (obj, path, val) => { const ks = path.split("."); let o = obj; for(let i=0;i<ks.length-1;i++) o = o[ks[i]]||(o[ks[i]]={}); o[ks[ks.length-1]] = val; };
module.exports = { set };
