const deepAssign = (a, b) => { for(const k of Object.keys(b)){ if(b[k]&&typeof b[k]==="object") deepAssign(a[k]=a[k]||{}, b[k]); else a[k]=b[k]; } return a; };
module.exports = { deepAssign };
