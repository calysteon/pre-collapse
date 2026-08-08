function merge(t, s){ for(const k in s){ if(typeof s[k]==="object") merge(t[k]||(t[k]={}), s[k]); else t[k]=s[k]; } return t; }
module.exports = { merge };
