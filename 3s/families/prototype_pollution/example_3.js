function extend(dst, src){ Object.keys(src).forEach(k => { if(src[k] && typeof src[k]==="object") extend(dst[k]=dst[k]||{}, src[k]); else dst[k]=src[k]; }); return dst; }
module.exports = { extend };
