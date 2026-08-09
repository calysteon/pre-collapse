function apply(target, patch){ Object.entries(patch).forEach(([k,v]) => { if(v && typeof v === "object") apply(target[k] = target[k]||{}, v); else target[k] = v; }); }
module.exports = { apply };
