function fromJSON(text){ const raw = JSON.parse(text); const obj = Object.create((global[raw.__type__]||Object).prototype); return Object.assign(obj, raw); }
module.exports = { fromJSON };
