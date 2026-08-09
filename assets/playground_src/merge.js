function deepMerge(target, source) {
  for (const k in source) {
    if (typeof source[k] === 'object') {
      if (!target[k]) target[k] = {};
      deepMerge(target[k], source[k]);   // no guard on __proto__
    } else {
      target[k] = source[k];
    }
  }
  return target;
}
module.exports = deepMerge;
