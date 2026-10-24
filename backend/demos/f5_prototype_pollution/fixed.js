const FORBIDDEN = new Set(['__proto__', 'constructor', 'prototype']);

function merge(target, source) {
  for (const key of Object.keys(source)) {        // own, enumerable keys only
    if (FORBIDDEN.has(key)) continue;             // FIXED: never walk into the prototype chain
    const value = source[key];
    if (typeof value === 'object' && value !== null) {
      if (!Object.hasOwn(target, key) || typeof target[key] !== 'object') target[key] = {};
      merge(target[key], value);
    } else {
      target[key] = value;
    }
  }
  return target;
}

const defaults = { theme: 'light' };
const fromClient = JSON.parse('{"theme": "dark", "__proto__": {"isAdmin": true}}');

merge(defaults, fromClient);

const anotherUser = {};
console.log('[demo] defaults after merge     =', JSON.stringify(defaults));
console.log('[demo] anotherUser.isAdmin      =', anotherUser.isAdmin);
if (anotherUser.isAdmin === undefined) {
  console.log('\n[BLOCKED] the legitimate key was merged; the "__proto__" key was skipped, so no shared object changed.');
}
