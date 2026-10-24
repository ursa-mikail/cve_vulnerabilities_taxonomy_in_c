const fs = require('fs');
const os = require('os');
const path = require('path');

// A tiny "static file server" whose web root sits next to a secret.
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'site-'));
const PUBLIC = path.join(root, 'public');
fs.mkdirSync(PUBLIC);
fs.writeFileSync(path.join(PUBLIC, 'hello.txt'), 'Hello, public visitor.\n');
fs.writeFileSync(path.join(root, 'secret.txt'), 'DB_PASSWORD=hunter2 (never meant for the web)\n');

function serve(requested) {
  const file = path.join(PUBLIC, requested); // VULNERABLE (CWE-22): '..' segments climb out of PUBLIC
  return fs.readFileSync(file, 'utf8');
}

console.log('[demo] GET /hello.txt        ->', JSON.stringify(serve('hello.txt')));
const attack = '../secret.txt';
console.log(`[demo] GET /${attack}     ->`, JSON.stringify(serve(attack)));
if (serve(attack).includes('DB_PASSWORD')) {
  console.log('\n[ATTACK SUCCEEDED] a request for a "public" file returned a file outside the web root.');
}
