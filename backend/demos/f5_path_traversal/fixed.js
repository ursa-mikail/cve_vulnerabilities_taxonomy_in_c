const fs = require('fs');
const os = require('os');
const path = require('path');

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'site-'));
const PUBLIC_RAW = path.join(root, 'public');
fs.mkdirSync(PUBLIC_RAW);
const PUBLIC = fs.realpathSync(PUBLIC_RAW);
fs.writeFileSync(path.join(PUBLIC, 'hello.txt'), 'Hello, public visitor.\n');
fs.writeFileSync(path.join(root, 'secret.txt'), 'DB_PASSWORD=hunter2 (never meant for the web)\n');

function serve(requested) {
  // FIXED: resolve to a canonical absolute path FIRST, then require it to stay inside the root.
  const file = fs.realpathSync(path.resolve(PUBLIC, requested));
  if (file !== PUBLIC && !file.startsWith(PUBLIC + path.sep)) {
    throw new Error('path escapes the web root');
  }
  return fs.readFileSync(file, 'utf8');
}

console.log('[demo] GET /hello.txt        ->', JSON.stringify(serve('hello.txt')));
const attack = '../secret.txt';
try {
  serve(attack);
} catch (e) {
  console.log(`[demo] GET /${attack}     -> refused (${e.message})`);
  console.log('\n[BLOCKED] the canonical path left the web root, so the file was never opened.');
}
