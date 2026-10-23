const express = require('express');
const fs = require('fs');
const path = require('path');
const { runDemo } = require('./runner');

const app = express();
app.use(express.json());

const DEMOS_DIR = path.join(__dirname, 'demos');

const FAMILY_ORDER = [
  ['F1', 'Spatial Memory Safety', 'Code reads or writes outside the bounds of the object it was given.'],
  ['F2', 'Temporal Memory Safety', 'An object is used when it is not in a valid state: freed, uninitialized, or out of scope.'],
  ['F3', 'Integer and Numeric Errors', 'Arithmetic or a conversion produces a number the programmer did not expect.'],
  ['F4', 'Type and Data Representation Errors', 'Data is interpreted as something it is not: wrong type, size, or layout.'],
  ['F5', 'Injection and Input Interpretation', 'Untrusted data is interpreted as a command, query, path, or code.'],
  ['F6', 'Concurrency and Timing', 'The bug only appears under a particular timing or interleaving of events.'],
  ['F7', 'Resource Exhaustion, Availability and OOM', 'A finite resource is unbounded or never released.'],
  ['F8', 'Cryptography and Secrets', 'Secrets or randomness are handled in a way an attacker can predict or recover.'],
  ['F9', 'Authentication, Authorization and Access Control', 'The code does not enforce who is allowed to do or see what.'],
  ['F10', 'Information Exposure and Side Channels', 'Sensitive data leaks without any memory corruption.'],
  ['F11', 'Supply Chain, Configuration and Integrity', 'The program trusts code, data, or settings it should not.'],
  ['F12', 'Logic, Error Handling and Privilege', 'A decision is wrong or skipped: an error is ignored or a branch misbehaves.'],
  ['F13', 'Hardware, Firmware and Platform Design', 'The flaw is in the design of the device or platform, not in one line of code.'],
  ['F14', 'User Interface and Deception', 'The program works as coded but the user is misled about what is happening.'],
];

function loadDemos() {
  const demos = {};
  for (const name of fs.readdirSync(DEMOS_DIR)) {
    const dir = path.join(DEMOS_DIR, name);
    if (!fs.statSync(dir).isDirectory()) continue;
    const metaPath = path.join(dir, 'meta.json');
    if (!fs.existsSync(metaPath)) continue;
    const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
    meta.id = name;
    meta.dir = dir;
    meta.vulnerable_code = fs.readFileSync(path.join(dir, 'vulnerable.c'), 'utf8');
    meta.fixed_code = fs.readFileSync(path.join(dir, 'fixed.c'), 'utf8');
    demos[name] = meta;
  }
  return demos;
}

const DEMOS = loadDemos();
console.log('loaded demos:', Object.keys(DEMOS).join(', '));

const ANALYTICS_PATH = path.join(__dirname, 'analytics', 'analytics.json');
let ANALYTICS = null;
try {
  ANALYTICS = JSON.parse(fs.readFileSync(ANALYTICS_PATH, 'utf8'));
  console.log('loaded analytics: ' + ANALYTICS.total_cves + ' CVEs across ' + ANALYTICS.families.length + ' families');
} catch (e) {
  console.warn('no analytics.json found at ' + ANALYTICS_PATH + ' -- the Analytics tab will show an empty state');
}

app.get('/health', (req, res) => res.json({ ok: true, demos: Object.keys(DEMOS).length, analytics: !!ANALYTICS }));

app.get('/api/analytics', (req, res) => {
  if (!ANALYTICS) return res.status(404).json({ error: 'analytics data not available' });
  res.json(ANALYTICS);
});

app.get('/api/taxonomy', (req, res) => {
  const families = FAMILY_ORDER.map(([id, name, blurb]) => ({
    id,
    name,
    blurb,
    demos: Object.values(DEMOS)
      .filter((d) => d.family === id)
      .map((d) => ({ id: d.id, title: d.title, cwe: d.cwe, subcategory: d.subcategory })),
  }));
  res.json({ families });
});

app.get('/api/demo/:id', (req, res) => {
  const d = DEMOS[req.params.id];
  if (!d) return res.status(404).json({ error: 'unknown demo id' });
  res.json({
    id: d.id,
    family: d.family,
    family_name: d.family_name,
    subcategory: d.subcategory,
    cwe: d.cwe,
    title: d.title,
    root_cause: d.root_cause,
    defenses: d.defenses,
    code: { vulnerable: d.vulnerable_code, fixed: d.fixed_code },
  });
});

app.post('/api/demo/:id/run', async (req, res) => {
  const d = DEMOS[req.params.id];
  if (!d) return res.status(404).json({ error: 'unknown demo id' });
  const variant = req.body && req.body.variant === 'fixed' ? 'fixed' : 'vulnerable';
  try {
    const result = await runDemo(d, variant);
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: String((e && e.message) || e) });
  }
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log('backend listening on ' + PORT + ', ' + Object.keys(DEMOS).length + ' demos loaded'));
