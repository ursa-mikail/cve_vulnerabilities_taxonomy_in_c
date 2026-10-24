// Self-test: every demo must really misbehave in its vulnerable version and really behave in its fixed version.
//   node test_demos.js            (run from backend/; needs gcc for the C demos, node, python3)
const fs = require('fs');
const path = require('path');
const { runDemo, LANGUAGES } = require('./runner');

const DIR = path.join(__dirname, 'demos');
const taxonomy = JSON.parse(fs.readFileSync(path.join(__dirname, 'taxonomy.json'), 'utf8'));
const analyticsPath = path.join(__dirname, 'analytics', 'analytics.json');
const analytics = fs.existsSync(analyticsPath) ? JSON.parse(fs.readFileSync(analyticsPath, 'utf8')) : null;
const REQUIRED = ['family', 'family_name', 'language', 'subcategory', 'csv_subcategory', 'cwe', 'title', 'root_cause', 'defenses', 'expect'];

(async () => {
  let failures = 0;
  const fail = (msg) => { failures++; console.log('  FAIL  ' + msg); };
  const famIds = new Set(taxonomy.families.map((f) => f.id));
  const covered = new Set();
  const subcats = new Set();
  if (analytics) analytics.coverage.forEach((c) => c.subcategories.forEach((s) => subcats.add(c.family + '|' + s.name)));

  for (const id of fs.readdirSync(DIR).sort()) {
    const dir = path.join(DIR, id);
    if (!fs.statSync(dir).isDirectory()) continue;
    const meta = JSON.parse(fs.readFileSync(path.join(dir, 'meta.json'), 'utf8'));
    meta.id = id; meta.dir = dir;
    console.log(id + '  [' + meta.language + ', ' + meta.family + ', ' + meta.cwe + ']');
    for (const k of REQUIRED) if (meta[k] === undefined) fail('meta.json is missing "' + k + '"');
    if (!famIds.has(meta.family)) fail('unknown family ' + meta.family);
    if (!LANGUAGES[meta.language]) fail('unsupported language ' + meta.language);
    if (analytics && !subcats.has(meta.family + '|' + meta.csv_subcategory)) fail('csv_subcategory "' + meta.csv_subcategory + '" does not exist in the CVE data for ' + meta.family);
    covered.add(meta.family);

    const v = await runDemo(meta, 'vulnerable');
    const f = await runDemo(meta, 'fixed');
    const ev = meta.expect.vulnerable, ef = meta.expect.fixed;
    const vulnOk = ev === 'SANITIZER' ? !!v.sanitizerIssue : ev === 'VERDICT' ? v.verdict === 'exploited' : new RegExp(ev, 'm').test(v.stdout);
    if (!vulnOk) fail('vulnerable version did not show the bug (expected ' + ev + ')');
    if (v.timedOut) fail('vulnerable version timed out');
    if (f.sanitizerIssue) fail('fixed version still trips ' + f.sanitizerIssue);
    if (f.verdict === 'exploited') fail('fixed version reports ATTACK SUCCEEDED');
    const fixOk = ef === 'VERDICT' ? f.verdict === 'blocked' : new RegExp(ef, 'm').test(f.stdout + f.stderr);
    if (!fixOk) fail('fixed version did not show the fix (expected ' + ef + ')');
    if (f.timedOut) fail('fixed version timed out');
    console.log('  vulnerable: ' + (vulnOk ? 'ok' : 'BAD') + ' (' + v.durationMs + ' ms)   fixed: ' + (fixOk ? 'ok' : 'BAD') + ' (' + f.durationMs + ' ms)');
  }
  for (const id of famIds) if (!covered.has(id)) fail('family ' + id + ' has no demo');
  console.log(failures ? '\n' + failures + ' FAILURE(S)' : '\nALL DEMOS BEHAVE AS DOCUMENTED');
  process.exit(failures ? 1 : 0);
})();
