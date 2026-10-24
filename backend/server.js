const express = require('express');
const fs = require('fs');
const path = require('path');
const { runDemo, LANGUAGES, sourceFile } = require('./runner');
const facets = require('./facets');

const app = express();
app.use(express.json());

const DEMOS_DIR = path.join(__dirname, 'demos');
const TAXONOMY = JSON.parse(fs.readFileSync(path.join(__dirname, 'taxonomy.json'), 'utf8'));

function loadDemos() {
  const demos = {};
  for (const name of fs.readdirSync(DEMOS_DIR).sort()) {
    const dir = path.join(DEMOS_DIR, name);
    if (!fs.statSync(dir).isDirectory()) continue;
    const metaPath = path.join(dir, 'meta.json');
    if (!fs.existsSync(metaPath)) continue;
    const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
    meta.id = name;
    meta.dir = dir;
    meta.language = meta.language || 'c';
    if (!LANGUAGES[meta.language]) {
      console.warn('skipping demo ' + name + ': unsupported language ' + meta.language);
      continue;
    }
    meta.language_label = LANGUAGES[meta.language].label;
    meta.vulnerable_code = fs.readFileSync(sourceFile(meta, 'vulnerable'), 'utf8');
    meta.fixed_code = fs.readFileSync(sourceFile(meta, 'fixed'), 'utf8');
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
  console.log('loaded analytics: ' + ANALYTICS.total_cves + ' CVEs across ' + ANALYTICS.families.length + ' buckets (mapping ' + ANALYTICS.mapping_version + ')');
} catch (e) {
  console.warn('no analytics.json found at ' + ANALYTICS_PATH + ' -- the Analytics tab will show an empty state');
}
console.log('facet filter: ' + (facets.available ? 'ready' : 'NOT available (run tools/build_facets.py)'));

const demoBrief = (d) => ({ id: d.id, title: d.title, cwe: d.cwe, subcategory: d.subcategory, language: d.language, language_label: d.language_label });
const demosFor = (family, csvSub) =>
  Object.values(DEMOS).filter((d) => d.family === family && d.csv_subcategory === csvSub).map(demoBrief);

app.get('/health', (req, res) =>
  res.json({ ok: true, demos: Object.keys(DEMOS).length, analytics: !!ANALYTICS, filter: facets.available }));

app.get('/api/analytics', (req, res) => {
  if (!ANALYTICS) return res.status(404).json({ error: 'analytics data not available' });
  // the coverage tables are served separately (merged with the demo registry), keep this payload lean
  const { coverage, mapping_basis, ...rest } = ANALYTICS;
  res.json(rest);
});

app.get('/api/taxonomy', (req, res) => {
  const families = TAXONOMY.families.map((f) => ({
    id: f.id,
    name: f.name,
    blurb: f.blurb,
    shows_up_in: f.shows_up_in,
    anchors: f.anchors || [],
    demos: Object.values(DEMOS).filter((d) => d.family === f.id).map(demoBrief),
  }));
  res.json({
    title: TAXONOMY.title,
    scope: TAXONOMY.scope,
    families,
    cross_cutting: TAXONOMY.cross_cutting,
    cross_cutting_note: TAXONOMY.cross_cutting_note,
    cwe_pillars: TAXONOMY.cwe_pillars,
    cwe_pillars_note: TAXONOMY.cwe_pillars_note,
    languages: [...new Set(Object.values(DEMOS).map((d) => d.language_label))],
  });
});

// "Are we missing anything?" -- every subcategory seen in the CVE data, whether a runnable demo covers it,
// and how strong the evidence behind each count is.
app.get('/api/coverage', (req, res) => {
  if (!ANALYTICS) return res.status(404).json({ error: 'analytics data not available' });
  let classified = 0, withDemo = 0, subs = 0, subsWithDemo = 0;
  const families = ANALYTICS.coverage.map((c) => {
    const famMeta = TAXONOMY.families.find((f) => f.id === c.family);
    const rows = c.subcategories.map((s) => {
      const demos = demosFor(c.family, s.name);
      classified += s.count; subs++;
      if (demos.length) { withDemo += s.count; subsWithDemo++; }
      return { ...s, demos };
    });
    const famDemos = Object.values(DEMOS).filter((d) => d.family === c.family).length;
    return { family: c.family, name: famMeta ? famMeta.name : c.family, total: c.total, distinct_cwes: c.distinct_cwes,
             demos: famDemos, subcategories: rows,
             covered_share: c.total ? Math.round((1000 * rows.filter((r) => r.demos.length).reduce((a, r) => a + r.count, 0)) / c.total) / 10 : 0 };
  });
  res.json({
    mapping_version: ANALYTICS.mapping_version,
    totals: { classified, subcategories: subs, subcategories_with_demo: subsWithDemo, cves_in_subcategories_with_demo: withDemo,
              cve_share_with_demo: classified ? Math.round((1000 * withDemo) / classified) / 10 : 0,
              families: TAXONOMY.families.length, families_with_demo: families.filter((f) => f.demos > 0).length,
              demos: Object.keys(DEMOS).length },
    bookkeeping: { total: ANALYTICS.total_cves, unclassified: ANALYTICS.unclassified_cves, rejected: ANALYTICS.rejected_cves },
    mapping_basis: ANALYTICS.mapping_basis,
    families,
    cwe_pillars: TAXONOMY.cwe_pillars,
    cwe_pillars_note: TAXONOMY.cwe_pillars_note,
  });
});

app.get('/api/facets', (req, res) => {
  const d = facets.describe();
  if (!d) return res.status(404).json({ error: 'facet data not available' });
  res.json(d);
});

const list = (v) => (v ? String(v).split(',').map((s) => s.trim()).filter(Boolean) : []);
app.get('/api/filter', (req, res) => {
  if (!facets.available) return res.status(404).json({ error: 'facet data not available' });
  try {
    const q = req.query;
    const num = (v) => (v === undefined || v === '' ? undefined : parseInt(v, 10));
    const result = facets.query({
      os: list(q.os), lang: list(q.lang), system: list(q.system), family: list(q.family),
      from: num(q.from), to: num(q.to), sev: q.sev, evidence: q.evidence,
    });
    // attach runnable demos to the top subcategories so a filter leads straight to something to run
    result.top_subcategories = result.top_subcategories.map((s) => ({ ...s, demos: demosFor(s.family, s.name) }));
    const seen = new Set();
    result.related_demos = result.top_subcategories.flatMap((s) => s.demos).filter((d) => !seen.has(d.id) && seen.add(d.id));
    res.json(result);
  } catch (e) {
    res.status(400).json({ error: String((e && e.message) || e) });
  }
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
    language: d.language,
    language_label: d.language_label,
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
