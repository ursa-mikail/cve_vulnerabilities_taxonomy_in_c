// Live faceted filtering over the fact table built by tools/build_facets.py.
// One pass over ~394k rows per query (tens of milliseconds); every combination of filters is exact,
// nothing is pre-aggregated per pair.
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const DIR = path.join(__dirname, 'analytics');
const TYPES = { uint8: Uint8Array, uint16: Uint16Array, uint32: Uint32Array };

function load() {
  const metaPath = path.join(DIR, 'facets.meta.json');
  const binPath = path.join(DIR, 'facets.bin.gz');
  if (!fs.existsSync(metaPath) || !fs.existsSync(binPath)) return null;
  const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
  const raw = zlib.gunzipSync(fs.readFileSync(binPath));
  const buf = raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength); // aligned copy
  const col = {};
  for (const c of meta.layout) col[c.name] = new TYPES[c.dtype](buf, c.offset, c.length);
  return { meta, col };
}

const DATA = load();
const SEV_MIN = { any: 0, low: 1, medium: 2, high: 3, critical: 4 };
const CONF_MIN = { any: 0, medium: 2, high: 3 };

function maskFor(dim, keys) {
  const defs = DATA.meta.facets[dim].values;
  let m = 0;
  for (const k of keys) {
    const d = defs.find((v) => v.key === k);
    if (!d) throw new Error(`unknown ${dim} value "${k}"`);
    m |= 1 << d.bit;
  }
  return m;
}

function topN(counts, n, labeler) {
  const out = [];
  for (let i = 0; i < counts.length; i++) if (counts[i] > 0) out.push([i, counts[i]]);
  out.sort((a, b) => b[1] - a[1]);
  return out.slice(0, n).map(([i, c]) => ({ ...labeler(i), count: c }));
}

function query(p) {
  if (!DATA) throw new Error('facet data not available');
  const { meta, col } = DATA;
  const n = meta.rows;
  const osM = maskFor('os', p.os || []);
  const langM = maskFor('lang', p.lang || []);
  const sysM = maskFor('system', p.system || []);
  let famM = 0;
  for (const f of p.family || []) {
    const ix = meta.families.indexOf(f);
    if (ix < 0) throw new Error(`unknown family "${f}"`);
    famM |= 1 << ix;
  }
  const from = p.from || 0, to = p.to || 9999;
  const sevMin = SEV_MIN[p.sev || 'any'], confMin = CONF_MIN[p.evidence || 'any'];
  if (sevMin === undefined || confMin === undefined) throw new Error('bad sev or evidence value');

  const nFam = meta.families.length, nSub = meta.subcategories.length, nCwe = meta.cwes.length, nV = meta.vendors.length;
  const y0 = 1999, nY = 2030 - y0;
  const famC = new Uint32Array(nFam), subC = new Uint32Array(nSub), cweC = new Uint32Array(nCwe);
  const vendC = new Uint32Array(nV), yearC = new Uint32Array(nY), sevC = new Uint32Array(5), confC = new Uint32Array(4);
  const osF = new Uint32Array(16), langF = new Uint32Array(16), sysF = new Uint32Array(16), famF = new Uint32Array(nFam);
  const best = []; // 6 rows with the smallest hash: a stable, unbiased sample
  let matched = 0, base = 0;

  const { fam, sub, cwe, year, num, sev, conf, os, lang, system, vendor } = col;
  for (let i = 0; i < n; i++) {
    const yv = year[i];
    if (yv < from || yv > to || sev[i] < sevMin || conf[i] < confMin) continue;
    base++;
    const okO = osM === 0 || (os[i] & osM) !== 0;
    const okL = langM === 0 || (lang[i] & langM) !== 0;
    const okS = sysM === 0 || (system[i] & sysM) !== 0;
    const okF = famM === 0 || ((1 << fam[i]) & famM) !== 0;
    // faceted counts: each dimension is counted under every OTHER active filter, so chips show what
    // clicking them would give, and selecting one value does not hide its siblings.
    if (okL && okS && okF) { let m = os[i]; for (let b = 0; m; b++, m >>= 1) if (m & 1) osF[b]++; }
    if (okO && okS && okF) { let m = lang[i]; for (let b = 0; m; b++, m >>= 1) if (m & 1) langF[b]++; }
    if (okO && okL && okF) { let m = system[i]; for (let b = 0; m; b++, m >>= 1) if (m & 1) sysF[b]++; }
    if (okO && okL && okS) famF[fam[i]]++;
    if (!(okO && okL && okS && okF)) continue;
    matched++;
    famC[fam[i]]++; subC[sub[i]]++; cweC[cwe[i]]++; vendC[vendor[i]]++;
    yearC[yv - y0]++; sevC[sev[i]]++; confC[conf[i]]++;
    const h = Math.imul(i + 1, 2654435761) >>> 0;
    if (best.length < 6 || h < best[best.length - 1][0]) {
      best.push([h, i]); best.sort((a, b) => a[0] - b[0]); if (best.length > 6) best.pop();
    }
  }

  const byKey = (dim, arr) => Object.fromEntries(meta.facets[dim].values.map((v) => [v.key, arr[v.bit]]));
  const sevNames = ['none', 'low', 'medium', 'high', 'critical'];
  const confNames = ['unclassified', 'low', 'medium', 'high'];
  return {
    matched, in_scope: base, total: n,
    facet_counts: { os: byKey('os', osF), lang: byKey('lang', langF), system: byKey('system', sysF),
                    family: Object.fromEntries(meta.families.map((f, i) => [f, famF[i]])) },
    by_family: meta.families.map((f, i) => ({ id: f, name: meta.family_names[f], count: famC[i] })),
    top_subcategories: topN(subC, 12, (i) => ({ family: meta.subcategories[i].family, name: meta.subcategories[i].name })),
    top_cwes: topN(cweC.map((c, i) => (i === 0 ? 0 : c)), 10, (i) => ({ cwe: meta.cwes[i].id, name: meta.cwes[i].name })),
    no_cwe: cweC[0],
    by_year: Array.from(yearC).map((c, i) => ({ year: y0 + i, count: c })).filter((r) => r.year >= 1999 && r.year <= 2026),
    severity: Object.fromEntries(sevNames.map((s, i) => [s, sevC[i]])),
    evidence: Object.fromEntries(confNames.map((s, i) => [s, confC[i]])),
    top_vendors: topN(vendC.map((c, i) => (i === 0 ? 0 : c)), 10, (i) => ({ name: meta.vendors[i] })),
    examples: best.map(([, i]) => {
      const id = `CVE-${year[i]}-${String(num[i]).padStart(4, '0')}`;
      return { id, family: meta.families[fam[i]], subcategory: meta.subcategories[sub[i]].name,
               cwe: meta.cwes[cwe[i]].id || null, severity: sevNames[sev[i]], url: `https://nvd.nist.gov/vuln/detail/${id}` };
    }),
  };
}

function describe() {
  if (!DATA) return null;
  const { meta } = DATA;
  return { rows: meta.rows, method: meta.method, facets: meta.facets, families: meta.families, family_names: meta.family_names };
}

module.exports = { available: !!DATA, query, describe };
