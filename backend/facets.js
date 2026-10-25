// Live faceted filtering, autocomplete and CVE listing over the fact table built by tools/build_facets.py.
// One pass over ~394k rows per query (tens of milliseconds); every combination of filters is exact,
// nothing is pre-aggregated per pair. Descriptions are read on demand from gzip blocks so the process
// stays far below the container's memory limit.
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const DIR = path.join(__dirname, 'analytics');
const TYPES = { uint8: Uint8Array, uint16: Uint16Array, uint32: Uint32Array };
const SEV_NAMES = ['none', 'low', 'medium', 'high', 'critical'];
const CONF_NAMES = ['unclassified', 'low', 'medium', 'high'];
const SEV_BY_NAME = { none: 0, unscored: 0, low: 1, medium: 2, high: 3, critical: 4 };

function load() {
  const metaPath = path.join(DIR, 'facets.meta.json');
  const binPath = path.join(DIR, 'facets.bin.gz');
  if (!fs.existsSync(metaPath) || !fs.existsSync(binPath)) return null;
  const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
  const raw = zlib.gunzipSync(fs.readFileSync(binPath));
  const buf = raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength);
  const col = {};
  for (const c of meta.layout) col[c.name] = new TYPES[c.dtype](buf, c.offset, c.length);
  const blk = path.join(DIR, 'descriptions.blk');
  const idxFile = path.join(DIR, 'descriptions.idx');
  let desc = null;
  if (fs.existsSync(blk) && fs.existsSync(idxFile)) {
    const ib = fs.readFileSync(idxFile);
    desc = { fd: fs.openSync(blk, 'r'), idx: new Uint32Array(ib.buffer.slice(ib.byteOffset, ib.byteOffset + ib.byteLength)), cache: new Map() };
  }
  return { meta, col, desc };
}

const DATA = load();

// ---------- descriptions ----------
function readBlock(b, lower = false) {
  const d = DATA.desc, start = d.idx[b], len = d.idx[b + 1] - start, buf = Buffer.alloc(len);
  fs.readSync(d.fd, buf, 0, len, start);
  const text = zlib.gunzipSync(buf).toString('utf8');
  return (lower ? text.toLowerCase() : text).split('\x00');
}

function description(i) {
  if (!DATA || !DATA.desc) return '';
  const B = DATA.meta.desc.block, d = DATA.desc, b = Math.floor(i / B);
  let rows = d.cache.get(b);
  if (!rows) {
    rows = readBlock(b);
    d.cache.set(b, rows);
    if (d.cache.size > 160) d.cache.delete(d.cache.keys().next().value);   // small LRU
  }
  return rows[i - b * B] || '';
}

// Free-text search: every word (or "quoted phrase") must appear in the description, case-insensitive.
// The scan streams all blocks once (about a second); the per-row result is cached so paging and
// toggling other filters with the same text is instant.
const TEXT_CACHE = new Map();
function textHits(text) {
  const terms = [];
  const rx = /"([^"]+)"|(\S+)/g;
  let m;
  while ((m = rx.exec(String(text).slice(0, 200)))) terms.push((m[1] || m[2]).toLowerCase());
  if (!terms.length) return null;
  if (terms.length > 8) throw new Error('at most 8 search words');
  if (terms.every((t) => t.length < 2)) throw new Error('search text is too short');
  if (!DATA.desc) throw new Error('descriptions are not available');
  const key = terms.join('\u0001');
  if (TEXT_CACHE.has(key)) return TEXT_CACHE.get(key);
  const n = DATA.meta.rows, B = DATA.meta.desc.block, hit = new Uint8Array(n);
  for (let b = 0, nb = DATA.desc.idx.length - 1; b < nb; b++) {
    const rows = readBlock(b, true);
    for (let k = 0; k < rows.length; k++) {
      const low = rows[k];
      let ok = 1;
      for (const t of terms) if (!low.includes(t)) { ok = 0; break; }
      hit[b * B + k] = ok;
    }
  }
  TEXT_CACHE.set(key, hit);
  if (TEXT_CACHE.size > 6) TEXT_CACHE.delete(TEXT_CACHE.keys().next().value);
  return hit;
}

// ---------- helpers ----------
const cveId = (i) => `CVE-${DATA.col.year[i]}-${String(DATA.col.num[i]).padStart(4, '0')}`;

function maskFor(dim, keys) {
  const defs = DATA.meta.facets[dim].values;
  let m = 0;
  for (const k of keys) {
    const d = defs.find((v) => v.key === k);
    if (!d) throw new Error(`unknown ${dim} value "${k}"`);
    m |= 1 << d.bit;
  }
  return m >>> 0;
}

function selector(names, dict, what) {
  if (!names || !names.length) return null;
  const sel = new Uint8Array(dict.length);
  for (const n of names) {
    const ix = dict.indexOf(n);
    if (ix < 0) throw new Error(`unknown ${what} "${n}"`);
    sel[ix] = 1;
  }
  return sel;
}

function tally(arr, m) { for (let b = 0; m; b++, m >>>= 1) if (m & 1) arr[b]++; }

function topN(counts, n, labeler, skipZero = false) {
  const out = [];
  for (let i = skipZero ? 1 : 0; i < counts.length; i++) if (counts[i] > 0) out.push([i, counts[i]]);
  out.sort((a, b) => b[1] - a[1]);
  return out.slice(0, n).map(([i, c]) => ({ ...labeler(i), count: c }));
}

function rowObject(i, withDesc) {
  const { meta, col } = DATA;
  const fam = meta.families[col.fam[i]];
  const tags = [];
  for (const dim of ['os', 'lang', 'system', 'hardware', 'network', 'deploy', 'vector', 'impact']) {
    const m = col['d_' + dim][i];
    if (!m) continue;
    for (const v of meta.facets[dim].values) if (m & (1 << v.bit)) tags.push({ dim, label: v.label });
  }
  const id = cveId(i);
  return {
    id, year: col.year[i], family: fam, family_name: meta.family_names[fam],
    subcategory: meta.subcategories[col.sub[i]].name,
    cwe: meta.cwes[col.cwe[i]].id || null, cwe_name: meta.cwes[col.cwe[i]].name || null,
    severity: SEV_NAMES[col.sev[i]], evidence: CONF_NAMES[col.conf[i]],
    vendor: meta.vendors[col.vendor[i]] || null, product: meta.products[col.product[i]] || null,
    tags: tags.slice(0, 8), url: `https://nvd.nist.gov/vuln/detail/${id}`,
    ...(withDesc ? { description: description(i) } : {}),
  };
}

// ---------- the query ----------
function query(p) {
  if (!DATA) throw new Error('facet data not available');
  const { meta, col } = DATA;
  const n = meta.rows, dimKeys = meta.dim_order;

  const selMask = {}, active = [];
  for (const d of dimKeys) {
    const m = maskFor(d, (p.dims && p.dims[d]) || []);
    selMask[d] = m;
    if (m) active.push(d);
  }
  let famM = 0;
  for (const f of p.family || []) {
    const ix = meta.families.indexOf(f);
    if (ix < 0) throw new Error(`unknown family "${f}"`);
    famM |= 1 << ix;
  }
  const subDict = meta.subcategories.map((s) => `${s.family}|${s.name}`);
  const subSel = selector(p.sub, subDict, 'subcategory');
  const vendSel = selector(p.vendor, meta.vendors, 'vendor');
  const prodSel = selector(p.product, meta.products, 'product');
  const cweSel = selector(p.cwe, meta.cwes.map((c) => c.id), 'CWE');
  let cveKeys = null;
  if (p.cve && p.cve.length) {
    cveKeys = new Set();
    for (const id of p.cve) {
      const m = /^CVE-(\d{4})-(\d+)$/i.exec(id);
      if (!m) throw new Error(`bad CVE id "${id}"`);
      cveKeys.add(Number(m[1]) * 1e9 + Number(m[2]));
    }
  }
  let sevAllowed = 31;
  if (p.sevs && p.sevs.length) {
    sevAllowed = 0;
    for (const s of p.sevs) { if (!(s in SEV_BY_NAME)) throw new Error(`bad severity "${s}"`); sevAllowed |= 1 << SEV_BY_NAME[s]; }
  } else if (p.sev) {
    if (!(p.sev in SEV_BY_NAME)) throw new Error('bad severity');
    sevAllowed = 31 & ~((1 << SEV_BY_NAME[p.sev]) - 1);
  }
  const confMin = { any: 0, medium: 2, high: 3 }[p.evidence || 'any'];
  if (confMin === undefined) throw new Error('bad evidence value');
  const from = p.from || 0, to = p.to || 9999;
  const textHit = p.text ? textHits(p.text) : null;

  const nFam = meta.families.length, nSub = meta.subcategories.length, nCwe = meta.cwes.length;
  const famC = new Uint32Array(nFam), subC = new Uint32Array(nSub), cweC = new Uint32Array(nCwe);
  const vendC = new Uint32Array(meta.vendors.length), prodC = new Uint32Array(meta.products.length);
  const y0 = 1999, yearC = new Uint32Array(40), sevC = new Uint32Array(5), confC = new Uint32Array(4);
  const mc = {}, extra = {};
  for (const d of dimKeys) { mc[d] = new Uint32Array(32); extra[d] = new Uint32Array(32); }
  const famExtra = new Uint32Array(nFam);
  const matchedIdx = new Uint32Array(n);
  let matched = 0, base = 0;
  const cols = dimKeys.map((d) => col['d_' + d]);
  const dimIx = Object.fromEntries(dimKeys.map((d, k) => [d, k]));
  const actIx = active.map((d) => dimIx[d]), actMask = active.map((d) => selMask[d]);
  const { fam, sub, cwe, year, num, sev, conf, vendor, product } = col;

  for (let i = 0; i < n; i++) {
    const yv = year[i];
    if (yv < from || yv > to || !((sevAllowed >> sev[i]) & 1) || conf[i] < confMin) continue;
    if (vendSel && !vendSel[vendor[i]]) continue;
    if (prodSel && !prodSel[product[i]]) continue;
    if (cweSel && !cweSel[cwe[i]]) continue;
    if (subSel && !subSel[sub[i]]) continue;
    if (cveKeys && !cveKeys.has(yv * 1e9 + num[i])) continue;
    if (textHit && !textHit[i]) continue;
    base++;
    let fails = 0, failDim = -1;
    for (let k = 0; k < actIx.length; k++) {
      if ((cols[actIx[k]][i] & actMask[k]) === 0) { fails++; failDim = actIx[k]; if (fails > 1) break; }
    }
    let famFail = false;
    if (fails < 2 && famM !== 0 && !((1 << fam[i]) & famM)) { fails++; famFail = true; failDim = -1; }
    if (fails > 1) continue;
    if (fails === 1) {                                   // would match if this one filter were lifted
      if (famFail) famExtra[fam[i]]++; else tally(extra[dimKeys[failDim]], cols[failDim][i]);
      continue;
    }
    matchedIdx[matched++] = i;
    famC[fam[i]]++; subC[sub[i]]++; cweC[cwe[i]]++; vendC[vendor[i]]++; prodC[product[i]]++;
    yearC[yv - y0]++; sevC[sev[i]]++; confC[conf[i]]++;
    for (let k = 0; k < cols.length; k++) { const m = cols[k][i]; if (m) tally(mc[dimKeys[k]], m); }
  }

  const keyed = (d, arr) => Object.fromEntries(meta.facets[d].values.map((v) => [v.key, arr[v.bit]]));
  const facet_counts = {}, dim_distribution = {};
  for (const d of dimKeys) {
    dim_distribution[d] = keyed(d, mc[d]);
    const fc = new Uint32Array(32);
    for (let b = 0; b < 32; b++) fc[b] = mc[d][b] + extra[d][b];
    facet_counts[d] = keyed(d, fc);
  }
  facet_counts.family = Object.fromEntries(meta.families.map((f, i) => [f, famC[i] + famExtra[i]]));

  const out = {
    matched, in_scope: base, total: n, facet_counts, dim_distribution,
    by_family: meta.families.map((f, i) => ({ id: f, name: meta.family_names[f], count: famC[i] })),
    top_subcategories: topN(subC, 15, (i) => ({ family: meta.subcategories[i].family, name: meta.subcategories[i].name })),
    top_cwes: topN(cweC, 12, (i) => ({ cwe: meta.cwes[i].id, name: meta.cwes[i].name }), true),
    no_cwe: cweC[0],
    by_year: Array.from(yearC).map((c, i) => ({ year: y0 + i, count: c })).filter((r) => r.year <= 2026),
    severity: Object.fromEntries(SEV_NAMES.map((s, i) => [s, sevC[i]])),
    evidence: Object.fromEntries(CONF_NAMES.map((s, i) => [s, confC[i]])),
    top_vendors: topN(vendC, 12, (i) => ({ name: meta.vendors[i] }), true),
    top_products: topN(prodC, 12, (i) => ({ name: meta.products[i] }), true),
    examples: [],
  };
  for (let k = 0; k < 6 && matched > 0; k++) out.examples.push(rowObject(matchedIdx[Math.floor(((k + 0.5) * matched) / 6)], false));

  const size = Math.min(Math.max(p.size || 0, 0), 200);
  if (size > 0) {
    const pages = Math.max(1, Math.ceil(matched / size));
    const page = Math.min(Math.max(p.page || 1, 1), pages);
    const rows = [];
    for (let k = (page - 1) * size; k < Math.min(matched, page * size); k++) {
      const i = p.order === 'old' ? matchedIdx[k] : matchedIdx[matched - 1 - k];
      rows.push(rowObject(i, true));
    }
    Object.assign(out, { rows, page, pages, size });
  }
  out._idx = matchedIdx.subarray(0, matched);       // used by export; stripped before sending
  return out;
}

function* exportRows(result, order, limit) {
  const idx = result._idx;
  for (let k = 0; k < Math.min(idx.length, limit); k++) yield rowObject(order === 'old' ? idx[k] : idx[idx.length - 1 - k], true);
}

// ---------- autocomplete ----------
let CATALOG = null;
function catalog() {
  if (CATALOG) return CATALOG;
  const { meta, col } = DATA;
  const count = (arr, size) => { const c = new Uint32Array(size); for (let i = 0; i < arr.length; i++) c[arr[i]]++; return c; };
  const vc = count(col.vendor, meta.vendors.length), pc = count(col.product, meta.products.length);
  const cc = count(col.cwe, meta.cwes.length), sc = count(col.sub, meta.subcategories.length), fc = count(col.fam, meta.families.length);
  const items = [];
  const add = (type, label, extra) => items.push({ type, label, hay: label.toLowerCase(), ...extra });
  for (const d of meta.dim_order) for (const v of meta.facets[d].values)
    add('facet', v.label, { dim: d, dim_label: meta.facets[d].label, key: v.key, count: v.count, hay2: `${v.key} ${v.description}`.toLowerCase() });
  meta.families.forEach((f, i) => add('family', `${f} ${meta.family_names[f]}`, { value: f, count: fc[i] }));
  meta.subcategories.forEach((s, i) => add('subcategory', s.name, { value: `${s.family}|${s.name}`, family: s.family, count: sc[i] }));
  meta.cwes.forEach((c, i) => { if (i) add('cwe', `${c.id} ${c.name}`.trim(), { value: c.id, count: cc[i], hay2: c.id.toLowerCase() }); });
  meta.vendors.forEach((v, i) => { if (i) add('vendor', v, { value: v, count: vc[i] }); });
  meta.products.forEach((v, i) => { if (i) add('product', v, { value: v, count: pc[i] }); });
  CATALOG = items;
  return items;
}

function matchKind(it, q) {
  const h = it.hay;
  if (h === q) return 0;
  if (h.startsWith(q)) return 1;
  if (h.split(/[^a-z0-9+#./]+/).some((w) => w.startsWith(q))) return 2;
  if (h.includes(q) || (it.hay2 && it.hay2.includes(q))) return 3;
  return -1;
}

function suggest(qRaw, limit = 14) {
  if (!DATA) throw new Error('facet data not available');
  const q = String(qRaw || '').trim().toLowerCase();
  if (q.length < 1) return [];
  const out = [];
  // CVE identifiers: "cve-2021-4" or "2021-44"
  const cm = /^(?:cve[-\s]?)?(\d{4})(?:-(\d*))?$/.exec(q);
  if (cm && (q.startsWith('cve') || q.includes('-'))) {
    const y = Number(cm[1]), pre = cm[2] || '';
    const { col } = DATA;
    for (let i = DATA.meta.rows - 1; i >= 0 && out.length < 6; i--) {
      if (col.year[i] === y && String(col.num[i]).startsWith(pre)) out.push({ type: 'cve', label: cveId(i), value: cveId(i), family: DATA.meta.families[col.fam[i]], count: 1 });
    }
  }
  const scored = [];
  for (const it of catalog()) {
    const k = matchKind(it, q);
    if (k >= 0) scored.push([k, it]);
  }
  scored.sort((a, b) => a[0] - b[0] || b[1].count - a[1].count);
  const per = {};
  const cap = { facet: 5, family: 2, subcategory: 3, cwe: 3, vendor: 4, product: 4 };
  for (const [k, it] of scored) {
    per[it.type] = (per[it.type] || 0) + 1;
    if (per[it.type] > cap[it.type]) continue;
    const { hay, hay2, ...rest } = it;
    out.push(rest);
    if (out.length >= limit) break;
  }
  return out;
}

function describe() {
  if (!DATA) return null;
  const { meta } = DATA;
  return { rows: meta.rows, method: meta.method, facets: meta.facets, dim_order: meta.dim_order, dim_groups: meta.dim_groups,
           families: meta.families, family_names: meta.family_names };
}

module.exports = { available: !!DATA, query, suggest, describe, exportRows };
