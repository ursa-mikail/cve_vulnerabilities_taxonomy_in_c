const BASE = '/api';

export async function getTaxonomy() {
  const r = await fetch(`${BASE}/taxonomy`);
  if (!r.ok) throw new Error('failed to load taxonomy');
  return r.json();
}

export async function getDemo(id) {
  const r = await fetch(`${BASE}/demo/${encodeURIComponent(id)}`);
  if (!r.ok) throw new Error('demo not found');
  return r.json();
}

export async function getAnalytics() {
  const r = await fetch(`${BASE}/analytics`);
  if (!r.ok) throw new Error('analytics not available');
  return r.json();
}

export async function runDemo(id, variant) {
  const r = await fetch(`${BASE}/demo/${encodeURIComponent(id)}/run`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ variant }),
  });
  if (!r.ok) throw new Error('run failed');
  return r.json();
}

export async function getCoverage() {
  const r = await fetch(`${BASE}/coverage`);
  if (!r.ok) throw new Error('coverage not available');
  return r.json();
}

export async function getFacets() {
  const r = await fetch(`${BASE}/facets`);
  if (!r.ok) throw new Error('facet data not available (run tools/build_facets.py)');
  return r.json();
}

// params: { os:[], lang:[], system:[], family:[], from, to, sev, evidence }
export async function filterCves(params) {
  const qs = new URLSearchParams();
  for (const k of ['os', 'lang', 'system', 'family']) if (params[k] && params[k].length) qs.set(k, params[k].join(','));
  for (const k of ['from', 'to', 'sev', 'evidence']) if (params[k]) qs.set(k, params[k]);
  const r = await fetch(`${BASE}/filter?${qs.toString()}`);
  if (!r.ok) {
    let msg = 'filter failed';
    try { msg = (await r.json()).error || msg; } catch (e) { /* keep default */ }
    throw new Error(msg);
  }
  return r.json();
}

// ---- Browse tab -------------------------------------------------------------------------
// state: { dims:{os:[],...}, family:[], cwe:[], sevs:[], evidence, from, to, order, page, size,
//          vendor:[], product:[], sub:[], cve:[] }
export function browseQuery(state) {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(state.dims || {})) if (v.length) qs.set(k, v.join(','));
  for (const k of ['family', 'cwe', 'sevs']) if (state[k] && state[k].length) qs.set(k, state[k].join(','));
  for (const k of ['vendor', 'product', 'sub', 'cve']) for (const v of state[k] || []) qs.append(k, v);
  for (const k of ['evidence', 'from', 'to', 'order', 'page', 'size', 'text']) if (state[k]) qs.set(k, state[k]);
  return qs;
}

export async function browse(state) {
  const r = await fetch(`${BASE}/browse?${browseQuery(state).toString()}`);
  if (!r.ok) {
    let msg = 'browse failed';
    try { msg = (await r.json()).error || msg; } catch (e) { /* keep default */ }
    throw new Error(msg);
  }
  return r.json();
}

export async function suggest(q) {
  const r = await fetch(`${BASE}/suggest?q=${encodeURIComponent(q)}`);
  if (!r.ok) return [];
  return (await r.json()).suggestions;
}

export const exportUrl = (state) => `${BASE}/browse/export.csv?${browseQuery({ ...state, page: undefined, size: undefined }).toString()}`;
