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
