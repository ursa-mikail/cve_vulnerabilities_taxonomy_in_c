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
