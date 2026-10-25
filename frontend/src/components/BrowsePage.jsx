import React, { useEffect, useMemo, useState } from 'react';
import { browse, getFacets, exportUrl } from '../api.js';
import { FAMILY_COLORS, SEVERITY_COLORS } from '../colors.js';
import Autocomplete from './Autocomplete.jsx';
import BarChart from './charts/BarChart.jsx';
import HBarList from './charts/HBarList.jsx';
import TrendChart from './charts/TrendChart.jsx';
import DonutChart from './charts/DonutChart.jsx';

const csv = (v) => (v ? v.split(',').filter(Boolean) : []);
const SEV_OPTS = [['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low'], ['none', 'Unscored']];

function readState(sp, dimOrder) {
  const g = (k) => (sp ? sp.get(k) || '' : '');
  const dims = {};
  for (const d of dimOrder) dims[d] = csv(g(d));
  return { dims, family: csv(g('family')), cwe: csv(g('cwe')), sevs: csv(g('sevs')), evidence: g('evidence'), text: g('text'), from: g('from'), to: g('to'),
           order: g('order') || 'new', page: g('page') || '1', size: g('size') || '25',
           vendor: sp ? sp.getAll('vendor') : [], product: sp ? sp.getAll('product') : [], sub: sp ? sp.getAll('sub') : [], cve: sp ? sp.getAll('cve') : [] };
}

function writeHash(s) {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(s.dims)) if (v.length) qs.set(k, v.join(','));
  for (const k of ['family', 'cwe', 'sevs']) if (s[k].length) qs.set(k, s[k].join(','));
  for (const k of ['vendor', 'product', 'sub', 'cve']) for (const v of s[k]) qs.append(k, v);
  for (const k of ['evidence', 'text', 'from', 'to']) if (s[k]) qs.set(k, s[k]);
  if (s.order !== 'new') qs.set('order', s.order);
  if (s.page !== '1') qs.set('page', s.page);
  if (s.size !== '25') qs.set('size', s.size);
  const t = qs.toString();
  window.location.hash = '#/browse' + (t ? '?' + t : '');
}

const toggleIn = (arr, v) => (arr.includes(v) ? arr.filter((x) => x !== v) : [...arr, v]);

function Check({ checked, label, count, onChange, color, hint }) {
  const dead = !checked && count === 0;
  return (
    <label className={`chk ${dead ? 'dead' : ''}`} title={hint || ''}>
      <input type="checkbox" checked={checked} disabled={dead} onChange={onChange} />
      <span className="chk-label" style={checked && color ? { color } : undefined}>{label}</span>
      {count !== undefined && <span className="chk-n">{count.toLocaleString()}</span>}
    </label>
  );
}

function distribution(meta, res, dim) {
  const labels = Object.fromEntries(meta.facets[dim].values.map((v) => [v.key, v.label]));
  return Object.entries(res.dim_distribution[dim]).filter(([, n]) => n > 0).sort((a, b) => b[1] - a[1])
    .slice(0, 12).map(([k, n]) => ({ name: labels[k], count: n }));
}

const CHART_TABS = [
  ['overview', 'Overview'],
  ['software', 'Platform & software', ['os', 'arch', 'lang', 'system', 'deploy', 'format']],
  ['hardware', 'Hardware & network', ['hardware', 'network']],
  ['attack', 'Attack & impact', ['vector', 'impact', 'sector']],
  ['weak', 'Weaknesses & vendors'],
];

export default function BrowsePage({ params: sp, families }) {
  const [meta, setMeta] = useState(null);
  const [res, setRes] = useState(null);
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);
  const [tab, setTab] = useState('overview');

  useEffect(() => { getFacets().then(setMeta).catch((e) => setErr(e.message)); }, []);
  const state = useMemo(() => (meta ? readState(sp, meta.dim_order) : null), [meta, sp && sp.toString()]);

  useEffect(() => {
    if (!state) return undefined;
    let live = true;
    setBusy(true);
    browse(state).then((r) => { if (live) { setRes(r); setErr(null); } })
      .catch((e) => live && setErr(e.message)).finally(() => live && setBusy(false));
    return () => { live = false; };
  }, [state && JSON.stringify(state)]);

  if (err && !meta) return <div className="panel error">{err}</div>;
  if (!meta || !state) return <div className="panel">Loading filters...</div>;

  const set = (patch) => writeHash({ ...state, page: '1', ...patch });
  const toggleDim = (d, k) => set({ dims: { ...state.dims, [d]: toggleIn(state.dims[d], k) } });
  const famName = Object.fromEntries(families.map((f) => [f.id, f.name]));

  const onPick = (it) => {
    if (it.type === 'facet') set({ dims: { ...state.dims, [it.dim]: state.dims[it.dim].includes(it.key) ? state.dims[it.dim] : [...state.dims[it.dim], it.key] } });
    else if (it.type === 'family') set({ family: [...new Set([...state.family, it.value])] });
    else if (it.type === 'cwe') set({ cwe: [...new Set([...state.cwe, it.value])] });
    else if (it.type === 'subcategory') set({ sub: [...new Set([...state.sub, it.value])] });
    else if (it.type === 'vendor') set({ vendor: [...new Set([...state.vendor, it.value])] });
    else if (it.type === 'product') set({ product: [...new Set([...state.product, it.value])] });
    else if (it.type === 'cve') set({ cve: [...new Set([...state.cve, it.value])] });
    else if (it.type === 'text') set({ text: it.value });
  };

  // active filter tags
  const tags = [];
  for (const d of meta.dim_order) for (const k of state.dims[d]) tags.push({ label: meta.facets[d].values.find((v) => v.key === k).label, kind: meta.facets[d].label, off: () => toggleDim(d, k) });
  state.family.forEach((f) => tags.push({ label: `${f} ${famName[f] || ''}`, kind: 'Family', off: () => set({ family: state.family.filter((x) => x !== f) }) }));
  state.sub.forEach((s) => tags.push({ label: s.split('|')[1], kind: 'Weakness', off: () => set({ sub: state.sub.filter((x) => x !== s) }) }));
  state.cwe.forEach((c) => tags.push({ label: c, kind: 'CWE', off: () => set({ cwe: state.cwe.filter((x) => x !== c) }) }));
  state.vendor.forEach((v) => tags.push({ label: v, kind: 'Vendor', off: () => set({ vendor: state.vendor.filter((x) => x !== v) }) }));
  state.product.forEach((v) => tags.push({ label: v, kind: 'Product', off: () => set({ product: state.product.filter((x) => x !== v) }) }));
  state.cve.forEach((v) => tags.push({ label: v, kind: 'CVE', off: () => set({ cve: state.cve.filter((x) => x !== v) }) }));
  if (state.text) tags.push({ label: `\u201C${state.text}\u201D`, kind: 'Text in description', off: () => set({ text: '' }) });
  state.sevs.forEach((s) => tags.push({ label: s, kind: 'Severity', off: () => set({ sevs: state.sevs.filter((x) => x !== s) }) }));
  if (state.from || state.to) tags.push({ label: `${state.from || '1999'}\u2013${state.to || '2026'}`, kind: 'Years', off: () => set({ from: '', to: '' }) });
  if (state.evidence) tags.push({ label: state.evidence === 'high' ? 'specific CWE only' : 'medium or better', kind: 'Evidence', off: () => set({ evidence: '' }) });

  const years = Array.from({ length: 28 }, (_, i) => String(1999 + i));
  const pages = res ? res.pages : 1, page = res ? res.page : 1;
  const go = (p) => writeHash({ ...state, page: String(p) });

  const famData = res ? res.by_family.filter((f) => f.id !== 'U0').map((f) => ({ id: f.id, label: f.id, value: f.count, color: FAMILY_COLORS[f.id] })) : [];
  const sevSeg = res ? SEV_OPTS.map(([k, l]) => ({ label: l, value: res.severity[k], color: SEVERITY_COLORS[k.toUpperCase()] || '#5c6b7f' })) : [];

  return (
    <div className="panel browse">
      <h1>Browse and search CVEs</h1>
      <p className="section-hint">
        Tick any boxes, or type in the search box (it suggests operating systems, languages, protocols, weaknesses, CWEs, vendors, products and CVE IDs).
        Within one group choices are OR; across groups they are AND. Counts beside each box show what you would get by adding it.
      </p>
      <div className="honesty">
        <strong>These filters are inferred from the wording of each record.</strong> CVE has no OS, language, hardware or protocol field, so a record appears
        under a box only if its vendor, product or description says so. Coverage differs by group (for example
        {' '}{meta.facets.system.share_with_any_value}% of records fit a system type, {meta.facets.lang.share_with_any_value}% name a language, {meta.facets.os.share_with_any_value}% an operating system,
        {' '}{meta.facets.hardware.share_with_any_value}% a hardware class, {meta.facets.arch.share_with_any_value}% a CPU architecture); a record that names nothing is never guessed. Impact and attack-vector boxes
        reflect what the text claims, not a verified CVSS vector. Wording-based rules have false positives.
      </div>

      <div className="explore-layout">
        <aside className="filters">
          <Autocomplete onPick={onPick} />
          {tags.length > 0 && (
            <div className="tags">
              {tags.map((t, i) => (
                <button key={i} type="button" className="tag" onClick={t.off} title={`Remove ${t.kind} filter`}>
                  <span className="tag-kind">{t.kind}</span> {t.label} <span aria-hidden="true">&times;</span>
                </button>))}
              <button type="button" className="clear-btn" onClick={() => { window.location.hash = '#/browse'; }}>Clear all</button>
            </div>
          )}

          {meta.dim_groups.map((g, gi) => (
            <details key={g.title} className="fgroup" open={gi < 2 || g.dims.some((d) => state.dims[d].length)}>
              <summary>{g.title}</summary>
              {g.dims.map((d) => (
                <div key={d} className="facet-group">
                  <h3>{meta.facets[d].label}</h3>
                  {meta.facets[d].values.map((v) => (
                    <Check key={v.key} checked={state.dims[d].includes(v.key)} label={v.label} hint={v.description}
                      count={res ? res.facet_counts[d][v.key] : undefined} onChange={() => toggleDim(d, v.key)} />))}
                </div>))}
            </details>
          ))}

          <details className="fgroup" open={state.family.length > 0}>
            <summary>Weakness family</summary>
            {families.map((f) => (
              <Check key={f.id} checked={state.family.includes(f.id)} label={`${f.id} ${f.name}`} hint={f.blurb} color={FAMILY_COLORS[f.id]}
                count={res ? res.facet_counts.family[f.id] : undefined} onChange={() => set({ family: toggleIn(state.family, f.id) })} />))}
            <Check checked={state.family.includes('U0')} label="U0 Unclassified" count={res ? res.facet_counts.family.U0 : undefined} onChange={() => set({ family: toggleIn(state.family, 'U0') })} />
          </details>

          <details className="fgroup">
            <summary>Severity, evidence, years</summary>
            <div className="facet-group"><h3>CVSS severity</h3>
              {SEV_OPTS.map(([k, l]) => <Check key={k} checked={state.sevs.includes(k)} label={l} count={res ? res.severity[k] : undefined} onChange={() => set({ sevs: toggleIn(state.sevs, k) })} />)}
            </div>
            <div className="facet-group"><h3>Evidence for the family</h3>
              {[['', 'Any'], ['medium', 'Medium or better'], ['high', 'Specific CWE only']].map(([k, l]) => (
                <label key={k} className="chk"><input type="radio" name="ev" checked={state.evidence === k} onChange={() => set({ evidence: k })} /><span className="chk-label">{l}</span></label>))}
            </div>
            <div className="selects">
              <label>From <select value={state.from} onChange={(e) => set({ from: e.target.value })}><option value="">any</option>{years.map((y) => <option key={y}>{y}</option>)}</select></label>
              <label>To <select value={state.to} onChange={(e) => set({ to: e.target.value })}><option value="">any</option>{years.map((y) => <option key={y}>{y}</option>)}</select></label>
            </div>
          </details>
        </aside>

        <section className="results">
          {err && <div className="panel error">{err}</div>}
          {!res && !err && <p>Loading...</p>}
          {res && (
            <div className={busy ? 'busy' : ''}>
              <div className="stat-row">
                <div className="stat-card"><div className="stat-num">{res.matched.toLocaleString()}</div><div className="stat-label">matching CVEs ({res.total ? Math.round((1000 * res.matched) / res.total) / 10 : 0}% of {res.total.toLocaleString()})</div></div>
                <div className="stat-card"><div className="stat-num">{res.matched ? Math.round((1000 * res.evidence.high) / res.matched) / 10 : 0}%</div><div className="stat-label">family set by a specific CWE</div></div>
                <div className="stat-card"><div className="stat-num">{res.related_demos.length}</div><div className="stat-label">runnable demos for the top weaknesses here</div></div>
              </div>

              <div className="subtabs" role="tablist">
                {CHART_TABS.map(([k, l]) => <button key={k} type="button" role="tab" aria-selected={tab === k} className={`subtab ${tab === k ? 'on' : ''}`} onClick={() => setTab(k)}>{l}</button>)}
              </div>

              {res.matched === 0 ? <p>No CVEs match this combination. Remove a filter above.</p> : (
                <div className="charts">
                  {tab === 'overview' && (
                    <>
                      <section className="analytics-section"><h2>Weakness families</h2>
                        <BarChart data={famData} height={200} onBarClick={(d) => set({ family: toggleIn(state.family, d.id) })} selectedId={state.family.length === 1 ? state.family[0] : null} /></section>
                      <div className="analytics-grid-2">
                        <section className="analytics-section"><h2>Over time</h2><TrendChart years={res.by_year.map((y) => String(y.year))} series={[{ id: 's', name: 'Matching CVEs', color: 'var(--accent)', values: res.by_year.map((y) => y.count) }]} /></section>
                        <section className="analytics-section"><h2>Severity</h2><DonutChart segments={sevSeg} centerLabel="CVSS severity" /></section>
                      </div>
                    </>
                  )}
                  {CHART_TABS.filter((t) => t[2] && t[0] === tab).map((t) => (
                    <div key={t[0]} className="analytics-grid-2">
                      {t[2].map((d) => {
                        const items = distribution(meta, res, d);
                        return (
                          <section key={d} className="analytics-section"><h2>{meta.facets[d].label}</h2>
                            {items.length ? <HBarList items={items} /> : <p className="muted">No matching record names a value here.</p>}</section>);
                      })}
                    </div>
                  ))}
                  {tab === 'weak' && (
                    <>
                      <section className="analytics-section"><h2>Most common weaknesses, with runnable demos</h2>
                        <table className="plain-table"><thead><tr><th>Subcategory</th><th>CVEs</th><th>Demo</th></tr></thead>
                          <tbody>{res.top_subcategories.map((s) => (
                            <tr key={s.family + s.name}><td><span className="pill subtle" style={{ color: FAMILY_COLORS[s.family] }}>{s.family}</span> {s.name}</td>
                              <td className="num">{s.count.toLocaleString()}</td>
                              <td>{s.demos.length ? s.demos.map((d) => <a key={d.id} href={`#/demo/${d.id}`} className="demo-link">{d.title} <span className="lang-tag">{d.language_label}</span></a>) : <span className="muted">no demo yet</span>}</td></tr>))}</tbody></table></section>
                      <div className="analytics-grid-2">
                        <section className="analytics-section"><h2>Top CWEs</h2><HBarList items={res.top_cwes.map((c) => ({ name: `${c.cwe} ${c.name}`.trim(), count: c.count }))} /></section>
                        <section className="analytics-section"><h2>Top vendors</h2>{res.top_vendors.length ? <HBarList items={res.top_vendors} /> : <p className="muted">No vendor recorded.</p>}</section>
                      </div>
                      <section className="analytics-section"><h2>Top products</h2>{res.top_products.length ? <HBarList items={res.top_products} /> : <p className="muted">No product recorded.</p>}</section>
                    </>
                  )}
                </div>
              )}

              <section className="analytics-section">
                <div className="list-head">
                  <h2>CVEs ({res.matched.toLocaleString()})</h2>
                  <div className="list-ctl">
                    <label>Sort <select value={state.order} onChange={(e) => set({ order: e.target.value })}><option value="new">newest first</option><option value="old">oldest first</option></select></label>
                    <label>Per page <select value={state.size} onChange={(e) => set({ size: e.target.value })}>{['10', '25', '50', '100'].map((n) => <option key={n}>{n}</option>)}</select></label>
                    <a className="run-btn-link" href={exportUrl(state)} download>Export CSV (up to 20,000)</a>
                  </div>
                </div>
                <ul className="cve-list">
                  {res.rows.map((r) => (
                    <li key={r.id} className="cve-row">
                      <div className="cve-top">
                        <a href={r.url} target="_blank" rel="noreferrer" className="cve-id">{r.id}</a>
                        <span className="pill subtle" style={{ color: FAMILY_COLORS[r.family] }} title={r.family_name}>{r.family}</span>
                        {r.severity !== 'none' && <span className={`sev-tag sev-${r.severity}`}>{r.severity}</span>}
                        <span className="muted">{r.subcategory}</span>
                        {r.cwe && <span className="muted" title={r.cwe_name || ''}>{r.cwe}</span>}
                        {(r.vendor || r.product) && <span className="cve-vp">{[r.vendor, r.product].filter(Boolean).join(' / ')}</span>}
                      </div>
                      <p className="cve-desc">{r.description || 'No description on record.'}</p>
                      {r.tags.length > 0 && <div className="cve-tags">{r.tags.map((t, i) => <span key={i} className="mini-tag">{t.label}</span>)}</div>}
                    </li>))}
                </ul>
                <div className="pager">
                  <button type="button" disabled={page <= 1} onClick={() => go(1)}>&laquo; First</button>
                  <button type="button" disabled={page <= 1} onClick={() => go(page - 1)}>&lsaquo; Prev</button>
                  <span>Page {page.toLocaleString()} of {pages.toLocaleString()}</span>
                  <button type="button" disabled={page >= pages} onClick={() => go(page + 1)}>Next &rsaquo;</button>
                  <button type="button" disabled={page >= pages} onClick={() => go(pages)}>Last &raquo;</button>
                </div>
                <p className="section-hint">Descriptions (and the text search) cover the first 1,200 characters; follow the CVE ID for the full record on NVD. Text search is a case-insensitive substring match, so \u201Caes\u201D also matches words that merely contain it.</p>
              </section>
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
