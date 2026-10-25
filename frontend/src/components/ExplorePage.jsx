import React, { useEffect, useMemo, useState } from 'react';
import { filterCves, getFacets } from '../api.js';
import { FAMILY_COLORS, SEVERITY_COLORS } from '../colors.js';
import BarChart from './charts/BarChart.jsx';
import HBarList from './charts/HBarList.jsx';
import TrendChart from './charts/TrendChart.jsx';
import DonutChart from './charts/DonutChart.jsx';

const DIMS = ['os', 'lang', 'system'];
const csv = (v) => (v ? v.split(',').filter(Boolean) : []);
const pct = (n, d) => (d ? Math.round((1000 * n) / d) / 10 : 0);

function readParams(sp) {
  const g = (k) => (sp ? sp.get(k) || '' : '');
  return { os: csv(g('os')), lang: csv(g('lang')), system: csv(g('system')), family: csv(g('family')),
           from: g('from'), to: g('to'), sev: g('sev'), evidence: g('evidence') };
}

function writeHash(p) {
  const qs = new URLSearchParams();
  for (const k of [...DIMS, 'family']) if (p[k].length) qs.set(k, p[k].join(','));
  for (const k of ['from', 'to', 'sev', 'evidence']) if (p[k]) qs.set(k, p[k]);
  const s = qs.toString();
  window.location.hash = '#/explore' + (s ? '?' + s : '');
}

function FacetGroup({ title, hint, values, selected, counts, onToggle, colorFor }) {
  return (
    <div className="facet-group">
      <h3>{title}</h3>
      {hint && <p className="facet-hint">{hint}</p>}
      <div className="chips">
        {values.map((v) => {
          const on = selected.includes(v.key);
          const n = counts ? counts[v.key] : undefined;
          const dead = !on && n === 0;
          return (
            <button key={v.key} type="button" className={`chip ${on ? 'on' : ''}`} disabled={dead}
              style={on && colorFor ? { borderColor: colorFor(v.key), color: colorFor(v.key) } : undefined}
              title={v.description || ''} onClick={() => onToggle(v.key)}>
              {v.label}{n !== undefined && <span className="chip-n">{n.toLocaleString()}</span>}
            </button>
          );
        })}
      </div>
    </div>
  );
}

export default function ExplorePage({ params: sp, families }) {
  const p = useMemo(() => readParams(sp), [sp && sp.toString()]);
  const [meta, setMeta] = useState(null);
  const [res, setRes] = useState(null);
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => { getFacets().then(setMeta).catch((e) => setErr(e.message)); }, []);
  useEffect(() => {
    if (!meta) return;
    let live = true;
    setBusy(true);
    filterCves(p).then((r) => { if (live) { setRes(r); setErr(null); } })
      .catch((e) => live && setErr(e.message)).finally(() => live && setBusy(false));
    return () => { live = false; };
  }, [meta, JSON.stringify(p)]);

  const toggle = (dim, key) => {
    const cur = p[dim];
    writeHash({ ...p, [dim]: cur.includes(key) ? cur.filter((k) => k !== key) : [...cur, key] });
  };
  const set = (k, v) => writeHash({ ...p, [k]: v });
  const anyFilter = DIMS.some((d) => p[d].length) || p.family.length || p.from || p.to || p.sev || p.evidence;

  const famValues = useMemo(() => families.map((f) => ({ key: f.id, label: `${f.id} ${f.name}`, description: f.blurb })), [families]);
  const years = useMemo(() => Array.from({ length: 28 }, (_, i) => String(1999 + i)), []);

  if (err && !meta) return <div className="panel error">{err}</div>;
  if (!meta) return <div className="panel">Loading filters...</div>;

  const famChartData = res ? res.by_family.filter((f) => f.id !== 'U0').map((f) => ({ id: f.id, label: f.id, value: f.count, color: FAMILY_COLORS[f.id] })) : [];
  const trend = res ? [{ id: 'sel', name: 'Matching CVEs', color: 'var(--accent)', values: res.by_year.map((y) => y.count) }] : [];
  const sev = res ? ['critical', 'high', 'medium', 'low'].map((s) => ({ label: s[0].toUpperCase() + s.slice(1), value: res.severity[s], color: SEVERITY_COLORS[s.toUpperCase()] })) : [];
  const ev = res ? res.evidence : null;
  const f = meta.facets;

  return (
    <div className="panel explore">
      <h1>Explore by system, language and platform</h1>
      <p className="section-hint">
        Pick any combination. Within one group the choices are OR (Linux or Windows); across groups they are AND (Linux and C/C++ and
        a specific family). Numbers on the buttons show what you would get if you added that choice.
      </p>
      <div className="honesty">
        <strong>How to read these filters.</strong> The CVE record has no "operating system" or "language" field, so these are inferred from the
        vendor, product and the wording of each description. A CVE that names nothing is left out of that filter, never guessed:
        {' '}{f.os.share_with_any_value}% of records name an operating system, {f.lang.share_with_any_value}% point at a programming language,
        and {f.system.share_with_any_value}% fit a system type. "PHP" means the record points at PHP code, not that every PHP flaw is here.
      </div>

      <div className="explore-layout">
        <aside className="filters">
          <FacetGroup title={f.os.label} values={f.os.values} selected={p.os} counts={res && res.facet_counts.os} onToggle={(k) => toggle('os', k)} />
          <FacetGroup title={f.lang.label} hint="Language of the affected component, where the record says or implies it." values={f.lang.values} selected={p.lang} counts={res && res.facet_counts.lang} onToggle={(k) => toggle('lang', k)} />
          <FacetGroup title={f.system.label} values={f.system.values} selected={p.system} counts={res && res.facet_counts.system} onToggle={(k) => toggle('system', k)} />
          <FacetGroup title="Weakness family" values={famValues} selected={p.family} counts={res && res.facet_counts.family} onToggle={(k) => toggle('family', k)} colorFor={(k) => FAMILY_COLORS[k]} />
          <div className="facet-group">
            <h3>Year, severity, evidence</h3>
            <div className="selects">
              <label>From <select value={p.from} onChange={(e) => set('from', e.target.value)}><option value="">any</option>{years.map((y) => <option key={y}>{y}</option>)}</select></label>
              <label>To <select value={p.to} onChange={(e) => set('to', e.target.value)}><option value="">any</option>{years.map((y) => <option key={y}>{y}</option>)}</select></label>
              <label>Min severity <select value={p.sev} onChange={(e) => set('sev', e.target.value)}><option value="">any (incl. unscored)</option><option value="low">low+</option><option value="medium">medium+</option><option value="high">high+</option><option value="critical">critical</option></select></label>
              <label>Family evidence <select value={p.evidence} onChange={(e) => set('evidence', e.target.value)}><option value="">any</option><option value="medium">medium or better</option><option value="high">specific CWE only</option></select></label>
            </div>
          </div>
          {anyFilter && <button type="button" className="clear-btn" onClick={() => { window.location.hash = '#/explore'; }}>Clear all filters</button>}
        </aside>

        <section className="results">
          {err && <div className="panel error">{err}</div>}
          {!res && <p>Loading...</p>}
          {res && (
            <div className={busy ? 'busy' : ''}>
              <div className="stat-row">
                <div className="stat-card"><div className="stat-num">{res.matched.toLocaleString()}</div><div className="stat-label">matching CVEs ({pct(res.matched, res.total)}% of {res.total.toLocaleString()})</div></div>
                <div className="stat-card"><div className="stat-num">{ev.high ? pct(ev.high, res.matched) : 0}%</div><div className="stat-label">family set by a specific CWE</div></div>
                <div className="stat-card"><div className="stat-num">{res.no_cwe.toLocaleString()}</div><div className="stat-label">have no CWE on record</div></div>
              </div>

              {res.matched === 0 ? <p>No CVEs match this combination.</p> : (
                <>
                  <section className="analytics-section">
                    <h2>Which weakness families?</h2>
                    <BarChart data={famChartData} height={200} onBarClick={(d) => toggle('family', d.id)} selectedId={p.family.length === 1 ? p.family[0] : null} />
                    {res.by_family.find((x) => x.id === 'U0').count > 0 && <p className="section-hint">{res.by_family.find((x) => x.id === 'U0').count.toLocaleString()} more matching CVEs are unclassified (not enough public information).</p>}
                  </section>

                  <section className="analytics-section">
                    <h2>Most common weaknesses here, and demos you can run</h2>
                    <table className="plain-table">
                      <thead><tr><th>Subcategory</th><th>CVEs</th><th>Demo</th></tr></thead>
                      <tbody>{res.top_subcategories.map((s) => (
                        <tr key={s.family + s.name}>
                          <td><span className="pill subtle" style={{ color: FAMILY_COLORS[s.family] }}>{s.family}</span> {s.name}</td>
                          <td className="num">{s.count.toLocaleString()}</td>
                          <td>{s.demos.length ? s.demos.map((d) => <a key={d.id} href={`#/demo/${d.id}`} className="demo-link">{d.title} <span className="lang-tag">{d.language_label}</span></a>) : <span className="muted">no demo yet</span>}</td>
                        </tr>))}</tbody>
                    </table>
                  </section>

                  <div className="analytics-grid-2">
                    <section className="analytics-section"><h2>Over time</h2><TrendChart years={res.by_year.map((y) => String(y.year))} series={trend} /></section>
                    <section className="analytics-section"><h2>Severity</h2><DonutChart segments={sev} centerLabel="CVSS severity" /></section>
                  </div>
                  <div className="analytics-grid-2">
                    <section className="analytics-section"><h2>Top CWEs</h2><HBarList items={res.top_cwes.map((c) => ({ name: `${c.cwe} ${c.name}`.trim(), count: c.count }))} /></section>
                    <section className="analytics-section"><h2>Top vendors</h2>{res.top_vendors.length ? <HBarList items={res.top_vendors} /> : <p className="muted">Vendors are not recorded for these CVEs.</p>}</section>
                  </div>

                  <section className="analytics-section">
                    <h2>A few matching CVEs</h2>
                    <p className="section-hint">A fixed, unbiased sample of the current selection (the same selection always shows the same CVEs).</p>
                    <ul className="example-list">{res.examples.map((e) => (
                      <li key={e.id}><a href={e.url} target="_blank" rel="noreferrer">{e.id}</a> <span className="pill subtle">{e.family}</span> {e.subcategory} <span className="muted">{e.cwe || 'no CWE'}</span> {e.severity !== 'none' && <span className={`sev-tag sev-${e.severity}`}>{e.severity}</span>}</li>))}
                    </ul>
                  </section>
                </>
              )}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
