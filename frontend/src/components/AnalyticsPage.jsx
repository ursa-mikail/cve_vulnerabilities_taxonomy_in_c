import React, { useEffect, useMemo, useState } from 'react';
import { getAnalytics } from '../api.js';
import BarChart from './charts/BarChart.jsx';
import TrendChart from './charts/TrendChart.jsx';
import DonutChart from './charts/DonutChart.jsx';
import HBarList from './charts/HBarList.jsx';

const FAMILY_COLORS = {
  F1: '#4da3ff', F2: '#7c8cff', F3: '#9b6bff', F4: '#c06bff',
  F5: '#ff6bd6', F6: '#ff6b8a', F7: '#ff8a4d', F8: '#f2c43b',
  F9: '#c3e04d', F10: '#5de08a', F11: '#2ecfc2', F12: '#2ea7df',
  F13: '#8a97a8', F14: '#5c6b7f', U0: '#4a5568', R0: '#394250',
};

const SEVERITY_COLORS = { CRITICAL: '#ff5c5c', HIGH: '#f2a93b', MEDIUM: '#f2d43b', LOW: '#2ecc71' };

function StatCard({ label, value, sub }) {
  return (
    <div className="stat-card">
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  );
}

export default function AnalyticsPage({ families: taxonomyFamilies }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [selectedFamily, setSelectedFamily] = useState(null);

  useEffect(() => {
    getAnalytics().then(setData).catch((e) => setError(e.message));
  }, []);

  const taxonomyDemoByFamily = useMemo(() => {
    const m = {};
    (taxonomyFamilies || []).forEach((f) => { m[f.id] = f.demos[0]; });
    return m;
  }, [taxonomyFamilies]);

  if (error) {
    return (
      <div className="panel">
        <h1>Analytics</h1>
        <p>Could not load analytics data: {error}</p>
      </div>
    );
  }
  if (!data) return <div className="panel">Loading analytics...</div>;

  const coreFamilies = data.families.filter((f) => f.id !== 'U0' && f.id !== 'R0');
  const metaFamilies = data.families.filter((f) => f.id === 'U0' || f.id === 'R0');

  const barData = [...coreFamilies, ...metaFamilies].map((f) => ({
    id: f.id,
    label: f.id,
    fullLabel: `${f.id} \u00b7 ${f.name}`,
    value: f.total,
    color: FAMILY_COLORS[f.id] || 'var(--accent)',
  }));

  const top5 = [...coreFamilies].sort((a, b) => b.total - a.total).slice(0, 5);
  const trendSeries = top5.map((f) => ({
    id: f.id,
    name: f.id,
    color: FAMILY_COLORS[f.id],
    values: f.by_year.map((p) => p.count),
  }));
  const totalSeries = {
    id: 'total',
    name: 'All families',
    color: '#ffffff',
    values: data.timeline_total.map((p) => p.count),
  };

  const sevSegments = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => ({
    label: s.charAt(0) + s.slice(1).toLowerCase(),
    value: data.severity_totals[s] || 0,
    color: SEVERITY_COLORS[s],
  }));

  const focused = selectedFamily ? data.families.find((f) => f.id === selectedFamily) : null;

  return (
    <div className="panel analytics-panel">
      <h1>CVE Analytics</h1>
      <p className="analytics-intro">
        {data.total_cves.toLocaleString()} CVE records ({data.year_range[0]}&ndash;{data.year_range[1]}), each mapped to one
        of the taxonomy families above by CWE and, where no CWE was available, by the wording of its own description.
        Hover any chart for exact numbers; click a family bar to drill in.
      </p>

      <div className="stat-row">
        <StatCard label="Total CVE records" value={data.total_cves.toLocaleString()} />
        <StatCard label="Published" value={data.published_cves.toLocaleString()} />
        <StatCard label="Rejected / withdrawn" value={data.rejected_cves.toLocaleString()} />
        <StatCard label="Unclassified" value={data.unclassified_cves.toLocaleString()}
          sub={`${((100 * data.unclassified_cves) / data.total_cves).toFixed(1)}% of total`} />
        <StatCard label="Years covered" value={`${data.year_range[1] - data.year_range[0] + 1}`}
          sub={`${data.year_range[0]}\u2013${data.year_range[1]}`} />
      </div>

      <section className="analytics-section">
        <h2>CVEs by family</h2>
        <p className="section-hint">Click a bar to see its top CWEs, subcategories, and example CVEs.</p>
        <BarChart data={barData} onBarClick={(d) => setSelectedFamily(d.id === selectedFamily ? null : d.id)} selectedId={selectedFamily} />
      </section>

      {focused && (
        <section className="analytics-section focus-panel">
          <div className="focus-header">
            <div>
              <span className="pill" style={{ color: FAMILY_COLORS[focused.id], borderColor: FAMILY_COLORS[focused.id] }}>{focused.id}</span>
              <h2 style={{ display: 'inline', marginLeft: '0.5rem' }}>{focused.name}</h2>
              <span className="meta" style={{ marginLeft: '0.6rem' }}>{focused.total.toLocaleString()} CVEs</span>
            </div>
            <div className="focus-actions">
              {taxonomyDemoByFamily[focused.id] && (
                <a className="run-btn-link" href={`#/demo/${taxonomyDemoByFamily[focused.id].id}`}>
                  Open the live demo &rarr;
                </a>
              )}
              <button className="close-focus" onClick={() => setSelectedFamily(null)}>Close</button>
            </div>
          </div>

          <div className="focus-grid">
            <div>
              <h3>Top CWEs in this family</h3>
              {focused.top_cwes.length ? (
                <HBarList
                  items={focused.top_cwes.map((c) => ({ name: `${c.cwe} \u00b7 ${c.name}`, count: c.count }))}
                  color={FAMILY_COLORS[focused.id]}
                />
              ) : <p className="section-hint">No individual CWE was assigned for this family's records.</p>}
            </div>
            <div>
              <h3>Top subcategories</h3>
              {focused.top_subcategories.length ? (
                <HBarList
                  items={focused.top_subcategories.map((c) => ({ name: c.name, count: c.count }))}
                  color={FAMILY_COLORS[focused.id]}
                />
              ) : <p className="section-hint">No subcategory breakdown available.</p>}
            </div>
          </div>

          <h3>Example CVEs</h3>
          <ul className="example-list">
            {focused.examples.map((ex) => (
              <li key={ex.id}>
                <a href={ex.url} target="_blank" rel="noreferrer">{ex.id}</a>
                {ex.severity && <span className={`sev-tag sev-${ex.severity.toLowerCase()}`}>{ex.severity}</span>}
                {ex.cwe && <span className="meta"> {ex.cwe}</span>}
                <div className="example-title">{ex.title}</div>
              </li>
            ))}
          </ul>
        </section>
      )}

      <section className="analytics-section">
        <h2>Trend over time</h2>
        <p className="section-hint">
          The five largest families, plus the running total across all 16. Move your mouse across the chart for exact
          per-year counts.
        </p>
        <TrendChart years={data.timeline_total.map((p) => p.year)} series={[totalSeries, ...trendSeries]} />
      </section>

      <div className="analytics-grid-2">
        <section className="analytics-section">
          <h2>Severity distribution</h2>
          <p className="section-hint">Across all published CVEs with a CVSS score on record.</p>
          <DonutChart segments={sevSegments} centerLabel="CVSS severity" />
        </section>

        <section className="analytics-section">
          <h2>Most-affected vendors</h2>
          <p className="section-hint">By number of published CVE records naming that vendor.</p>
          <HBarList items={data.top_vendors} />
        </section>
      </div>

      <section className="analytics-section">
        <h2>Most-affected products</h2>
        <HBarList items={data.top_products} color="#5de08a" />
      </section>
    </div>
  );
}
