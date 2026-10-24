import React, { useEffect, useState } from 'react';
import { getCoverage } from '../api.js';
import { FAMILY_COLORS } from '../colors.js';

const pct = (n, d) => (d ? Math.round((1000 * n) / d) / 10 : 0);

export default function CoveragePage() {
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);
  const [open, setOpen] = useState({});
  const [onlyGaps, setOnlyGaps] = useState(false);

  useEffect(() => { getCoverage().then(setData).catch((e) => setErr(e.message)); }, []);
  if (err) return <div className="panel error">{err}</div>;
  if (!data) return <div className="panel">Loading coverage...</div>;
  const t = data.totals, b = data.bookkeeping;
  const strong = data.mapping_basis.find((r) => r.basis.startsWith('Specific CWE'));

  return (
    <div className="panel coverage">
      <h1>Does the taxonomy cover all of CVE?</h1>
      <p>
        Short answer: every one of the {b.total.toLocaleString()} CVE records lands in exactly one bucket, and the record set
        contains {t.subcategories} distinct kinds of weakness, grouped into {t.families} families. Two further buckets hold
        records that are not a weakness class at all. The sections below show what that does and does not prove.
      </p>

      <div className="stat-row">
        <div className="stat-card"><div className="stat-num">{(b.total - b.unclassified - b.rejected).toLocaleString()}</div><div className="stat-label">classified into a family</div></div>
        <div className="stat-card"><div className="stat-num">{b.unclassified.toLocaleString()}</div><div className="stat-label">unclassified (public text names no weakness)</div></div>
        <div className="stat-card"><div className="stat-num">{b.rejected.toLocaleString()}</div><div className="stat-label">rejected / withdrawn IDs</div></div>
        <div className="stat-card"><div className="stat-num">{t.demos}</div><div className="stat-label">runnable demos, {t.families_with_demo}/{t.families} families</div></div>
        <div className="stat-card"><div className="stat-num">{t.cve_share_with_demo}%</div><div className="stat-label">of classified CVEs sit in a subcategory with a demo ({t.subcategories_with_demo}/{t.subcategories})</div></div>
      </div>

      <h2>How strong is the evidence?</h2>
      <p className="section-hint">
        "Covered" and "correct" are different things. {strong ? `${pct(strong.total, t.classified)}% of classified CVEs were placed by a specific CWE` : ''};
        the rest were placed by weaker evidence and carry lower confidence. Use the Explore tab's "specific CWE only" setting to see only the strong ones.
      </p>
      <table className="plain-table">
        <thead><tr><th>Basis for the family</th><th>CVEs</th><th>High</th><th>Medium</th><th>Low</th></tr></thead>
        <tbody>{data.mapping_basis.map((r) => (
          <tr key={r.basis}><td>{r.basis}</td><td className="num">{r.total.toLocaleString()}</td><td className="num">{r.high.toLocaleString()}</td><td className="num">{r.medium.toLocaleString()}</td><td className="num">{r.low.toLocaleString()}</td></tr>))}
        </tbody>
      </table>

      <h2>Against MITRE's top-level CWE pillars</h2>
      <p className="section-hint">{data.cwe_pillars_note}</p>
      <table className="plain-table">
        <thead><tr><th>CWE pillar</th><th>Families</th></tr></thead>
        <tbody>{data.cwe_pillars.map((p) => (
          <tr key={p.cwe}><td>{p.cwe} {p.name}</td><td>{p.families.map((f) => <span key={f} className="pill subtle" style={{ color: FAMILY_COLORS[f] }}>{f}</span>)}</td></tr>))}
        </tbody>
      </table>

      <h2>Every subcategory in the CVE data</h2>
      <label className="gap-toggle"><input type="checkbox" checked={onlyGaps} onChange={(e) => setOnlyGaps(e.target.checked)} /> show only subcategories without a demo</label>
      {data.families.map((fam) => {
        const rows = fam.subcategories.filter((s) => !onlyGaps || s.demos.length === 0);
        if (!rows.length) return null;
        const isOpen = open[fam.family] !== false;
        return (
          <div key={fam.family} className="cov-family">
            <button type="button" className="cov-head" onClick={() => setOpen({ ...open, [fam.family]: !isOpen })}>
              <span className="chevron">{isOpen ? '\u25BE' : '\u25B8'}</span>
              <span className="pill subtle" style={{ color: FAMILY_COLORS[fam.family] }}>{fam.family}</span> {fam.name}
              <span className="muted"> &middot; {fam.total.toLocaleString()} CVEs &middot; {fam.distinct_cwes} CWEs &middot; {fam.covered_share}% in subcategories with a demo</span>
            </button>
            {isOpen && (
              <table className="plain-table">
                <thead><tr><th>Subcategory</th><th>CVEs</th><th>Specific-CWE %</th><th>Top CWEs</th><th>Demo</th></tr></thead>
                <tbody>{rows.map((s) => (
                  <tr key={s.name}>
                    <td>{s.name}</td><td className="num">{s.count.toLocaleString()}</td><td className="num">{s.high_confidence_pct}%</td>
                    <td className="muted">{s.top_cwes.map((c) => c.cwe).join(', ')}</td>
                    <td>{s.demos.length ? s.demos.map((d) => <a key={d.id} href={`#/demo/${d.id}`} className="demo-link">{d.title} <span className="lang-tag">{d.language_label}</span></a>) : <span className="muted">no demo yet</span>}</td>
                  </tr>))}</tbody>
              </table>
            )}
          </div>
        );
      })}
    </div>
  );
}
