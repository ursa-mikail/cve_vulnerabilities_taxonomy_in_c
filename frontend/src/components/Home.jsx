import React from 'react';

export default function Home({ taxonomy }) {
  const { families } = taxonomy;
  const demoCount = families.reduce((n, f) => n + f.demos.length, 0);
  return (
    <div className="panel">
      <h1>CVE Weakness Taxonomy Lab</h1>
      <p>
        {families.length} families that together cover the whole CVE record, each with {demoCount > families.length ? 'one or more ' : 'a '}
        runnable demo. A family is a root-cause idea, such as "untrusted data is interpreted as a command" or "a limit is not
        enforced", so it applies to every language and every kind of system. The demos are small illustrations written in{' '}
        {taxonomy.languages.join(', ')}; the language is incidental, and each demo says which one it uses.
      </p>
      <p className="home-links">
        <a href="#/explore">Explore by operating system, language or system type &rarr;</a>
        <a href="#/coverage">Does this cover all of CVE? &rarr;</a>
        <a href="#/analytics">Analytics &rarr;</a>
      </p>
      <div className="home-grid">
        {families.map((fam) => (
          <div key={fam.id} className="home-card">
            <h2>{fam.id} &middot; {fam.name}</h2>
            <p>{fam.blurb}</p>
            <p className="shows-up"><strong>Shows up in:</strong> {fam.shows_up_in}</p>
            {fam.anchors.length > 0 && (
              <p className="shows-up">
                <strong>Real CVEs:</strong>{' '}
                {fam.anchors.map((a, i) => (
                  <span key={a.cve}>
                    {i > 0 && ', '}
                    <a href={`https://nvd.nist.gov/vuln/detail/${a.cve}`} target="_blank" rel="noreferrer">{a.label}</a>
                  </span>
                ))}
              </p>
            )}
            <ul>
              {fam.demos.map((d) => (
                <li key={d.id}>
                  <a href={`#/demo/${d.id}`}>{d.title}</a> <span className="lang-tag">{d.language_label}</span>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>

      <h2 className="home-sub">Domains cut across families</h2>
      <p className="section-hint">{taxonomy.cross_cutting_note}</p>
      <table className="plain-table">
        <thead><tr><th>Domain (where the flaw lives)</th><th>Families it draws on (how it went wrong)</th></tr></thead>
        <tbody>
          {taxonomy.cross_cutting.map((d) => (
            <tr key={d.name}>
              <td>{d.name}</td>
              <td>{d.families.map((f) => <span key={f} className="pill subtle">{f}</span>)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
