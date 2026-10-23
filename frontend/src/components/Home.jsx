import React from 'react';

export default function Home({ families }) {
  return (
    <div className="panel">
      <h1>C Vulnerability Taxonomy Lab</h1>
      <p>
        Twelve vulnerability families, each with a real compiled C demo: the vulnerable version
        runs in a sandboxed container so you can see exactly what goes wrong, next to the fixed
        version and the concrete defenses that stop it. Pick a family from the left, or jump
        straight to a demo below.
      </p>
      <div className="home-grid">
        {families.map((fam) => (
          <div key={fam.id} className="home-card">
            <h2>
              {fam.id} &middot; {fam.name}
            </h2>
            <p>{fam.blurb}</p>
            <ul>
              {fam.demos.map((d) => (
                <li key={d.id}>
                  <a href={`#/demo/${d.id}`}>{d.title}</a>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </div>
  );
}
