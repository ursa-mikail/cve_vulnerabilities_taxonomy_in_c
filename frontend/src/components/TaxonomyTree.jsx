import React, { useState } from 'react';

export default function TaxonomyTree({ families, currentId }) {
  const [open, setOpen] = useState(() => new Set(families.map((f) => f.id)));

  function toggle(id) {
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  return (
    <nav className="tree" aria-label="Vulnerability family taxonomy">
      {families.map((fam) => (
        <div key={fam.id} className="tree-family">
          <button className="tree-family-btn" onClick={() => toggle(fam.id)}>
            <span className={`chevron ${open.has(fam.id) ? 'open' : ''}`}>&#9656;</span>
            <span className="fam-id">{fam.id}</span>
            <span className="fam-name">{fam.name}</span>
          </button>
          {open.has(fam.id) && (
            <ul className="tree-demos">
              {fam.demos.length === 0 && <li className="tree-empty">No demos yet</li>}
              {fam.demos.map((d) => (
                <li key={d.id}>
                  <a href={`#/demo/${d.id}`} className={d.id === currentId ? 'active' : ''}>
                    {d.title}
                  </a>
                </li>
              ))}
            </ul>
          )}
        </div>
      ))}
    </nav>
  );
}
