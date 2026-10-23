import React from 'react';

export default function Breadcrumb({ items }) {
  return (
    <div className="breadcrumb" aria-label="Breadcrumb">
      <a href="#/">Home</a>
      {items.map((it, i) => (
        <React.Fragment key={i}>
          <span className="sep">/</span>
          {it.href ? <a href={it.href}>{it.label}</a> : <span>{it.label}</span>}
        </React.Fragment>
      ))}
    </div>
  );
}
