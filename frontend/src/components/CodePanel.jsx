import React from 'react';

export default function CodePanel({ code, language, variant }) {
  return (
    <div className="code-wrap">
      <div className="code-caption">
        <span>{variant === 'fixed' ? 'fixed' : 'vulnerable'}</span>
        <span className="lang-tag">{language}</span>
      </div>
      <pre className="code-panel">
        <code>{code}</code>
      </pre>
    </div>
  );
}
