import React from 'react';

export default function CodePanel({ code }) {
  return (
    <pre className="code-panel">
      <code>{code}</code>
    </pre>
  );
}
