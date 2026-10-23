import React, { useEffect, useState } from 'react';
import { getDemo, runDemo } from '../api.js';
import CodePanel from './CodePanel.jsx';
import OutputPanel from './OutputPanel.jsx';
import Breadcrumb from './Breadcrumb.jsx';

export default function DemoView({ demoId, families }) {
  const [demo, setDemo] = useState(null);
  const [error, setError] = useState(null);
  const [variant, setVariant] = useState('vulnerable');
  const [results, setResults] = useState({ vulnerable: null, fixed: null });
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setDemo(null);
    setError(null);
    setResults({ vulnerable: null, fixed: null });
    setVariant('vulnerable');
    getDemo(demoId).then(setDemo).catch((e) => setError(e.message));
  }, [demoId]);

  if (error) {
    return (
      <div className="panel">
        <p>
          Could not load demo "{demoId}". <a href="#/">Go back home.</a>
        </p>
      </div>
    );
  }
  if (!demo) return <div className="panel">Loading...</div>;

  async function handleRun() {
    setLoading(true);
    try {
      const result = await runDemo(demo.id, variant);
      setResults((prev) => ({ ...prev, [variant]: result }));
    } catch (e) {
      setResults((prev) => ({
        ...prev,
        [variant]: { stage: 'run', stdout: '', stderr: String(e), exitCode: null },
      }));
    } finally {
      setLoading(false);
    }
  }

  const flat = families.flatMap((f) => f.demos.map((d) => ({ ...d, familyId: f.id })));
  const idx = flat.findIndex((d) => d.id === demo.id);
  const prev = idx > 0 ? flat[idx - 1] : null;
  const next = idx >= 0 && idx < flat.length - 1 ? flat[idx + 1] : null;

  return (
    <div className="panel">
      <Breadcrumb items={[{ label: `${demo.family} \u00b7 ${demo.family_name}` }, { label: demo.title }]} />
      <h1>{demo.title}</h1>
      <div className="demo-meta">
        <span className="pill">{demo.family}</span>
        <span className="pill">{demo.cwe}</span>
        <span className="pill subtle">{demo.subcategory}</span>
      </div>
      <p className="root-cause">
        <strong>Root cause:</strong> {demo.root_cause}
      </p>

      <div className="tabs">
        <button className={variant === 'vulnerable' ? 'active' : ''} onClick={() => setVariant('vulnerable')}>
          Vulnerable version
        </button>
        <button className={variant === 'fixed' ? 'active' : ''} onClick={() => setVariant('fixed')}>
          Fixed version
        </button>
      </div>

      <div className="demo-grid">
        <div>
          <CodePanel code={variant === 'vulnerable' ? demo.code.vulnerable : demo.code.fixed} />
          <button className="run-btn" onClick={handleRun} disabled={loading}>
            {loading ? 'Running...' : `Run ${variant} version in sandbox`}
          </button>
          <OutputPanel result={results[variant]} loading={loading} />
        </div>
        <aside className="defenses">
          <h2>Defenses</h2>
          <ul>
            {demo.defenses.map((d, i) => (
              <li key={i}>{d}</li>
            ))}
          </ul>
        </aside>
      </div>

      <div className="pager">
        {prev ? <a href={`#/demo/${prev.id}`}>&larr; {prev.title}</a> : <span />}
        {next ? <a href={`#/demo/${next.id}`}>{next.title} &rarr;</a> : <span />}
      </div>
    </div>
  );
}
