import React from 'react';

function statusOf(result) {
  if (!result) return null;
  if (result.stage === 'compile') return 'error';
  if (result.timedOut) return 'warn';
  if (result.sanitizerIssue) return 'error';
  if (result.exitCode === 0) return 'ok';
  return 'warn';
}

export default function OutputPanel({ result, loading }) {
  if (loading) return <div className="output-panel loading">Compiling and running in the sandbox...</div>;
  if (!result)
    return (
      <div className="output-panel empty">
        Click "Run in sandbox" to compile and execute this version.
      </div>
    );

  const status = statusOf(result);
  const labels = {
    ok: 'Ran cleanly',
    warn: result.timedOut ? 'Timed out / resource-limited' : 'Exited with an error',
    error: result.stage === 'compile' ? 'Compile error' : 'Security issue detected',
  };
  const label = labels[status];

  return (
    <div className={`output-panel status-${status}`}>
      <div className="output-header">
        <span className={`badge badge-${status}`}>{label}</span>
        {typeof result.exitCode === 'number' && <span className="meta">exit code {result.exitCode}</span>}
        {result.durationMs != null && <span className="meta">{result.durationMs} ms</span>}
        {result.sanitizerIssue && <span className="meta">{result.sanitizerIssue}</span>}
      </div>
      {result.stdout && (
        <div className="output-block">
          <div className="output-label">stdout</div>
          <pre>{result.stdout}</pre>
        </div>
      )}
      {(result.sanitizerSummary || result.stderr) && (
        <div className="output-block">
          <div className="output-label">
            {result.sanitizerIssue ? `${result.sanitizerIssue} report` : 'stderr'}
          </div>
          <pre>{result.sanitizerSummary || result.stderr}</pre>
        </div>
      )}
    </div>
  );
}
