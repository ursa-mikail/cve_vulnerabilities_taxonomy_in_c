// Renders the real app against a running backend:  (cd backend && PORT=4010 node server.js) then  npm test
import React from 'react';
import { describe, it, expect, beforeAll } from 'vitest';
import { render, screen, waitFor, cleanup } from '@testing-library/react';
import App from './App.jsx';

const BACKEND = process.env.BACKEND || 'http://localhost:4010';
beforeAll(() => {
  const real = globalThis.fetch;
  globalThis.fetch = (u, o) => real(String(u).startsWith('/') ? BACKEND + u : u, o);
});

async function open(hash) {
  cleanup();
  window.location.hash = hash;
  render(<App />);
}

describe('tabs render real data', () => {
  it('home lists 14 families and non-C demos', async () => {
    await open('#/');
    await waitFor(() => expect(screen.getAllByText(/Spatial Memory Safety/).length).toBeGreaterThan(0));
    expect(screen.getAllByText('JavaScript (Node.js)').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Python 3').length).toBeGreaterThan(0);
    expect(document.body.textContent).not.toMatch(/Twelve/);
    expect(document.body.textContent).not.toMatch(/C Vulnerability Taxonomy/);
  });

  it('explore filters by OS + language and shows demos', async () => {
    await open('#/explore?lang=php&system=web');
    await waitFor(() => expect(screen.getAllByText(/matching CVEs/).length).toBeGreaterThan(0));
    await waitFor(() => expect(document.body.textContent).toMatch(/SQL injection/));
    expect(document.body.textContent).toMatch(/Cross-site scripting/);
    expect(screen.getAllByText(/Python 3|JavaScript \(Node\.js\)/).length).toBeGreaterThan(0);
  });

  it('explore with an impossible combination says so', async () => {
    await open('#/explore?os=rtos&lang=php&family=F13');
    await waitFor(() => expect(document.body.textContent).toMatch(/No CVEs match|matching CVEs/));
  });

  it('coverage answers the coverage question', async () => {
    await open('#/coverage');
    await waitFor(() => expect(screen.getByText(/Does the taxonomy cover all of CVE/)).toBeTruthy());
    await waitFor(() => expect(document.body.textContent).toMatch(/CWE-707/));
    expect(document.body.textContent).toMatch(/no demo yet/);
  });

  it('a non-C demo page shows its language', async () => {
    await open('#/demo/f5_sql_injection');
    await waitFor(() => expect(document.body.textContent).toMatch(/SQL injection through string-built queries/));
    expect(document.body.textContent).toMatch(/Python 3/);
  });
});
