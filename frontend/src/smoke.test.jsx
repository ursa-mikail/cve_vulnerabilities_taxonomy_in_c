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

  it('browse lists CVEs with descriptions and charts the matching set', async () => {
    await open('#/browse?network=tls&hardware=router&impact=rce');
    await waitFor(() => expect(document.body.textContent).toMatch(/CVEs \([\d,]+\)/), { timeout: 15000 });
    await waitFor(() => expect(document.querySelectorAll('.cve-row').length).toBeGreaterThan(0));
    expect(document.querySelector('.cve-desc').textContent.length).toBeGreaterThan(20);
    expect(document.body.textContent).toMatch(/Weakness families/);
    expect(document.querySelectorAll('input[type=checkbox]:checked').length).toBe(3);
  });

  it('browse autocomplete suggests and applies a filter', async () => {
    await open('#/browse');
    await waitFor(() => expect(document.querySelector('.ac-input')).toBeTruthy());
    const input = document.querySelector('.ac-input');
    const { fireEvent } = await import('@testing-library/react');
    fireEvent.change(input, { target: { value: 'sql inj' } });
    await waitFor(() => expect(document.querySelectorAll('.ac-item').length).toBeGreaterThan(0), { timeout: 5000 });
    expect(document.body.textContent).toMatch(/SQL injection/);
    fireEvent.mouseDown(document.querySelector('.ac-item'));
    await waitFor(() => expect(window.location.hash).toMatch(/#\/browse\?/));
  });

  it('clicking a family bar after an autocomplete search filters by that family (no error)', async () => {
    const { fireEvent } = await import('@testing-library/react');
    await open('#/browse');
    await waitFor(() => expect(document.querySelector('.ac-input')).toBeTruthy());
    fireEvent.change(document.querySelector('.ac-input'), { target: { value: 'aes' } });
    await waitFor(() => expect(document.querySelectorAll('.ac-item').length).toBeGreaterThan(0), { timeout: 5000 });
    fireEvent.mouseDown(document.querySelector('.ac-item'));
    await waitFor(() => expect(document.querySelectorAll('.bar-col').length).toBeGreaterThan(0), { timeout: 10000 });
    const bars = Array.from(document.querySelectorAll('.bar-col'));
    const tallest = bars.sort((a, b) => parseInt(b.querySelector('.bar').style.height) - parseInt(a.querySelector('.bar').style.height))[0];
    fireEvent.click(tallest);
    await waitFor(() => expect(window.location.hash).toMatch(/family=F\d+/));
    await waitFor(() => expect(document.querySelectorAll('.cve-row').length).toBeGreaterThan(0), { timeout: 10000 });
    expect(document.body.textContent).not.toMatch(/object Object|unknown family/);
    expect(document.querySelector('.panel.error')).toBeNull();
  });

  it('explore: clicking a family bar also works', async () => {
    const { fireEvent } = await import('@testing-library/react');
    await open('#/explore?lang=php');
    await waitFor(() => expect(document.querySelectorAll('.bar-col').length).toBeGreaterThan(0), { timeout: 10000 });
    fireEvent.click(document.querySelectorAll('.bar-col')[4]);
    await waitFor(() => expect(window.location.hash).toMatch(/family=F5/));
    await waitFor(() => expect(document.body.textContent).not.toMatch(/object Object|unknown family/));
  });

  it('typing "aes" suggests the AES filter and a description search; both return CVEs that mention AES', async () => {
    const { fireEvent } = await import('@testing-library/react');
    await open('#/browse');
    await waitFor(() => expect(document.querySelector('.ac-input')).toBeTruthy());
    fireEvent.change(document.querySelector('.ac-input'), { target: { value: 'aes' } });
    await waitFor(() => expect(Array.from(document.querySelectorAll('.ac-item')).some((e) => /AES \/ Rijndael/.test(e.textContent))).toBe(true), { timeout: 5000 });
    expect(Array.from(document.querySelectorAll('.ac-item')).some((e) => /Search descriptions for/.test(e.textContent))).toBe(true);
    // pick the AES algorithm filter
    fireEvent.mouseDown(Array.from(document.querySelectorAll('.ac-item')).find((e) => /AES \/ Rijndael/.test(e.textContent)));
    await waitFor(() => expect(window.location.hash).toMatch(/crypto=aes/));
    await waitFor(() => expect(document.querySelectorAll('.cve-row').length).toBeGreaterThan(0), { timeout: 10000 });
    expect(document.body.textContent).not.toMatch(/object Object|unknown family/);
  });

  it('free-text description search works from the autocomplete (Ctrl+Enter)', async () => {
    const { fireEvent } = await import('@testing-library/react');
    await open('#/browse');
    await waitFor(() => expect(document.querySelector('.ac-input')).toBeTruthy());
    const input = document.querySelector('.ac-input');
    fireEvent.change(input, { target: { value: 'padding oracle' } });
    fireEvent.keyDown(input, { key: 'Enter', ctrlKey: true });
    await waitFor(() => expect(window.location.hash).toMatch(/text=padding(\+|%20)oracle/));
    await waitFor(() => expect(document.querySelectorAll('.cve-row').length).toBeGreaterThan(0), { timeout: 15000 });
    expect(Array.from(document.querySelectorAll('.cve-desc')).every((e) => /padding/i.test(e.textContent) && /oracle/i.test(e.textContent))).toBe(true);   // unquoted words are ANDed
  });
});
