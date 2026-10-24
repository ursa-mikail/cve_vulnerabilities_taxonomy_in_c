import React, { useEffect, useState } from 'react';
import { getTaxonomy } from './api.js';
import TaxonomyTree from './components/TaxonomyTree.jsx';
import DemoView from './components/DemoView.jsx';
import Home from './components/Home.jsx';
import AnalyticsPage from './components/AnalyticsPage.jsx';
import ExplorePage from './components/ExplorePage.jsx';
import CoveragePage from './components/CoveragePage.jsx';

// Routes live in the URL hash so every view is bookmarkable:
//   #/  #/demo/<id>  #/analytics  #/explore?os=linux&lang=c_cpp  #/coverage  #/about
export function parseHash() {
  const raw = window.location.hash.replace(/^#/, '');
  const [h, query = ''] = raw.split('?');
  const m = h.match(/^\/demo\/([^/]+)$/);
  if (m) return { route: 'demo', id: decodeURIComponent(m[1]) };
  if (h === '/about') return { route: 'about' };
  if (h === '/analytics') return { route: 'analytics' };
  if (h === '/coverage') return { route: 'coverage' };
  if (h === '/explore') return { route: 'explore', params: new URLSearchParams(query) };
  return { route: 'home' };
}

function About({ taxonomy }) {
  return (
    <div className="panel">
      <h1>How this works</h1>
      <h2>What the taxonomy is</h2>
      <p>
        {taxonomy ? taxonomy.scope : ''} It is built from the full CVE Program record set and organises every record by{' '}
        <em>how the system went wrong</em>, not by the language it was written in or the product it affects.
      </p>
      <h2>What the demos are</h2>
      <p>
        Each demo is a small, fixed program written for this lab -- nothing is compiled or run from arbitrary input. The
        vulnerable and fixed versions are run side by side in a sandbox so you can see the mistake and the fix.
        The language is incidental: C shows memory and OS-level mistakes with AddressSanitizer / ThreadSanitizer /
        UndefinedBehaviorSanitizer; JavaScript (Node.js) and Python show injection, logic, authorization, and
        supply-chain mistakes, which dominate the CVE record and have nothing to do with C. Each demo says which language
        it uses; the same weakness exists in many others.
      </p>
      <h2>What the tabs do</h2>
      <ul>
        <li><strong>Analytics</strong>: how many CVEs fall in each family, over time, by severity, vendor and product.</li>
        <li><strong>Explore</strong>: filter the CVE record by operating system, programming language, system type, family, year, and evidence strength, and jump to the demos that match.</li>
        <li><strong>Coverage</strong>: does the taxonomy cover all of CVE? Every subcategory, how many CVEs it holds, whether a demo exists, and how strong the evidence behind each mapping is.</li>
      </ul>
      <p>
        This is an educational sandbox, not a general-purpose code runner: you cannot submit your own code. See{' '}
        <code>SECURITY.md</code> for the protections and their limits.
      </p>
    </div>
  );
}

export default function App() {
  const [taxonomy, setTaxonomy] = useState(null);
  const [error, setError] = useState(null);
  const [route, setRoute] = useState(parseHash());

  useEffect(() => {
    getTaxonomy()
      .then(setTaxonomy)
      .catch((e) => setError(e.message));
    const onHash = () => setRoute(parseHash());
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);

  const families = taxonomy ? taxonomy.families : null;
  const nav = (r, label) => (
    <a href={`#/${r}`} className={`about-link ${route.route === r ? 'current' : ''}`}>{label}</a>
  );

  return (
    <div className="app">
      <header className="topbar">
        <a href="#/" className="brand">CVE Weakness Taxonomy Lab</a>
        <nav className="topnav">
          {nav('analytics', 'Analytics')}
          {nav('explore', 'Explore')}
          {nav('coverage', 'Coverage')}
          {nav('about', 'How this works')}
        </nav>
      </header>
      <div className="body">
        <aside className="sidebar">
          {families ? (
            <TaxonomyTree families={families} currentId={route.route === 'demo' ? route.id : null} />
          ) : (
            <div className="sidebar-loading">Loading taxonomy...</div>
          )}
        </aside>
        <main className="content">
          {error && <div className="panel error">Could not reach the backend: {error}</div>}
          {!error && !families && <div className="panel">Loading...</div>}
          {!error && families && route.route === 'home' && <Home taxonomy={taxonomy} />}
          {!error && families && route.route === 'about' && <About taxonomy={taxonomy} />}
          {!error && families && route.route === 'analytics' && <AnalyticsPage families={families} />}
          {!error && families && route.route === 'explore' && <ExplorePage params={route.params} families={families} />}
          {!error && families && route.route === 'coverage' && <CoveragePage />}
          {!error && families && route.route === 'demo' && <DemoView demoId={route.id} families={families} />}
        </main>
      </div>
    </div>
  );
}
