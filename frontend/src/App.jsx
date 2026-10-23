import React, { useEffect, useState } from 'react';
import { getTaxonomy } from './api.js';
import TaxonomyTree from './components/TaxonomyTree.jsx';
import DemoView from './components/DemoView.jsx';
import Home from './components/Home.jsx';
import AnalyticsPage from './components/AnalyticsPage.jsx';

function parseHash() {
  const h = window.location.hash.replace(/^#/, '');
  const m = h.match(/^\/demo\/([^/]+)$/);
  if (m) return { route: 'demo', id: decodeURIComponent(m[1]) };
  if (h === '/about') return { route: 'about' };
  if (h === '/analytics') return { route: 'analytics' };
  return { route: 'home' };
}

function About() {
  return (
    <div className="panel">
      <h1>How this works</h1>
      <p>
        Each demo is a small, fixed C program written for this lab -- nothing is compiled from
        arbitrary input. When you click "Run", the backend compiles that exact file with
        AddressSanitizer / UndefinedBehaviorSanitizer (or ThreadSanitizer for the concurrency
        demo) and executes it as a non-root user, with no extra privileges, a capped virtual
        memory limit, a process-count limit, and a hard timeout. The vulnerable versions are
        designed to fail safely inside those limits -- a crash or a sanitizer report stays
        inside its own throwaway process.
      </p>
      <p>
        This is an educational sandbox, not a general-purpose code runner: you cannot submit
        your own C code through this interface. See <code>SECURITY.md</code> in the project for
        the full list of protections and their limits.
      </p>
    </div>
  );
}

export default function App() {
  const [families, setFamilies] = useState(null);
  const [error, setError] = useState(null);
  const [route, setRoute] = useState(parseHash());

  useEffect(() => {
    getTaxonomy()
      .then((d) => setFamilies(d.families))
      .catch((e) => setError(e.message));
    const onHash = () => setRoute(parseHash());
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);

  return (
    <div className="app">
      <header className="topbar">
        <a href="#/" className="brand">
          C Vulnerability Taxonomy Lab
        </a>
        <a href="#/analytics" className="about-link analytics-link">
          Analytics
        </a>
        <a href="#/about" className="about-link">
          How this works
        </a>
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
          {!error && families && route.route === 'home' && <Home families={families} />}
          {!error && families && route.route === 'about' && <About />}
          {!error && families && route.route === 'analytics' && <AnalyticsPage families={families} />}
          {!error && families && route.route === 'demo' && <DemoView demoId={route.id} families={families} />}
        </main>
      </div>
    </div>
  );
}
