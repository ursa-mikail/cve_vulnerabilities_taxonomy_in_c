import React, { useEffect, useRef, useState } from 'react';
import { suggest } from '../api.js';

const TYPE_LABEL = { facet: 'Filter', family: 'Family', subcategory: 'Weakness', cwe: 'CWE', vendor: 'Vendor', product: 'Product', cve: 'CVE', text: 'Text' };

// Search box with live suggestions from the data: filter values (OS, language, protocol...), weakness families,
// subcategories, CWEs, vendors, products and CVE IDs. Picking one adds it as a filter.
export default function Autocomplete({ onPick }) {
  const [q, setQ] = useState('');
  const [items, setItems] = useState([]);
  const [open, setOpen] = useState(false);
  const [hi, setHi] = useState(0);
  const box = useRef(null);
  const seq = useRef(0);

  useEffect(() => {
    if (q.trim().length < 1) { setItems([]); return undefined; }
    const my = ++seq.current;
    const t = setTimeout(() => {
      suggest(q).then((r) => { if (my === seq.current) { setItems(r); setHi(0); } }).catch(() => {});
    }, 140);
    return () => clearTimeout(t);
  }, [q]);

  useEffect(() => {
    const away = (e) => { if (box.current && !box.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', away);
    return () => document.removeEventListener('mousedown', away);
  }, []);

  const withText = q.trim().length >= 2 ? [...items, { type: 'text', label: `Search descriptions for \u201C${q.trim()}\u201D`, value: q.trim(), count: 0 }] : items;
  const pick = (it) => { onPick(it); setQ(''); setItems([]); setOpen(false); };
  const onKey = (e) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setHi((h) => Math.min(h + 1, withText.length - 1)); setOpen(true); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setHi((h) => Math.max(h - 1, 0)); }
    else if (e.key === 'Enter' && (e.ctrlKey || e.metaKey) && q.trim().length >= 2) { e.preventDefault(); pick({ type: 'text', value: q.trim() }); }
    else if (e.key === 'Enter' && open && withText[hi]) { e.preventDefault(); pick(withText[hi]); }
    else if (e.key === 'Escape') setOpen(false);
  };

  return (
    <div className="ac" ref={box}>
      <input className="ac-input" type="search" value={q} placeholder="Search: linux, SQL injection, CWE-79, cisco, CVE-2021-4422..."
        aria-label="Search filters, vendors, products, CWEs and CVE IDs" role="combobox" aria-expanded={open && withText.length > 0}
        onChange={(e) => { setQ(e.target.value); setOpen(true); }} onFocus={() => setOpen(true)} onKeyDown={onKey} />
      {open && q.trim() && (
        <ul className="ac-list" role="listbox">
          {items.length === 0 && <li className="ac-empty">No filter, weakness, vendor, product, CWE or CVE ID matches; you can still search the descriptions.</li>}
          {withText.map((it, i) => (
            <li key={it.type + (it.value || it.key) + i} role="option" aria-selected={i === hi}
              className={`ac-item ${i === hi ? 'hi' : ''}`} onMouseEnter={() => setHi(i)} onMouseDown={(e) => { e.preventDefault(); pick(it); }}>
              <span className={`ac-type t-${it.type}`}>{TYPE_LABEL[it.type]}</span>
              <span className="ac-label">{it.label}</span>
              {it.type === 'facet' && <span className="ac-sub">{it.dim_label}</span>}
              {it.type !== 'cve' && it.type !== 'text' && <span className="ac-n">{it.count.toLocaleString()}</span>}
            </li>
          ))}
        </ul>
      )}
      {open && q.trim() && <div className="ac-hint">Enter picks the highlighted item. Ctrl+Enter searches the description text.</div>}
    </div>
  );
}
