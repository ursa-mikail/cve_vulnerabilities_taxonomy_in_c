import React, { useRef, useState } from 'react';
import ChartTooltip from './ChartTooltip.jsx';

// items: [{ name, count }]
export default function HBarList({ items, color = 'var(--accent)', valueLabel = 'CVEs' }) {
  const containerRef = useRef(null);
  const [hover, setHover] = useState(null);
  const max = Math.max(1, ...items.map((i) => i.count));

  return (
    <div className="hbar-list" ref={containerRef}>
      {items.map((it, i) => (
        <div
          key={it.name}
          className="hbar-row"
          onMouseMove={(e) => {
            const rect = containerRef.current.getBoundingClientRect();
            setHover({ index: i, x: e.clientX - rect.left, y: e.clientY - rect.top });
          }}
          onMouseLeave={() => setHover(null)}
        >
          <div className="hbar-name" title={it.name}>{it.name}</div>
          <div className="hbar-track">
            <div
              className={`hbar-fill ${hover?.index === i ? 'active' : ''}`}
              style={{ width: `${Math.max(3, (it.count / max) * 100)}%`, background: color }}
            />
          </div>
          <div className="hbar-count">{it.count.toLocaleString()}</div>
        </div>
      ))}
      {hover && (
        <ChartTooltip x={hover.x} y={hover.y}>
          <strong>{items[hover.index].name}</strong>
          <div>{items[hover.index].count.toLocaleString()} {valueLabel}</div>
        </ChartTooltip>
      )}
    </div>
  );
}
