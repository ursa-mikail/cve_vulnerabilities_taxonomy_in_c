import React, { useRef, useState } from 'react';
import ChartTooltip from './ChartTooltip.jsx';

// data: [{ id, label, value, color }]
export default function BarChart({ data, height = 260, onBarClick, selectedId, valueLabel = 'CVEs' }) {
  const containerRef = useRef(null);
  const [hover, setHover] = useState(null); // { index, x, y }

  const max = Math.max(1, ...data.map((d) => d.value));
  const barGap = 10;
  const widthPerBar = 100 / data.length;

  function handleMove(e, i) {
    const rect = containerRef.current.getBoundingClientRect();
    setHover({ index: i, x: e.clientX - rect.left, y: e.clientY - rect.top });
  }

  return (
    <div className="chart-wrap" ref={containerRef} style={{ height }}>
      <div className="bar-chart">
        {data.map((d, i) => {
          const h = Math.max(2, (d.value / max) * 100);
          const active = hover?.index === i;
          const selected = selectedId && d.id === selectedId;
          return (
            <div
              key={d.id}
              className={`bar-col ${active ? 'active' : ''} ${selected ? 'selected' : ''}`}
              style={{ width: `calc(${widthPerBar}% - ${barGap}px)` }}
              onMouseMove={(e) => handleMove(e, i)}
              onMouseLeave={() => setHover(null)}
              onClick={() => onBarClick && onBarClick(d)}
            >
              <div className="bar-value-ghost">{d.value.toLocaleString()}</div>
              <div
                className="bar"
                style={{ height: `${h}%`, background: d.color || 'var(--accent)' }}
              />
              <div className="bar-label">{d.label}</div>
            </div>
          );
        })}
      </div>
      {hover && (
        <ChartTooltip x={hover.x} y={hover.y}>
          <strong>{data[hover.index].fullLabel || data[hover.index].label}</strong>
          <div>
            {data[hover.index].value.toLocaleString()} {valueLabel}
          </div>
        </ChartTooltip>
      )}
    </div>
  );
}
