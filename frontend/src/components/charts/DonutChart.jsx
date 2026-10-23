import React, { useRef, useState } from 'react';
import ChartTooltip from './ChartTooltip.jsx';

const SIZE = 180;
const R = 70;
const HOLE = 42;
const CX = SIZE / 2;
const CY = SIZE / 2;

function arcPath(startAngle, endAngle, r, hole) {
  const toXY = (angle, radius) => [CX + radius * Math.cos(angle), CY + radius * Math.sin(angle)];
  const [x0, y0] = toXY(startAngle, r);
  const [x1, y1] = toXY(endAngle, r);
  const [x2, y2] = toXY(endAngle, hole);
  const [x3, y3] = toXY(startAngle, hole);
  const large = endAngle - startAngle > Math.PI ? 1 : 0;
  return [
    `M ${x0} ${y0}`,
    `A ${r} ${r} 0 ${large} 1 ${x1} ${y1}`,
    `L ${x2} ${y2}`,
    `A ${hole} ${hole} 0 ${large} 0 ${x3} ${y3}`,
    'Z',
  ].join(' ');
}

// segments: [{ label, value, color }]
export default function DonutChart({ segments, centerLabel }) {
  const containerRef = useRef(null);
  const [hover, setHover] = useState(null);
  const total = Math.max(1, segments.reduce((a, s) => a + s.value, 0));

  let angle = -Math.PI / 2;
  const arcs = segments
    .filter((s) => s.value > 0)
    .map((s) => {
      const span = (s.value / total) * Math.PI * 2;
      const a0 = angle;
      const a1 = angle + span;
      angle = a1;
      return { ...s, d: arcPath(a0, a1, R, HOLE), pct: (100 * s.value) / total };
    });

  function handleMove(e) {
    const rect = containerRef.current.getBoundingClientRect();
    setHover((h) => (h ? { ...h, x: e.clientX - rect.left, y: e.clientY - rect.top } : h));
  }

  return (
    <div className="chart-wrap donut-wrap" ref={containerRef} onMouseMove={handleMove}>
      <svg viewBox={`0 0 ${SIZE} ${SIZE}`} className="donut-svg">
        {arcs.map((a) => (
          <path
            key={a.label}
            d={a.d}
            fill={a.color}
            className={`donut-arc ${hover?.label === a.label ? 'active' : ''}`}
            onMouseEnter={(e) => {
              const rect = containerRef.current.getBoundingClientRect();
              setHover({ label: a.label, value: a.value, pct: a.pct, x: e.clientX - rect.left, y: e.clientY - rect.top });
            }}
            onMouseLeave={() => setHover(null)}
          />
        ))}
        <text x={CX} y={CY - 2} textAnchor="middle" className="donut-center-value">
          {total.toLocaleString()}
        </text>
        <text x={CX} y={CY + 14} textAnchor="middle" className="donut-center-label">
          {centerLabel}
        </text>
      </svg>
      <div className="donut-legend">
        {segments.map((s) => (
          <div key={s.label} className="legend-item">
            <span className="swatch" style={{ background: s.color }} /> {s.label}
            <span className="legend-count">{s.value.toLocaleString()}</span>
          </div>
        ))}
      </div>
      {hover && (
        <ChartTooltip x={hover.x} y={hover.y}>
          <strong>{hover.label}</strong>
          <div>
            {hover.value.toLocaleString()} ({hover.pct.toFixed(1)}%)
          </div>
        </ChartTooltip>
      )}
    </div>
  );
}
