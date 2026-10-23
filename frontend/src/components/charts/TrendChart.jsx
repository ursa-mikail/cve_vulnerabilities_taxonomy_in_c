import React, { useMemo, useRef, useState } from 'react';
import ChartTooltip from './ChartTooltip.jsx';

const W = 760;
const H = 260;
const PAD_L = 36;
const PAD_B = 22;
const PAD_T = 10;
const PAD_R = 10;

// years: ["1999", ..., "2026"]; series: [{ id, name, color, values: [n, n, ...] }] (same length as years)
export default function TrendChart({ years, series }) {
  const containerRef = useRef(null);
  const [hoverIdx, setHoverIdx] = useState(null);
  const [mouse, setMouse] = useState(null);

  const max = useMemo(() => Math.max(1, ...series.flatMap((s) => s.values)), [series]);

  const innerW = W - PAD_L - PAD_R;
  const innerH = H - PAD_T - PAD_B;
  const n = years.length;
  const xAt = (i) => PAD_L + (n <= 1 ? 0 : (i / (n - 1)) * innerW);
  const yAt = (v) => PAD_T + innerH - (v / max) * innerH;

  const paths = useMemo(
    () =>
      series.map((s) => ({
        ...s,
        d: s.values.map((v, i) => `${i === 0 ? 'M' : 'L'} ${xAt(i).toFixed(1)} ${yAt(v).toFixed(1)}`).join(' '),
      })),
    [series, max, n]
  );

  const yTicks = [0, 0.25, 0.5, 0.75, 1].map((f) => Math.round(f * max));
  const xLabelEvery = Math.max(1, Math.ceil(n / 10));

  function handleMove(e) {
    const rect = containerRef.current.getBoundingClientRect();
    const px = e.clientX - rect.left;
    const scale = rect.width / W; // SVG is responsive (viewBox), convert back to SVG units
    const svgX = px / scale;
    const relative = (svgX - PAD_L) / innerW;
    let idx = Math.round(relative * (n - 1));
    idx = Math.max(0, Math.min(n - 1, idx));
    setHoverIdx(idx);
    setMouse({ x: px, y: e.clientY - rect.top });
  }

  return (
    <div className="chart-wrap trend-wrap" ref={containerRef}>
      <svg
        viewBox={`0 0 ${W} ${H}`}
        className="trend-svg"
        onMouseMove={handleMove}
        onMouseLeave={() => { setHoverIdx(null); setMouse(null); }}
      >
        {yTicks.map((t, i) => (
          <g key={i}>
            <line x1={PAD_L} x2={W - PAD_R} y1={yAt(t)} y2={yAt(t)} className="grid-line" />
            <text x={4} y={yAt(t) + 4} className="axis-label">{t.toLocaleString()}</text>
          </g>
        ))}
        {years.map((y, i) =>
          i % xLabelEvery === 0 ? (
            <text key={y} x={xAt(i)} y={H - 4} textAnchor="middle" className="axis-label">{y}</text>
          ) : null
        )}
        {hoverIdx != null && (
          <line x1={xAt(hoverIdx)} x2={xAt(hoverIdx)} y1={PAD_T} y2={H - PAD_B} className="crosshair" />
        )}
        {paths.map((p) => (
          <path key={p.id} d={p.d} fill="none" stroke={p.color} strokeWidth={2.2} className="trend-line" />
        ))}
        {hoverIdx != null &&
          paths.map((p) => (
            <circle key={p.id} cx={xAt(hoverIdx)} cy={yAt(p.values[hoverIdx])} r={3.5} fill={p.color} stroke="#0a0e13" strokeWidth={1.2} />
          ))}
      </svg>
      {hoverIdx != null && mouse && (
        <ChartTooltip x={mouse.x} y={mouse.y} align={hoverIdx > n * 0.7 ? 'right' : 'left'}>
          <strong>{years[hoverIdx]}</strong>
          {paths.map((p) => (
            <div key={p.id} className="tooltip-row">
              <span className="swatch" style={{ background: p.color }} />
              {p.name}: <strong>{p.values[hoverIdx].toLocaleString()}</strong>
            </div>
          ))}
        </ChartTooltip>
      )}
      <div className="trend-legend">
        {series.map((s) => (
          <span key={s.id} className="legend-item">
            <span className="swatch" style={{ background: s.color }} /> {s.name}
          </span>
        ))}
      </div>
    </div>
  );
}
