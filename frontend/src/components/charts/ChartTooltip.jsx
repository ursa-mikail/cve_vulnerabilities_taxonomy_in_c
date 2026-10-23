import React from 'react';

// Positioned absolutely within a `position: relative` chart container.
// `x`/`y` are in pixels relative to that container's top-left corner.
export default function ChartTooltip({ x, y, children, align = 'center' }) {
  if (x == null || y == null) return null;
  const style = {
    left: x,
    top: y,
    transform:
      align === 'left' ? 'translate(0, -110%)' : align === 'right' ? 'translate(-100%, -110%)' : 'translate(-50%, -112%)',
  };
  return (
    <div className="chart-tooltip" style={style}>
      {children}
    </div>
  );
}
