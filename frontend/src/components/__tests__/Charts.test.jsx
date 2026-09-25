/* The shared SVG/CSS charts.
 *
 * These are hand-built (no chart library), so a test pins the load-bearing
 * behaviour: the radar draws one point per axis, the donut draws one arc per
 * non-zero segment and its centre total, the histogram draws a bar per datum,
 * and an all-empty input renders without throwing.
 */
import { render } from '@testing-library/react';
import { expect, it } from 'vitest';
import { Donut, Histogram, Legend, Radar } from '../Charts.jsx';

it('radar plots one vertex per axis', () => {
  const { container } = render(<Radar values={[10, 20, 30, 40, 50, 60]} />);
  // Six axes -> six data-point circles.
  expect(container.querySelectorAll('circle').length).toBe(6);
  // The filled polygon is the last polygon drawn.
  expect(container.querySelector('polygon[fill-opacity]')).toBeTruthy();
});

it('donut draws an arc per non-zero segment and shows the total', () => {
  const segs = [
    { label: 'critical', value: 2, color: '#ef4444' },
    { label: 'high', value: 3, color: '#f97316' },
    { label: 'low', value: 0, color: '#06b6d4' },
  ];
  const { container, getByText } = render(<Donut segments={segs} />);
  // One background ring + one arc for each of the two non-zero segments.
  expect(container.querySelectorAll('circle').length).toBe(3);
  expect(getByText('5')).toBeTruthy();
});

it('donut with all-zero segments renders the ring and a zero, no arcs', () => {
  const { container, getByText } = render(<Donut segments={[{ label: 'x', value: 0, color: '#000' }]} />);
  expect(container.querySelectorAll('circle').length).toBe(1); // just the track ring
  expect(getByText('0')).toBeTruthy();
});

it('histogram draws a bar per datum', () => {
  const { container } = render(<Histogram data={[{ label: 'planner', value: 12 }, { label: 'executor', value: 4 }]} />);
  expect(container.querySelectorAll('.chart-hist__bar').length).toBe(2);
});

it('legend lists each segment with its value', () => {
  const { getByText } = render(<Legend segments={[{ label: 'high', value: 3, color: '#f97316' }]} suffix="%" />);
  expect(getByText('high')).toBeTruthy();
  expect(getByText('3%')).toBeTruthy();
});

it('empty inputs never throw', () => {
  expect(() => render(<Radar values={[]} axes={[]} />)).not.toThrow();
  expect(() => render(<Histogram data={[]} />)).not.toThrow();
  expect(() => render(<Donut segments={[]} />)).not.toThrow();
});
