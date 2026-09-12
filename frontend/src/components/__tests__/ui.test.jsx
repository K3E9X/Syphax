/* The primitives, and in particular the three states a panel must keep
 * distinguishable: loading, broken, and genuinely empty. Collapsing them into
 * one blank area is the failure this whole refactor exists to remove.
 */
import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { Async, Empty, Notice, fmtTokens, fmtUsd } from '../ui.jsx';

describe('Notice', () => {
  it('renders nothing when there is no message', () => {
    // Lets a page write <Notice message={error} /> unconditionally.
    expect(render(<Notice message={null} />).container.innerHTML).toBe('');
    expect(render(<Notice message="" />).container.innerHTML).toBe('');
    expect(render(<Notice />).container.innerHTML).toBe('');
  });

  it('shows the message it is given', () => {
    render(<Notice title="Backend unreachable" message="Failed to fetch" />);
    expect(screen.getByText('Failed to fetch')).toBeTruthy();
    expect(screen.getByText('Backend unreachable')).toBeTruthy();
  });

  it('announces an error to assistive technology', () => {
    render(<Notice kind="error" message="boom" />);
    expect(screen.getByRole('alert')).toBeTruthy();
  });

  it('uses a non-interrupting role for a warning', () => {
    render(<Notice kind="warn" message="budget" />);
    expect(screen.getByRole('status')).toBeTruthy();
  });

  it('offers a retry only when the caller can retry', () => {
    const onRetry = vi.fn();
    render(<Notice message="down" onRetry={onRetry} />);
    screen.getByRole('button', { name: /retry/i }).click();
    expect(onRetry).toHaveBeenCalledOnce();

    render(<Notice message="down" />);
    expect(screen.queryAllByRole('button')).toHaveLength(1);  // only the first one
  });
});

describe('Async', () => {
  const child = <div>content</div>;

  it('shows an error instead of the content, with a retry', () => {
    const onRetry = vi.fn();
    render(<Async loading={false} error="API is down" data={null} onRetry={onRetry}>{child}</Async>);
    expect(screen.getByRole('alert').textContent).toContain('API is down');
    expect(screen.queryByText('content')).toBeNull();
  });

  it('prefers the error even while loading', () => {
    render(<Async loading error="down" data={null}>{child}</Async>);
    expect(screen.getByRole('alert')).toBeTruthy();
  });

  it('distinguishes "not fetched yet" from "nothing found"', () => {
    const { unmount } = render(<Async loading data={null}>{child}</Async>);
    expect(screen.getByText(/loading/i)).toBeTruthy();
    unmount();

    render(<Async loading={false} data={[]}>{child}</Async>);
    expect(screen.queryByText(/loading/i)).toBeNull();
    expect(screen.getByText(/nothing here yet/i)).toBeTruthy();
  });

  it('keeps showing data while a refresh is in flight', () => {
    // A poll must not blank the panel every tick.
    render(<Async loading data={[1]} >{child}</Async>);
    expect(screen.getByText('content')).toBeTruthy();
  });

  it('renders the content when there is data', () => {
    render(<Async loading={false} error={null} data={[1]}>{child}</Async>);
    expect(screen.getByText('content')).toBeTruthy();
  });

  it('takes a caller-supplied emptiness test', () => {
    render(<Async loading={false} data={{ items: [] }} empty="No calls yet."
                  isEmpty={(d) => !d.items.length}>{child}</Async>);
    expect(screen.getByText('No calls yet.')).toBeTruthy();
  });
});

describe('Empty', () => {
  it('has a default message', () => {
    render(<Empty />);
    expect(screen.getByText(/nothing here yet/i)).toBeTruthy();
  });
});

describe('formatters', () => {
  it('scales tokens so 1.2M does not read as 1200000', () => {
    expect(fmtTokens(1_240_000)).toBe('1.24M');
    expect(fmtTokens(12_400)).toBe('12.4k');
    expect(fmtTokens(940)).toBe('940');
    expect(fmtTokens(0)).toBe('0');
  });

  it('never prints NaN for a missing figure', () => {
    expect(fmtTokens(undefined)).toBe('0');
    expect(fmtTokens(null)).toBe('0');
    expect(fmtUsd(undefined)).toBe('$0.00');
    expect(fmtUsd('nope')).toBe('$0.00');
  });

  it('keeps sub-cent LLM costs visible at four decimals', () => {
    expect(fmtUsd(0.0042, 4)).toBe('$0.0042');
    expect(fmtUsd(0.0042)).toBe('$0.00');   // the 2-decimal default rounds it away
  });
});
