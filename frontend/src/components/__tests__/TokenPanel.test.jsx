/* The token panel.
 *
 * Its whole reason for existing is the question the old UI could not answer:
 * which part of the system is spending this. The planner runs once per loop
 * iteration, so a role breakdown is what turns "the run cost $4" into "the
 * planner cost $4".
 */
import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import TokenPanel, { PromptSplit, Sparkline } from '../TokenPanel.jsx';

const USAGE = {
  calls: 42,
  prompt_tokens: 180_000,
  completion_tokens: 20_000,
  total_tokens: 200_000,
  cost_usd: 1.2345,
  tokens_per_min: 5400,
  confirmed_findings: 3,
  cost_per_finding_usd: 0.4115,
  by_role: [
    { key: 'planner', calls: 30, tokens: 150_000, cost_usd: 0.9, pct: 75 },
    { key: 'validator', calls: 12, tokens: 50_000, cost_usd: 0.33, pct: 25 },
  ],
  timeline: { buckets: [10, 50, 5, 0, 90], bucket_seconds: 12 },
  top_calls: [
    { ts: Date.now() / 1000 - 30, role: 'planner', model: 'kimi-k3', tokens: 82_000, cost_usd: 0.51 },
  ],
  budget: { limit_usd: 0, spend_usd: 1.2345, over: false, pct: 0 },
};

describe('TokenPanel', () => {
  it('names the role that is spending, which the per-model bar never could', () => {
    render(<TokenPanel usage={USAGE} loading={false} error={null} />);
    // "Planner" appears in the role breakdown AND in the most-expensive-calls
    // list, which is the point: the same culprit named twice.
    expect(screen.getAllByText('Planner').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText('Validator')).toBeTruthy();
  });

  it('shows the burn rate so a run can be judged while it runs', () => {
    render(<TokenPanel usage={USAGE} loading={false} error={null} />);
    expect(screen.getByText('5.4k/min')).toBeTruthy();
  });

  it('shows the cost per confirmed finding when there is one', () => {
    render(<TokenPanel usage={USAGE} loading={false} error={null} />);
    expect(screen.getByText('Per finding')).toBeTruthy();
    expect(screen.getByText(/^\$0\.41/)).toBeTruthy();
  });

  it('hides the per-finding ratio when nothing is confirmed', () => {
    // Dividing by zero findings would report an infinite or absurd cost.
    render(<TokenPanel usage={{ ...USAGE, confirmed_findings: 0, cost_per_finding_usd: 0 }}
                       loading={false} error={null} />);
    expect(screen.queryByText('Per finding')).toBeNull();
  });

  it('lists the single most expensive call, not just the total', () => {
    render(<TokenPanel usage={USAGE} loading={false} error={null} />);
    expect(screen.getByText('kimi-k3')).toBeTruthy();
    expect(screen.getByText(/82\.0k/)).toBeTruthy();
  });

  it('warns and explains when the engagement budget is reached', () => {
    render(<TokenPanel loading={false} error={null}
                       usage={{ ...USAGE, budget: { limit_usd: 1, spend_usd: 1.23, over: true, pct: 123 } }} />);
    expect(screen.getByText(/Engagement budget reached/)).toBeTruthy();
    expect(screen.getByText(/Settings/)).toBeTruthy();
  });

  it('says so plainly when no call has been made', () => {
    render(<TokenPanel usage={{ calls: 0 }} loading={false} error={null} />);
    expect(screen.getByText(/No LLM calls on this engagement yet/)).toBeTruthy();
  });

  it('surfaces a fetch failure with a retry rather than showing zeros', () => {
    // Showing "0 tokens" for a failed request is the exact confusion the
    // refactor removes: broken must not look like idle.
    const onRetry = vi.fn();
    render(<TokenPanel usage={null} loading={false} error="API is down" onRetry={onRetry} />);
    expect(screen.getByRole('alert').textContent).toContain('API is down');
    screen.getByRole('button', { name: /retry/i }).click();
    expect(onRetry).toHaveBeenCalledOnce();
  });

  it('drops the timeline and call list in compact mode', () => {
    render(<TokenPanel usage={USAGE} loading={false} error={null} compact />);
    expect(screen.getByText('Planner')).toBeTruthy();          // kept
    expect(screen.queryByText('kimi-k3')).toBeNull();          // dropped
  });

  it('survives a payload missing every optional field', () => {
    expect(() => render(<TokenPanel usage={{ calls: 1 }} loading={false} error={null} />))
      .not.toThrow();
  });
});

describe('PromptSplit', () => {
  it('makes a wasted-context run obvious', () => {
    render(<PromptSplit prompt={950} completion={50} />);
    expect(screen.getByText('95%', { exact: false })).toBeTruthy();
  });

  it('renders nothing with no tokens', () => {
    expect(render(<PromptSplit prompt={0} completion={0} />).container.innerHTML).toBe('');
  });

  it('describes itself to assistive technology', () => {
    render(<PromptSplit prompt={800} completion={200} />);
    expect(screen.getByRole('img').getAttribute('aria-label')).toMatch(/80% prompt/);
  });
});

describe('Sparkline', () => {
  it('scales the bars to the busiest bucket', () => {
    const { container } = render(<Sparkline buckets={[0, 50, 100]} />);
    const bars = container.querySelectorAll('.spark__b');
    expect(bars).toHaveLength(3);
    expect(bars[2].style.height).toBe('100%');
    expect(bars[0].className).toContain('spark__b--empty');
  });

  it('says so when there is nothing to draw', () => {
    render(<Sparkline buckets={[]} />);
    expect(screen.getByText(/No calls recorded yet/)).toBeTruthy();
  });

  it('does not divide by zero on an all-zero series', () => {
    expect(() => render(<Sparkline buckets={[0, 0, 0]} />)).not.toThrow();
  });
});
