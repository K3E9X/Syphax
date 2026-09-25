/* Ranking for the command palette.
 *
 * A palette is only as good as its first result. These pin the judgements that
 * make "type a few letters, hit Enter" reliable: a substring beats a scattered
 * subsequence, a word-start beats a mid-word hit, and a missing character means
 * no match rather than a low one.
 */
import { describe, expect, it } from 'vitest';
import { rank, score } from '../fuzzy.js';

describe('score', () => {
  it('returns null when a query character is missing', () => {
    expect(score('xyz', 'findings')).toBeNull();
    expect(score('findz', 'findings')).toBeNull();
  });

  it('scores an empty query as neutral, not a failure', () => {
    expect(score('', 'anything')).toBe(0);
  });

  it('ranks a prefix above a mid-string substring', () => {
    expect(score('set', 'settings')).toBeGreaterThan(score('set', 'reset password'));
  });

  it('ranks a word-start above a mid-word hit', () => {
    // "rec" at the start of "recon" beats "rec" inside "correction".
    expect(score('rec', 'pre-recon')).toBeGreaterThan(score('rec', 'correction'));
  });

  it('rewards contiguous matches over scattered ones', () => {
    expect(score('sqli', 'sqli in login')).toBeGreaterThan(score('sqli', 's q l i spread out'));
  });
});

describe('rank', () => {
  const items = [
    { label: 'Settings', keywords: 'model api key' },
    { label: 'Findings', keywords: 'vulnerabilities' },
    { label: 'SQL injection on /login', keywords: 'sqli api' },
    { label: 'Surface', keywords: 'assets' },
  ];

  it('puts the obvious hit first', () => {
    const out = rank('sqli', items, { keys: ['label', 'keywords'] });
    expect(out[0].label).toBe('SQL injection on /login');
  });

  it('matches on extra keys, not just the label', () => {
    const out = rank('api key', items, { keys: ['label', 'keywords'] });
    expect(out[0].label).toBe('Settings');
  });

  it('drops non-matches entirely', () => {
    const out = rank('zzzz', items, { keys: ['label', 'keywords'] });
    expect(out).toEqual([]);
  });

  it('preserves order and truncates on an empty query', () => {
    const out = rank('', items, { keys: ['label'], limit: 2 });
    expect(out.map((i) => i.label)).toEqual(['Settings', 'Findings']);
  });

  it('honours the limit', () => {
    expect(rank('s', items, { keys: ['label'], limit: 1 }).length).toBe(1);
  });
});
