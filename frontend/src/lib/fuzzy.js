// Fuzzy subsequence matching for the command palette.
//
// A palette lives or dies on ranking: type "sqli findings" and the SQL
// injection finding has to beat a page called "Settings" that also happens to
// contain s-e-t-t... The scoring here rewards the things a human means by "that
// matches" - the query appearing as a run, at a word start, near the front -
// so the obvious hit sorts first without the operator thinking about it.
//
// Pure and dependency-free, so the ranking is unit-tested rather than eyeballed.

const WORD_BOUNDARY = /[\s\-_/.:>]/;

/**
 * Score how well `query` matches `text`. Higher is better; null means no match.
 *
 * Every character of the (lowercased) query must appear in order in the text -
 * a subsequence, the same rule editors use for "go to file". The score then
 * layers on the signals that separate a good match from a technically-true one.
 */
export function score(query, text) {
  const q = (query || '').toLowerCase().trim();
  const t = (text || '').toLowerCase();
  if (!q) return 0;
  if (!t) return null;

  // A direct substring is the strongest signal and the common case; score it
  // high, with a bonus for matching at the very start or at a word boundary.
  const idx = t.indexOf(q);
  if (idx !== -1) {
    let s = 100 - idx;                      // earlier is better
    if (idx === 0) s += 60;                 // prefix
    else if (WORD_BOUNDARY.test(t[idx - 1])) s += 30;  // word start
    s += Math.max(0, 20 - (t.length - q.length)); // tighter is better
    return s;
  }

  // Otherwise fall back to a subsequence walk, rewarding contiguous runs and
  // matches that land at word boundaries.
  let ti = 0;
  let s = 0;
  let run = 0;
  let matched = 0;
  for (let qi = 0; qi < q.length; qi += 1) {
    const ch = q[qi];
    let found = -1;
    for (let j = ti; j < t.length; j += 1) {
      if (t[j] === ch) { found = j; break; }
    }
    if (found === -1) return null;          // character missing -> no match
    matched += 1;
    if (found === ti) { run += 1; s += 5 + run * 2; }  // contiguous
    else { run = 0; s += 1; }
    if (found === 0 || WORD_BOUNDARY.test(t[found - 1])) s += 8;  // word start
    ti = found + 1;
  }
  if (matched !== q.length) return null;
  return s - Math.floor(t.length / 20);     // gently prefer shorter texts
}

/**
 * Rank items against a query. Each item is scored on its label plus any extra
 * keywords (a finding's target, an engagement's host), and the best of those
 * wins. With an empty query, order is preserved so the palette shows a sensible
 * default list rather than nothing.
 */
export function rank(query, items, { keys = ['label'], limit = 50 } = {}) {
  const q = (query || '').trim();
  if (!q) return items.slice(0, limit);

  const scored = [];
  for (const item of items) {
    let best = null;
    for (const key of keys) {
      const value = typeof key === 'function' ? key(item) : item[key];
      if (value == null) continue;
      const s = score(q, String(value));
      if (s != null && (best == null || s > best)) best = s;
    }
    if (best != null) scored.push([best, item]);
  }
  // Stable sort by score descending; ties keep input order (a for-loop index
  // is not needed - Array.sort is stable in every engine we target).
  scored.sort((a, b) => b[0] - a[0]);
  return scored.slice(0, limit).map(([, item]) => item);
}
