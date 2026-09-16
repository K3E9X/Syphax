/* Data-fetching hooks.
 *
 * Every page used to hand-roll this: 41 useEffect, 27 separate
 * setError/setLoading/setBusy states, 14 useState in Home alone, and three
 * independent setInterval pollers. Two consequences that these hooks exist to
 * remove:
 *
 *   1. Errors were swallowed. Home called four endpoints as
 *      `.then(set).catch(() => {})`, so a dead backend, a wrong API key or a
 *      refused VPN all rendered as "-" with no explanation. For a security
 *      tool "I see no findings" and "the API is down" must never look alike.
 *   2. Polling never stopped. Nothing checked document.visibilityState, so a
 *      forgotten background tab hammered the API forever.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { api } from './api.js';

/** Is the tab currently on screen? Treated as visible when the API is absent. */
export function isVisible() {
  return typeof document === 'undefined' || document.visibilityState !== 'hidden';
}

/**
 * Run an async function and expose { data, error, loading, reload, reset }.
 *
 * `fn` is re-run whenever `deps` change. A result that arrives after unmount
 * (or after a newer call started) is dropped, so a slow response cannot
 * overwrite a fresh one or set state on a dead component.
 */
export function useApi(fn, deps = [], { immediate = true, initial = null } = {}) {
  const [data, setData] = useState(initial);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(Boolean(immediate));
  const alive = useRef(true);
  const seq = useRef(0);
  const fnRef = useRef(fn);
  fnRef.current = fn;

  useEffect(() => {
    alive.current = true;
    return () => { alive.current = false; };
  }, []);

  const run = useCallback(async (...args) => {
    const mine = ++seq.current;
    setLoading(true);
    try {
      const result = await fnRef.current(...args);
      if (!alive.current || mine !== seq.current) return undefined;
      setData(result);
      setError(null);
      return result;
    } catch (e) {
      if (!alive.current || mine !== seq.current) return undefined;
      // Surfaced, never swallowed: the caller renders it.
      setError(e?.message || String(e));
      return undefined;
    } finally {
      if (alive.current && mine === seq.current) setLoading(false);
    }
     
  }, []);

  useEffect(() => {
    if (immediate) run();
    else setLoading(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  const reset = useCallback(() => { setData(initial); setError(null); }, [initial]);
  return { data, error, loading, reload: run, reset, setData };
}

/**
 * Like useApi, but repeats every `intervalMs`.
 *
 * Ticks only while `active` AND the tab is visible; on becoming visible again
 * it refetches immediately rather than waiting out the interval, so returning
 * to the tab never shows stale numbers.
 */
export function usePoll(fn, intervalMs, { active = true, deps = [], initial = null } = {}) {
  const state = useApi(fn, deps, { initial });
  const { reload } = state;

  useEffect(() => {
    if (!active || !intervalMs) return undefined;
    let timer = null;

    const start = () => {
      if (timer) return;
      timer = setInterval(() => { if (isVisible()) reload(); }, intervalMs);
    };
    const stop = () => { if (timer) { clearInterval(timer); timer = null; } };

    const onVisibility = () => {
      if (isVisible()) { reload(); start(); } else { stop(); }
    };

    if (isVisible()) start();
    document.addEventListener('visibilitychange', onVisibility);
    return () => {
      stop();
      document.removeEventListener('visibilitychange', onVisibility);
    };
     
  }, [active, intervalMs, reload]);

  return state;
}

/**
 * One-shot action with its own busy/error state (a button handler).
 *
 * Returns [run, { busy, error, clearError }]. `run` resolves to the result, or
 * undefined when it failed - the error is kept for rendering instead of
 * escaping as an unhandled rejection.
 */
export function useAction(fn) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const alive = useRef(true);
  useEffect(() => () => { alive.current = false; }, []);

  const run = useCallback(async (...args) => {
    setBusy(true);
    setError(null);
    try {
      return await fn(...args);
    } catch (e) {
      if (alive.current) setError(e?.message || String(e));
      return undefined;
    } finally {
      if (alive.current) setBusy(false);
    }
     
  }, [fn]);

  return [run, { busy, error, clearError: () => setError(null) }];
}


/**
 * The engagement picker that five pages each rebuilt.
 *
 * Surface, Methodology, Reports, Sandbox and Findings all fetched the list,
 * stored it, auto-selected the first entry and swallowed the failure with
 * `.catch(() => {})`. With no engagements AND a dead backend they rendered the
 * same empty dropdown, so "you have not created one yet" was indistinguishable
 * from "the API is down".
 *
 * `autoSelect` picks the first engagement when the page needs one to show
 * anything (Findings does not: it defaults to a cross-engagement view).
 */
/* One active engagement, shared by every page and remembered across reloads.
 *
 * Each page used to hold its own selection and Findings defaulted to "all
 * engagements (deduped)", so a second target's findings were read as the
 * first's - a stale exposed .git from yesterday sitting next to today's scan.
 * Aggregating is still available, but it is now a deliberate choice rather
 * than the default, and picking an engagement anywhere picks it everywhere. */
const ACTIVE_KEY = 'syphax_engagement';

function storedEngagement() {
  try { return localStorage.getItem(ACTIVE_KEY) || ''; } catch { return ''; }
}

function rememberEngagement(id) {
  try {
    if (id) localStorage.setItem(ACTIVE_KEY, id);
    else localStorage.removeItem(ACTIVE_KEY);
  } catch { /* private mode: the choice just will not persist */ }
}

export function useEngagements({ autoSelect = true } = {}) {
  const [engId, setEngIdState] = useState(storedEngagement);
  const picked = useRef(false);
  const { data, error, loading, reload } = useApi(
    () => api.engagements.list(), [], { initial: null });

  // A new [] on every render made the effect below re-run on every render.
  // It is guarded by a ref so it did no damage, but the guard was carrying the
  // weight of an identity bug.
  const engagements = useMemo(() => data?.items || [], [data]);

  const setEngId = useCallback((id) => {
    rememberEngagement(id);
    setEngIdState(id);
  }, []);

  useEffect(() => {
    if (picked.current || !engagements.length) return;
    picked.current = true;
    // A remembered engagement that has since been deleted must not leave the
    // app pinned to an id the backend will 404 on.
    const exists = engagements.some((e) => e.id === engId);
    if (engId && exists) return;
    if (engId && !exists) rememberEngagement('');
    if (autoSelect) setEngId(engagements[0].id);
    else setEngIdState('');
  }, [autoSelect, engagements, engId, setEngId]);

  return { engagements, engId, setEngId, error, loading, reload };
}
