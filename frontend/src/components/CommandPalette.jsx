import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../lib/api.js';
import { rank } from '../lib/fuzzy.js';

/**
 * ⌘K / Ctrl-K command palette.
 *
 * A pentest console is used at the keyboard, and eleven flat nav links do not
 * scale: by the third engagement the operator is hunting, not navigating. This
 * reaches anything in one keystroke - a page, an engagement, a finding by its
 * title, a staged PoC - and ranks it (see lib/fuzzy.js) so the obvious hit is
 * first.
 *
 * It NAVIGATES; it does not act. "Start run" and "approve PoC" are gated
 * controls that live on their pages, and the palette takes you to them rather
 * than firing them - a fuzzy-matched Enter is the wrong way to launch an
 * exploit. So there is no dangerous action reachable here that is not reachable,
 * gated, where it already lives.
 *
 * Live data (engagements, findings) is loaded only when the palette opens, and
 * only once per opening, so the shortcut costs nothing until it is used.
 */

// Static destinations, always available. Ordered the way the nav is.
const PAGES = [
  { id: 'p-home', label: 'Home', group: 'Pages', to: '/', keywords: 'dashboard status' },
  { id: 'p-prerecon', label: 'Pre-recon', group: 'Pages', to: '/pre-recon', keywords: 'dns tls whois asn certificate before engagement' },
  { id: 'p-eng', label: 'Engagements', group: 'Pages', to: '/engagements', keywords: 'targets scope authorize new' },
  { id: 'p-live', label: 'Live view', group: 'Pages', to: '/live', keywords: 'run console phases stream' },
  { id: 'p-scans', label: 'Scans', group: 'Pages', to: '/scans', keywords: 'tools nuclei sqlmap jobs' },
  { id: 'p-find', label: 'Findings', group: 'Pages', to: '/findings', keywords: 'vulnerabilities verdicts' },
  { id: 'p-surf', label: 'Surface', group: 'Pages', to: '/surface', keywords: 'assets attack surface hosts' },
  { id: 'p-meth', label: 'Methodology', group: 'Pages', to: '/methodology', keywords: 'wstg attack catalog coverage' },
  { id: 'p-sand', label: 'Sandbox', group: 'Pages', to: '/sandbox', keywords: 'poc exploit staged runner' },
  { id: 'p-proxy', label: 'Proxy', group: 'Pages', to: '/proxy', keywords: 'mitm intercept flows capture ca' },
  { id: 'p-rep', label: 'Reports', group: 'Pages', to: '/reports', keywords: 'export markdown pdf sarif' },
  { id: 'p-set', label: 'Settings', group: 'Pages', to: '/settings', keywords: 'model router api key account operators budget' },
];

// Things you DO, phrased as verbs. Each just navigates to where the real,
// gated control lives - the palette never performs the action itself.
const ACTIONS = [
  { id: 'a-new-eng', label: 'New engagement', group: 'Actions', to: '/engagements', keywords: 'create add target start' },
  { id: 'a-prerecon', label: 'Run pre-recon on a target', group: 'Actions', to: '/pre-recon', keywords: 'lookup dns scan before' },
  { id: 'a-connect-model', label: 'Connect a model', group: 'Actions', to: '/settings', keywords: 'llm provider api key jev' },
  { id: 'a-review-poc', label: 'Review staged PoCs', group: 'Actions', to: '/sandbox', keywords: 'approve exploit' },
  { id: 'a-account', label: 'Account & password', group: 'Actions', to: '/settings', keywords: 'sign out sessions logout' },
];

function severityDot(sev) {
  const s = (sev || 'info').toLowerCase();
  return <span className={'cmd__sev cmd__sev--' + s} aria-hidden="true" />;
}

export default function CommandPalette() {
  const nav = useNavigate();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [active, setActive] = useState(0);
  const [live, setLive] = useState({ engagements: [], findings: [] });
  const inputRef = useRef(null);
  const listRef = useRef(null);
  const restoreFocusTo = useRef(null);

  // Open on ⌘K / Ctrl-K from anywhere; close on Escape. Registered once.
  useEffect(() => {
    const onKey = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setOpen((o) => !o);
      }
    };
    // A click on the top-nav hint dispatches this, so the chip and the shortcut
    // share one open path.
    const onOpen = () => setOpen(true);
    window.addEventListener('keydown', onKey);
    window.addEventListener('syphax:command-palette', onOpen);
    return () => {
      window.removeEventListener('keydown', onKey);
      window.removeEventListener('syphax:command-palette', onOpen);
    };
  }, []);

  // On open: remember where focus was, focus the input, and pull live data
  // once. On close: reset the query and give focus back.
  useEffect(() => {
    if (open) {
      restoreFocusTo.current = document.activeElement;
      setQuery('');
      setActive(0);
      // Focus after paint so the input exists.
      requestAnimationFrame(() => inputRef.current?.focus());
      let alive = true;
      Promise.allSettled([api.engagements.list(), api.findings.list()]).then(
        ([eng, find]) => {
          if (!alive) return;
          setLive({
            engagements: eng.status === 'fulfilled' ? (eng.value?.items || []) : [],
            findings: find.status === 'fulfilled' ? (find.value?.items || []) : [],
          });
        });
      return () => { alive = false; };
    }
    const el = restoreFocusTo.current;
    if (el && typeof el.focus === 'function') el.focus();
    return undefined;
  }, [open]);

  // The full candidate set, rebuilt when live data arrives. Findings and
  // engagements become navigable rows that carry their host/severity as extra
  // match keys, so "sqli on api" finds the right one.
  const items = useMemo(() => {
    const eng = live.engagements.map((e) => ({
      id: 'eng-' + e.id,
      label: e.title || e.target_url || e.target_host || e.id,
      group: 'Engagements',
      to: `/engagements/${e.id}/live`,
      keywords: `${e.target_host || ''} ${e.status || ''}`,
      meta: e.status,
    }));
    const find = live.findings.map((f) => ({
      id: 'find-' + f.id,
      label: f.title || f.cls || f.id,
      group: 'Findings',
      to: '/findings',
      keywords: `${f.target || ''} ${f.cls || ''} ${f.severity || ''}`,
      severity: f.severity,
    }));
    return [...PAGES, ...ACTIONS, ...eng, ...find];
  }, [live]);

  const results = useMemo(
    () => rank(query, items, {
      keys: ['label', 'keywords'],
      limit: 40,
    }),
    [query, items]);

  // Keep the active index in range as results change, and scroll it into view.
  useEffect(() => { setActive(0); }, [query]);
  useEffect(() => {
    const el = listRef.current?.querySelector('[data-active="true"]');
    el?.scrollIntoView?.({ block: 'nearest' });
  }, [active, results]);

  const choose = useCallback((item) => {
    if (!item) return;
    setOpen(false);
    nav(item.to);
  }, [nav]);

  const onKeyDown = (e) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setActive((a) => Math.min(a + 1, results.length - 1)); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActive((a) => Math.max(a - 1, 0)); }
    else if (e.key === 'Enter') { e.preventDefault(); choose(results[active]); }
    else if (e.key === 'Escape') { e.preventDefault(); setOpen(false); }
  };

  if (!open) return null;

  // Group the flat ranked list back into sections, preserving rank order.
  const groups = [];
  const seen = new Map();
  results.forEach((item, i) => {
    let g = seen.get(item.group);
    if (!g) { g = { name: item.group, rows: [] }; seen.set(item.group, g); groups.push(g); }
    g.rows.push({ item, index: i });
  });

  return (
    <div className="cmd" role="presentation" onMouseDown={() => setOpen(false)}>
      <div className="cmd__panel" role="dialog" aria-modal="true" aria-label="Command palette"
           onMouseDown={(e) => e.stopPropagation()}>
        <input
          ref={inputRef}
          className="cmd__input"
          placeholder="Jump to a page, engagement, finding…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={onKeyDown}
          role="combobox"
          aria-expanded="true"
          aria-controls="cmd-list"
          aria-activedescendant={results[active] ? 'cmd-row-' + active : undefined}
          autoComplete="off"
          spellCheck="false"
        />
        <div className="cmd__list" id="cmd-list" ref={listRef} role="listbox">
          {results.length === 0 && (
            <div className="cmd__empty">No match for “{query}”.</div>
          )}
          {groups.map((g) => (
            <div key={g.name} className="cmd__group">
              <div className="cmd__group-h">{g.name}</div>
              {g.rows.map(({ item, index }) => (
                <button
                  key={item.id}
                  id={'cmd-row-' + index}
                  className={'cmd__row' + (index === active ? ' cmd__row--active' : '')}
                  data-active={index === active}
                  role="option"
                  aria-selected={index === active}
                  onMouseEnter={() => setActive(index)}
                  onClick={() => choose(item)}
                >
                  {item.severity ? severityDot(item.severity) : <span className="cmd__ic" aria-hidden="true" />}
                  <span className="cmd__label">{item.label}</span>
                  {item.meta && <span className="cmd__meta">{item.meta}</span>}
                </button>
              ))}
            </div>
          ))}
        </div>
        <div className="cmd__foot">
          <span><kbd>↑</kbd><kbd>↓</kbd> move</span>
          <span><kbd>↵</kbd> open</span>
          <span><kbd>esc</kbd> close</span>
        </div>
      </div>
    </div>
  );
}
