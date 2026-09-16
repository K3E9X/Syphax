import { useEffect, useState } from 'react';
import { NavLink } from 'react-router-dom';
import { api } from '../lib/api.js';
import { useAuth } from '../lib/auth.jsx';
import logoMark from '../assets/logo-mark.svg';

// Canonical nav order (HANDOFF section 1). Text-only, no icons.
const LINKS = [
  { label: 'Home', to: '/' },
  // Before Engagements on purpose: it is the step before one, not a tool you
  // reach for afterwards. "Pre-recon" and not "Recon": the engagement's recon
  // PHASE is a different thing that runs real tools, and one word between them
  // is how an operator ends up looking for subfinder output on this page.
  { label: 'Pre-recon', to: '/pre-recon' },
  { label: 'Engagements', to: '/engagements' },
  { label: 'Live', to: '/live' },         // resolves to the most-recent engagement
  { label: 'Scans', to: '/scans' },
  { label: 'Findings', to: '/findings' },
  { label: 'Surface', to: '/surface' },
  { label: 'Methodology', to: '/methodology' },
  { label: 'Sandbox', to: '/sandbox' },
  { label: 'Proxy', to: '/proxy' },
  { label: 'Reports', to: '/reports' },
  { label: 'Settings', to: '/settings' },
];

export default function TopNav() {
  const { user, logout } = useAuth();
  // Without this, a backend that is down looks identical to a tool with no
  // data: every page renders its empty state and says nothing is wrong.
  const [online, setOnline] = useState(null);
  useEffect(() => {
    let alive = true;
    const ping = () => api.health()
      .then(() => alive && setOnline(true))
      .catch(() => alive && setOnline(false));
    ping();
    const t = setInterval(ping, 15000);
    return () => { alive = false; clearInterval(t); };
  }, []);

  // "Live" points at the most-recent engagement's live view.
  const [liveTo, setLiveTo] = useState('/engagements');
  useEffect(() => {
    let alive = true;
    api.engagements.list()
      .then((res) => {
        const items = res?.items || [];
        if (alive && items.length) setLiveTo(`/engagements/${items[0].id}/live`);
      })
      .catch(() => {});
    return () => { alive = false; };
  }, []);

  return (
    <nav className="topnav">
      <NavLink to="/" className="topnav__brand" aria-label="Syphax home">
        <img className="topnav__mark" src={logoMark} alt="" width="22" height="22" />
        <span className="topnav__wm">syphax</span>
      </NavLink>
      <span className={'topnav__health topnav__health--' + (online === null ? 'unknown' : online ? 'up' : 'down')}
            title={online === false ? 'Backend unreachable — pages will look empty' : 'Backend reachable'}>
        {online === false ? 'backend offline' : ''}
      </span>
      <div className="topnav__links">
        {LINKS.map((l) => {
          const to = l.label === 'Live' ? liveTo : l.to;
          return (
            <NavLink
              key={l.label}
              to={to}
              end={l.to === '/'}
              className={({ isActive }) =>
                'topnav__link' + (isActive ? ' topnav__link--active' : '')}
            >
              {l.label}
            </NavLink>
          );
        })}
      </div>
      {user && (
        <div className="topnav__who">
          <span className="topnav__user" title={`signed in as ${user.username} (${user.role})`}>
            {user.username}
          </span>
          <button type="button" className="btn btn--muted btn--sm" onClick={logout}>
            Sign out
          </button>
        </div>
      )}
    </nav>
  );
}
