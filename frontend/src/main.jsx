import React, { useEffect, useState } from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import App from './App.jsx';
import Home from './pages/Home.jsx';
import { api } from './lib/api.js';

// Home is eager - it is the landing screen. Every other page is split into its
// own chunk so the first paint does not carry all eleven of them. On a local
// install this matters little; it keeps the entry chunk from growing with each
// page added, which is the part that compounds.
const Engagements = React.lazy(() => import('./pages/Engagements.jsx'));
const LiveView = React.lazy(() => import('./pages/LiveView.jsx'));
const Proxy = React.lazy(() => import('./pages/Proxy.jsx'));
const Scans = React.lazy(() => import('./pages/Scans.jsx'));
const Reports = React.lazy(() => import('./pages/Reports.jsx'));
const Findings = React.lazy(() => import('./pages/Findings.jsx'));
const Surface = React.lazy(() => import('./pages/Surface.jsx'));
const Methodology = React.lazy(() => import('./pages/Methodology.jsx'));
const Sandbox = React.lazy(() => import('./pages/Sandbox.jsx'));
const Settings = React.lazy(() => import('./pages/Settings.jsx'));
import './styles.css';

// "/live" resolves to the most-recent engagement's live view.
function NotFound() {
  return (
    <div className="page">
      <div className="card">
        <div className="card__head"><span className="card__title">Not found</span></div>
        <div className="card__body">
          <div className="empty">That page does not exist. Use the navigation above.</div>
        </div>
      </div>
    </div>
  );
}

function LiveRedirect() {
  const [to, setTo] = useState(null);
  useEffect(() => {
    api.engagements.list()
      .then((r) => {
        const items = r?.items || [];
        setTo(items.length ? `/engagements/${items[0].id}/live` : '/engagements');
      })
      .catch(() => setTo('/engagements'));
  }, []);
  if (!to) return <div className="page"><div className="empty">Loading...</div></div>;
  return <Navigate to={to} replace />;
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <BrowserRouter>
      <React.Suspense fallback={<div className="page"><div className="empty empty--loading">Loading…</div></div>}>
          <Routes>
        <Route path="/" element={<App />}>
          <Route index element={<Home />} />
          <Route path="engagements" element={<Engagements />} />
          <Route path="engagements/:id/live" element={<LiveView />} />
          <Route path="live" element={<LiveRedirect />} />
          <Route path="scans" element={<Scans />} />
          <Route path="findings" element={<Findings />} />
          <Route path="surface" element={<Surface />} />
          <Route path="methodology" element={<Methodology />} />
          <Route path="sandbox" element={<Sandbox />} />
          <Route path="proxy" element={<Proxy />} />
          <Route path="reports" element={<Reports />} />
          <Route path="settings" element={<Settings />} />
          {/* Without a catch-all, a URL matching no child renders null for the
              whole <Routes> - a blank page with no nav to escape from. */}
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
        </React.Suspense>
    </BrowserRouter>
  </React.StrictMode>
);
