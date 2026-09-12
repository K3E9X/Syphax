import React, { useEffect, useState } from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import App from './App.jsx';
import Home from './pages/Home.jsx';
import Engagements from './pages/Engagements.jsx';
import LiveView from './pages/LiveView.jsx';
import Proxy from './pages/Proxy.jsx';
import Scans from './pages/Scans.jsx';
import Reports from './pages/Reports.jsx';
import Findings from './pages/Findings.jsx';
import Surface from './pages/Surface.jsx';
import Methodology from './pages/Methodology.jsx';
import Sandbox from './pages/Sandbox.jsx';
import Settings from './pages/Settings.jsx';
import { api } from './lib/api.js';
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
    </BrowserRouter>
  </React.StrictMode>
);
