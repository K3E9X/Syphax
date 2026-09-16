import React, { useCallback, useEffect, useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { useAuth } from '../lib/auth.jsx';
import { api } from '../lib/api.js';
import { Notice } from './ui.jsx';

const Login = React.lazy(() => import('../pages/Login.jsx'));
const LlmSetup = React.lazy(() => import('../pages/LlmSetup.jsx'));

/**
 * Nothing renders until we know who is asking, and until this install can
 * actually think.
 *
 * Both checks are here, in front of the router, rather than per page: a guard
 * each page opts into is a guard the next page forgets. Neither can be
 * forgotten, because there is no route outside them.
 *
 * They are conveniences, not the controls. The backend refuses every /api call
 * without a session, and refuses to start a run with no model configured,
 * regardless of what this component decides.
 */

/**
 * Routes that work without a model, and are therefore not held behind the
 * model gate.
 *
 * Recon is the whole list, and the reason is that it genuinely does not use
 * one: it reads DNS, the registries, a certificate and one HTTP response, and
 * every conclusion it draws is a pure function over those. Blocking it would
 * be the tool refusing to do something it is perfectly capable of, to enforce
 * a requirement that does not apply - and it is the one page a person
 * evaluating this would reach for before they go and buy an API key.
 *
 * Adding a route here is a claim that it needs no model. Check that it is true
 * before you make it: the failure mode is a page that silently does less.
 */
const WORKS_WITHOUT_A_MODEL = ['/recon'];

function needsModel(pathname) {
  const path = '/' + (pathname || '').replace(/^\/+|\/+$/g, '');
  return !WORKS_WITHOUT_A_MODEL.includes(path);
}

export default function Gate({ children }) {
  const { loading, user } = useAuth();
  const { pathname } = useLocation();
  const [llm, setLlm] = useState(null);      // null = not checked yet
  const [llmError, setLlmError] = useState('');

  const checkLlm = useCallback(async () => {
    try {
      setLlm(await api.llm.readiness());
      setLlmError('');
    } catch (e) {
      // A readiness call that fails must not lock the operator out of the tool
      // - that would turn a transient backend hiccup into an unusable UI. Let
      // them through; the run gate still refuses on the server side.
      setLlmError(e.message);
      setLlm({ ready: true });
    }
  }, []);

  useEffect(() => { if (user) checkLlm(); }, [user, checkLlm]);

  if (loading) {
    return <div className="page"><div className="empty empty--loading">Loading…</div></div>;
  }
  if (!user) return <Login />;
  if (llm === null) {
    return <div className="page"><div className="empty empty--loading">Loading…</div></div>;
  }
  if (!llm.ready && needsModel(pathname)) return <LlmSetup onReady={checkLlm} />;

  return (
    <>
      {/* We let them through, but we say why we could not check - swallowing
          it is how "the tool found nothing" became a mystery in the first
          place. */}
      {llmError && (
        <div className="page page--flush">
          <Notice kind="warn" title="Could not check the model configuration"
                  message={llmError} onRetry={checkLlm} />
        </div>
      )}
      {/* On a page that works without a model, say plainly that the rest does
          not. Otherwise the operator finishes a recon, presses Create an
          engagement, and lands on a setup screen with no idea why. */}
      {!llm.ready && (
        <div className="page page--flush">
          <Notice kind="warn" title="No model is connected">
            <span className="notice__m">
              This page works without one. Engagements, runs and validation do
              not — the tool refuses to start a run it cannot drive.{' '}
              <Link to="/settings">Connect a model</Link> to unlock the rest.
            </span>
          </Notice>
        </div>
      )}
      {children}
    </>
  );
}
