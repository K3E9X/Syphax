import React, { useCallback, useEffect, useState } from 'react';
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
export default function Gate({ children }) {
  const { loading, user } = useAuth();
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
  if (!llm.ready) return <LlmSetup onReady={checkLlm} />;
  // We let them through, but we say why we could not check - swallowing it is
  // how "the tool found nothing" became a mystery in the first place.
  return (
    <>
      {llmError && (
        <div className="page page--flush">
          <Notice kind="warn" title="Could not check the model configuration"
                  message={llmError} onRetry={checkLlm} />
        </div>
      )}
      {children}
    </>
  );
}
