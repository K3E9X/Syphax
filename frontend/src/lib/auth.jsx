import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { api, UNAUTHENTICATED_EVENT } from './api.js';

/**
 * Who is signed in, and whether this install has been set up at all.
 *
 * One source of truth for both questions, because they are answered by one
 * endpoint and the UI has to branch on them together: an install with no
 * account shows the setup form, one with an account and no session shows the
 * login form, and they are the same screen with different copy.
 */
const AuthContext = createContext(null);

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>');
  return ctx;
}

export function AuthProvider({ children }) {
  const [state, setState] = useState({ loading: true, user: null, setupRequired: false, error: '' });
  const alive = useRef(true);
  useEffect(() => () => { alive.current = false; }, []);

  const refresh = useCallback(async () => {
    try {
      const res = await api.auth.status();
      if (!alive.current) return res;
      setState({
        loading: false,
        user: res?.user || null,
        setupRequired: !!res?.setup_required,
        error: '',
      });
      return res;
    } catch (e) {
      // A backend that is down must not look like a backend that signed us
      // out: the operator would retype their password into a page that cannot
      // check it. Say what actually happened.
      if (alive.current) {
        setState({ loading: false, user: null, setupRequired: false, error: e.message });
      }
      return null;
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  // A 401 from any call - including a background poll on a page nobody is
  // looking at - drops straight back to the login screen instead of leaving
  // every panel showing its own error.
  useEffect(() => {
    const onUnauthenticated = () => {
      setState((s) => (s.user === null && !s.loading ? s
        : { loading: false, user: null, setupRequired: s.setupRequired, error: '' }));
    };
    window.addEventListener(UNAUTHENTICATED_EVENT, onUnauthenticated);
    return () => window.removeEventListener(UNAUTHENTICATED_EVENT, onUnauthenticated);
  }, []);

  const login = useCallback(async (username, password) => {
    const res = await api.auth.login(username, password);
    if (alive.current) {
      setState({ loading: false, user: res?.user || null, setupRequired: false, error: '' });
    }
    return res;
  }, []);

  const setup = useCallback(async (username, password) => {
    const res = await api.auth.setup(username, password);
    if (alive.current) {
      setState({ loading: false, user: res?.user || null, setupRequired: false, error: '' });
    }
    return res;
  }, []);

  const logout = useCallback(async () => {
    try { await api.auth.logout(); } catch { /* the cookie is gone either way */ }
    if (alive.current) setState({ loading: false, user: null, setupRequired: false, error: '' });
  }, []);

  const value = useMemo(() => ({ ...state, refresh, login, setup, logout }),
    [state, refresh, login, setup, logout]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
