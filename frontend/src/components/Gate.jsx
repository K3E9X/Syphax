import React from 'react';
import { useAuth } from '../lib/auth.jsx';

const Login = React.lazy(() => import('../pages/Login.jsx'));

/**
 * Nothing renders until we know who is asking.
 *
 * The check is here, in front of the router, rather than per page: a guard that
 * each page opts into is a guard that the next page forgets. This one cannot be
 * forgotten, because there is no route outside it.
 *
 * It is a convenience, not the control. The backend refuses every /api call
 * without a session regardless of what this component decides, so a browser
 * that skips it sees an empty shell and a wall of 401s.
 */
export default function Gate({ children }) {
  const { loading, user } = useAuth();

  if (loading) {
    return <div className="page"><div className="empty empty--loading">Loading…</div></div>;
  }
  if (!user) return <Login />;
  return children;
}
