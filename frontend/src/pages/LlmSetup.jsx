import ModelRouter from '../components/ModelRouter.jsx';
import { useAuth } from '../lib/auth.jsx';
import logoMark from '../assets/logo-mark.svg';

/**
 * The screen a signed-in operator sees while no model is configured.
 *
 * This is not a banner they can dismiss. The tool plans its next move, drives
 * its tools and judges its own findings with a model; without one it is a
 * scanner wrapper that prints raw output, and a run started in that state looks
 * exactly like a run that found nothing. Blocking here is the honest version of
 * what the run gate already enforces on the API side.
 */
export default function LlmSetup({ onReady }) {
  const { user, logout } = useAuth();

  return (
    <div className="auth">
      <div className="auth__card auth__card--wide">
        <div className="auth__brand">
          <img src={logoMark} alt="" width="26" height="26" />
          <span className="auth__wm">syphax</span>
          <button type="button" className="btn btn--muted btn--sm auth__signout"
                  onClick={logout}>
            Sign out{user ? ` (${user.username})` : ''}
          </button>
        </div>

        <h1 className="auth__title">Connect a model</h1>
        <p className="auth__sub">
          Three roles need one: the <strong>planner</strong> decides what to do
          next, the <strong>executor</strong> drives the tools and reads their
          output, and the <strong>validator</strong> confirms or kills each
          finding. Any OpenAI-compatible endpoint works. You can change all of
          this later in Settings.
        </p>

        <ModelRouter compact onSaved={onReady} />
      </div>
    </div>
  );
}
