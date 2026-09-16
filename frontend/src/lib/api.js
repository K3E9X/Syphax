// Thin fetch wrappers for the FastAPI backend. Paths are relative so they
// work behind the nginx proxy in production and the Vite dev proxy locally.

// Machine credential (backend SYPHAX_API_KEY), for scripts and CI. A browser
// normally authenticates with the session cookie set by /api/auth/login and
// leaves this empty; it is stored per browser for the case where an operator
// drives the API from the UI of a headless install.
const KEY_STORAGE = 'syphax_api_key';

export function getApiKey() {
  try { return localStorage.getItem(KEY_STORAGE) || ''; } catch { return ''; }
}

export function setApiKey(key) {
  try {
    if (key) localStorage.setItem(KEY_STORAGE, key);
    else localStorage.removeItem(KEY_STORAGE);
  } catch { /* private mode: the key just won't persist */ }
}

// Raised when the backend says this browser is not signed in, so the shell can
// swap in the login screen from wherever the 401 happened - a background poll
// on a page the operator is not even looking at included.
export const UNAUTHENTICATED_EVENT = 'syphax:unauthenticated';

async function request(path, opts = {}) {
  const key = getApiKey();
  const res = await fetch(path, {
    // The session is an httpOnly cookie; without this an opts object with its
    // own `credentials` would silently drop it.
    credentials: 'same-origin',
    ...opts,
    headers: key
      ? { ...(opts.headers || {}), 'X-API-Key': key }
      : (opts.headers || {}),
  });
  const text = await res.text();
  const body = text ? safeJson(text) : null;
  if (!res.ok) {
    if (res.status === 401 && typeof window !== 'undefined') {
      window.dispatchEvent(new CustomEvent(UNAUTHENTICATED_EVENT, {
        detail: { reason: body?.reason || '', setupRequired: !!body?.setup_required },
      }));
    }
    const err = new Error(errorMessage(body, text, res.status));
    err.status = res.status;
    err.reason = body?.reason || '';
    throw err;
  }
  return body;
}

/**
 * Turn an error body into a sentence a human can act on.
 *
 * FastAPI returns `detail` as a STRING for an HTTPException but as an ARRAY OF
 * OBJECTS for a 422 validation error. Passing that array to `new Error()`
 * stringified it, so every validation failure reached the operator as the
 * literal text "[object Object]" - which the pages now render prominently,
 * making a silent bug a loud one.
 */
export function errorMessage(body, text, status) {
  const detail = body?.detail ?? body?.error;
  if (typeof detail === 'string' && detail) return detail;

  if (Array.isArray(detail) && detail.length) {
    const parts = detail.map((d) => {
      if (typeof d === 'string') return d;
      // loc is ["body", "field", 0]; the first element is the request part.
      const where = Array.isArray(d?.loc) ? d.loc.slice(1).join('.') : '';
      const what = d?.msg || d?.type || 'invalid value';
      return where ? `${where}: ${what}` : what;
    });
    return parts.join('; ');
  }

  if (detail && typeof detail === 'object') {
    try { return JSON.stringify(detail); } catch { /* fall through */ }
  }
  return (typeof text === 'string' && text.trim()) ? text : `HTTP ${status}`;
}

function safeJson(text) {
  try { return JSON.parse(text); } catch { return text; }
}

export const api = {
  config: () => request('/api/config'),
  health: () => request('/api/health'),
  llmPing: (role) => request(`/api/llm/ping${role ? `?role=${role}` : ''}`, { method: 'POST' }),
  dashboard: () => request('/api/dashboard'),
  tools: () => request('/api/tools'),

  engagements: {
    // What an engagement can additionally authorize beyond read-only proof.
    // Served, not hardcoded: a checkbox offering something the backend does not
    // know would grant nothing and say nothing.
    capabilities: () => request('/api/engagements/capabilities'),
    // `get` and `verify` used to live here with no caller: state() returns a
    // superset of get(), and the DNS-TXT / .well-known ownership proof is a
    // deliberate API-only feature with no UI. The endpoints remain; the dead
    // client methods do not.
    list: () => request('/api/engagements'),
    create: (payload) => request('/api/engagements', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    }),
    close: (id) => request(`/api/engagements/${id}/close`, { method: 'POST' }),
    remove: (id) => request(`/api/engagements/${id}`, { method: 'DELETE' }),
    run: (id) => request(`/api/engagements/${id}/run`, { method: 'POST' }),
    stop: (id) => request(`/api/engagements/${id}/stop`, { method: 'POST' }),
    state: (id) => request(`/api/engagements/${id}/state`),
    validate: (id) => request(`/api/engagements/${id}/validate`, { method: 'POST' }),
    analyzeTraffic: (id) => request(`/api/engagements/${id}/analyze-traffic`, { method: 'POST' }),
    events: (id, afterId = 0) => request(`/api/engagements/${id}/events?after_id=${afterId}`),
    approvals: (id) => request(`/api/engagements/${id}/approvals`),
    surface: (id) => request(`/api/engagements/${id}/surface`),
    coverage: (id) => request(`/api/engagements/${id}/coverage`),
    findings: (id) => request(`/api/engagements/${id}/findings`),
    chains: (id) => request(`/api/engagements/${id}/chains`),
    reportJson: (id) => request(`/api/engagements/${id}/report.json`),
    verifyProof: (fid) => request(`/api/findings/${fid}/verify-proof`, { method: 'POST' }),
    memory: (id) => request(`/api/engagements/${id}/memory`),
    usage: (id) => request(`/api/engagements/${id}/usage`),
    diff: (id, against) => request(`/api/engagements/${id}/diff?against=${against}`),
    retestFinding: (id, fid) => request(`/api/engagements/${id}/findings/${fid}/retest`, { method: 'POST' }),
    decideApproval: (id, approvalId, decision) =>
      request(`/api/engagements/${id}/approvals/${approvalId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ decision }),
      }),
  },

  // Pre-recon: the look taken BEFORE an engagement exists. Not the
  // engagement's recon phase, which runs tools through the queue.
  prerecon: {
    // What a pre-recon run does and does not do. Served rather than hardcoded
    // so the page cannot promise something the backend does not enforce.
    scope: () => request('/api/prerecon/scope'),
    run: (target, includeCt = true) => request('/api/prerecon', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, include_ct: includeCt }),
    }),
  },

  methodology: {
    catalog: () => request('/api/methodology/catalog'),
  },

  proxy: {
    status: () => request('/api/proxy/status'),
    hosts: () => request('/api/proxy/hosts'),
    flows: (params = {}) => {
      const qs = new URLSearchParams(
        Object.entries(params).filter(([, v]) => v !== undefined && v !== '' && v !== null)
      ).toString();
      return request(`/api/proxy/flows${qs ? `?${qs}` : ''}`);
    },
    flow: (id) => request(`/api/proxy/flows/${id}`),
    clear: () => request('/api/proxy/flows', { method: 'DELETE' }),
    caUrl: () => '/api/proxy/ca.pem',
  },

  scans: {
    tools: () => request('/api/scans/tools'),
    // How the tools may present themselves on the wire. Served, not hardcoded:
    // a UI offering a browser the backend does not know would silently fall
    // back to rotating and nobody would be able to tell.
    identities: () => request('/api/scans/identities'),
    list: (params = {}) => {
      const qs = new URLSearchParams(
        Object.entries(params).filter(([, v]) => v !== undefined && v !== '' && v !== null)
      ).toString();
      return request(`/api/scans${qs ? `?${qs}` : ''}`);
    },
    submit: (payload) => request('/api/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    }),
    get: (id) => request(`/api/scans/${id}`),
    cancel: (id) => request(`/api/scans/${id}/cancel`, { method: 'POST' }),
    delete: (id) => request(`/api/scans/${id}`, { method: 'DELETE' }),
  },

  llm: {
    providers: () => request('/api/llm/providers'),
    readiness: () => request('/api/llm/readiness'),
    suggestForFlow: (flowId) => request(`/api/llm/flows/${flowId}/suggest`, { method: 'POST' }),
    explainJob: (jobId) => request(`/api/llm/jobs/${jobId}/explain`, { method: 'POST' }),
    report: (payload) => request('/api/llm/report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    }),
  },

  findings: {
    list: (params = {}) => {
      const qs = new URLSearchParams(
        Object.entries(params).filter(([, v]) => v !== undefined && v !== '' && v !== null)
      ).toString();
      return request(`/api/findings${qs ? `?${qs}` : ''}`);
    },
    setStatus: (id, status) => request(`/api/findings/${id}/status`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status }),
    }),
    retest: (id) => request(`/api/findings/${id}/retest`, { method: 'POST' }),
    exportUrl: (id) => `/api/findings/${id}/export?format=h1`,
  },

  sandbox: {
    run: (payload) => request('/api/sandbox/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    }),
  },

  auth: {
    status: () => request('/api/auth/status'),
    setup: (username, password) => request('/api/auth/setup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    }),
    login: (username, password) => request('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    }),
    logout: () => request('/api/auth/logout', { method: 'POST' }),
    changePassword: (currentPassword, newPassword) => request('/api/auth/password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    }),
    revokeSessions: () => request('/api/auth/sessions/revoke', { method: 'POST' }),
    sessions: () => request('/api/auth/sessions'),
    apiKeyState: () => request('/api/auth/api-key'),
    users: () => request('/api/auth/users'),
    addUser: (payload) => request('/api/auth/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    }),
    removeUser: (id) => request(`/api/auth/users/${id}`, { method: 'DELETE' }),
  },

  settings: {
    get: () => request('/api/settings'),
    save: (payload) => request('/api/settings', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    }),
  },

  poc: {
    runnerHealth: () => request('/api/poc/runner/health'),
    list: (engagementId) => request(`/api/poc/engagements/${engagementId}`),
    get: (pocId) => request(`/api/poc/${pocId}`),
    stage: (payload) => request('/api/poc/stage', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    }),
    approve: (pocId) => request(`/api/poc/${pocId}/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ decided_by: 'operator' }),
    }),
    reject: (pocId) => request(`/api/poc/${pocId}/reject`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ decided_by: 'operator' }),
    }),
    run: (pocId, timeout = 60) => request(`/api/poc/${pocId}/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ timeout }),
    }),
  },

  network: {
    status: () => request('/api/network/status'),
    check: () => request('/api/network/check', { method: 'POST' }),
    guard: () => request('/api/network/guard'),
    identity: () => request('/api/network/identity'),
    setBaseline: () => request('/api/network/baseline', { method: 'POST' }),
    setProxy: (proxyUrl) => request('/api/network/proxy', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ proxy_url: proxyUrl }),
    }),
    connectVpn: (configPath, mode) => request('/api/network/vpn/connect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ config_path: configPath || '', mode: mode || '' }),
    }),
    disconnect: () => request('/api/network/vpn/disconnect', { method: 'POST' }),
  },

  audit: {
    list: (params = {}) => {
      const qs = new URLSearchParams(
        Object.entries(params).filter(([, v]) => v !== undefined && v !== '' && v !== null)
      ).toString();
      return request(`/api/audit${qs ? `?${qs}` : ''}`);
    },
  },
};
