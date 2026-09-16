/* Pre-recon: the step before an engagement.
 *
 * Two things here are worth pinning beyond "it renders": that the page tells
 * the operator what leaves this machine using the BACKEND's list rather than a
 * copy of it (a page that promises less than the backend enforces is worse
 * than no promise), and that the handoff into an engagement carries the target
 * across rather than making the operator retype it.
 */
import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import PreRecon from '../PreRecon.jsx';
import { api } from '../../lib/api.js';

const mockNavigate = vi.fn();
vi.mock('react-router-dom', async () => ({
  ...(await vi.importActual('react-router-dom')),
  useNavigate: () => mockNavigate,
}));

const SCOPE = {
  touches_target: ['GET /', 'GET /robots.txt', 'one TLS handshake'],
  asks_third_parties: ['DNS - the resolver', 'RDAP - rdap.org'],
  never: ['port scanning', 'directory or subdomain brute force'],
  limits: ['at most 6 requests to the target'],
};

const REPORT = {
  target: { host: 'example.com', base_url: 'https://example.com/',
            registrable_domain: 'example.com', is_ip: false, scheme: 'https', notes: [] },
  took_ms: 812,
  dns: { resolved: true, addresses: ['1.2.3.4'], records: { A: ['1.2.3.4'], MX: ['mail.example.com'] },
         reverse: { '1.2.3.4': 'edge.example.com' }, spf: ['v=spf1 -all'], dmarc: [] },
  network: { primary_address: '1.2.3.4',
             asn: { asn: '13335', as_name: 'CLOUDFLARENET, US', prefix: '1.2.3.0/24',
                    shared_infrastructure: 'cloudflare' },
             registration: { range: '1.2.3.0 - 1.2.3.255', organisations: ['Cloudflare'] } },
  domain: { registrar: 'Example Registrar', expires: '2027-01-01', nameservers: ['ns1.example.com'],
            dnssec: true, status: ['clientTransferProhibited'] },
  tls: { available: true, subject: 'example.com', issuer_org: "Let's Encrypt",
         not_after: '2026-11-01', days_remaining: 46, san: ['example.com', 'www.example.com'],
         san_count: 2, issues: [], signature_algorithm: 'sha256' },
  http: { error: '', requests_made: 4, redirects: [{ status: 301, to: 'https://example.com/' }],
          root: { status: 200, reason: 'OK', title: 'Example', url: 'https://example.com/',
                  http_version: 'HTTP/2', elapsed_ms: 120, body_bytes: 1256 } },
  technologies: {
    frontend: [{ name: 'React', layer: 'frontend', category: 'framework',
                 confidence: 'likely', evidence: 'data-reactroot', version: null, note: '' }],
    backend: [{ name: 'PHP', layer: 'backend', category: 'language',
                confidence: 'certain', evidence: 'x-powered-by: PHP/8.2', version: '8.2', note: '' }],
    infrastructure: [{ name: 'Cloudflare', layer: 'infrastructure', category: 'cdn',
                       confidence: 'certain', evidence: 'cf-ray: x', version: null, note: '' }],
  },
  headers: { present: [{ name: 'strict-transport-security', value: 'max-age=31536000' }],
             missing: [{ name: 'content-security-policy', consequence: 'any injected script runs' }],
             disclosing: [{ name: 'server', value: 'nginx' }] },
  cookies: [{ name: 'sid', http_only: false, secure: true, same_site: 'lax' }],
  public_files: { '/robots.txt': { status: 200, present: true, bytes: 40, preview: 'Disallow: /admin' } },
  certificate_transparency: { available: true, total: 2, names: ['example.com', 'api.example.com'],
                              wildcards: [], issuers: [] },
  candidate_hosts: ['example.com', 'www.example.com', 'api.example.com'],
  counts: { addresses: 1, technologies: 3, names_in_ct: 2, certificate_names: 2, missing_headers: 1 },
  highlights: [
    { level: 'warn', text: 'The address belongs to CLOUDFLARENET, US, not to the client.',
      why: 'Anything at the network layer here is that provider to authorize.' },
    { level: 'info', text: '1 redirect(s), ending at https://example.com/.', why: '' },
  ],
  errors: [],
  scope_of_this_check: SCOPE,
};

async function mount() {
  let r;
  await act(async () => { r = render(<MemoryRouter><PreRecon /></MemoryRouter>); });
  return r;
}

async function search(term = 'example.com') {
  await userEvent.type(screen.getByLabelText('Target'), term);
  await userEvent.click(screen.getByRole('button', { name: /run pre-recon/i }));
}

beforeEach(() => {
  vi.restoreAllMocks();
  mockNavigate.mockClear();
  vi.spyOn(api.prerecon, 'scope').mockResolvedValue(SCOPE);
});

describe('what it tells the operator it will do', () => {
  it("lists the backend's scope, not a copy of it", async () => {
    await mount();
    await userEvent.click(screen.getByRole('button', { name: /passive only/i }));
    expect(screen.getByText('GET /robots.txt')).toBeTruthy();
    expect(screen.getByText('port scanning')).toBeTruthy();
    expect(api.prerecon.scope).toHaveBeenCalled();
  });

  it('says plainly that it is not the engagement\'s recon phase', async () => {
    /* One word between two different things. Without this line an operator
       comes here looking for subfinder output and concludes the tool is
       broken. */
    // The sentence is split by an <em>, so match against the rendered text
    // rather than a single node.
    const { container } = await mount();
    const text = container.textContent;
    expect(text).toMatch(/not the recon phase/i);
    expect(text).toMatch(/subfinder, dnsx, httpx, gau, naabu and nmap/i);
  });
});

describe('running it', () => {
  it('shows the rejection sentence the backend wrote', async () => {
    vi.spyOn(api.prerecon, 'run').mockRejectedValue(
      new Error("'singleword' has no dot in it. Did you mean singleword.com?"));
    await mount();
    await search('singleword');
    await waitFor(() => expect(screen.getByRole('alert').textContent).toMatch(/no dot in it/));
  });

  it('passes the CT toggle through, because it is the slow source', async () => {
    const run = vi.spyOn(api.prerecon, 'run').mockResolvedValue(REPORT);
    await mount();
    await userEvent.click(screen.getByLabelText(/ct logs/i));
    await search();
    expect(run).toHaveBeenCalledWith('example.com', false);
  });

  it('puts the synthesis above the raw panels', async () => {
    vi.spyOn(api.prerecon, 'run').mockResolvedValue(REPORT);
    await mount();
    await search();
    await waitFor(() => screen.getByText(/read this first/i));
    expect(screen.getByText(/belongs to CLOUDFLARENET/)).toBeTruthy();
    expect(screen.getByText(/that provider/i)).toBeTruthy();
  });

  it('keeps the three technology layers apart', async () => {
    /* `Server: cloudflare` says nothing about the application; filing it as a
       backend would make the whole panel misleading. */
    vi.spyOn(api.prerecon, 'run').mockResolvedValue(REPORT);
    await mount();
    await search();
    await waitFor(() => screen.getByText('Frontend'));

    const column = (name) => screen.getByText(name).closest('.pre-tech__col');
    expect(within(column('Frontend')).getByText('React')).toBeTruthy();
    expect(within(column('Backend')).getByText(/PHP/)).toBeTruthy();
    expect(within(column('Infrastructure')).getByText('Cloudflare')).toBeTruthy();
  });

  it('gives each missing header its consequence rather than a grade', async () => {
    vi.spyOn(api.prerecon, 'run').mockResolvedValue(REPORT);
    await mount();
    await search();
    await waitFor(() => screen.getByText('content-security-policy'));
    expect(screen.getByText(/any injected script runs/)).toBeTruthy();
  });

  it('surfaces a source that did not answer instead of pretending it had nothing', async () => {
    vi.spyOn(api.prerecon, 'run').mockResolvedValue({
      ...REPORT,
      errors: [{ section: 'certificate_transparency', error: 'crt.sh unreachable' }],
    });
    await mount();
    await search();
    await waitFor(() => expect(screen.getByText(/crt\.sh unreachable/)).toBeTruthy());
  });
});

describe('the handoff into an engagement', () => {
  it('carries the target and the names it found', async () => {
    vi.spyOn(api.prerecon, 'run').mockResolvedValue(REPORT);
    await mount();
    await search();
    await waitFor(() => screen.getByRole('button', { name: /create an engagement/i }));
    await userEvent.click(screen.getByRole('button', { name: /create an engagement/i }));

    expect(mockNavigate).toHaveBeenCalledWith('/engagements', {
      state: {
        target_url: 'https://example.com/',
        scope_hosts: 'example.com, www.example.com, api.example.com',
        from_prerecon: 'example.com',
      },
    });
  });
});
