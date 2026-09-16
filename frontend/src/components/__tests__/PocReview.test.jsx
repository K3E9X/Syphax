/* The PoC review queue — where exploitation either becomes usable or becomes
 * a list nobody empties.
 *
 * Two things this screen has to make obvious at a glance, because getting
 * either wrong changes what a reviewer approves:
 *
 *   where the code came from — a script a model wrote in the last minute is
 *   read differently from one a researcher published after studying the bug;
 *   whether it may run at all — the fitness verdict is not overridable by
 *   approving, so showing it only after the click would waste the review.
 */
import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import PocReview from '../PocReview.jsx';
import { api } from '../../lib/api.js';

const AUTHORED = {
  id: 'p1', repo: 'authored by glm-5.2', path: 'idor.py', language: 'python',
  status: 'staged',
  inspection: { verdict: 'review', summary: 'nothing obviously hostile', origin: 'authored',
                attempts: 2, signals: [],
                vetting: { allowed: true, summary: 'Allowed.', blocking: [], warnings: [] } },
};

const PUBLIC_BAD = {
  id: 'p2', repo: 'someone/CVE-2024-1234-poc', path: 'exploit.py', language: 'python',
  status: 'staged',
  inspection: { verdict: 'suspicious', summary: 'reads files outside the workdir',
                origin: 'public', signals: [],
                vetting: { allowed: false,
                           summary: 'Refused: destructive. An engagement proves impact; it does not cause it.',
                           blocking: [{ category: 'destructive', line_no: 12,
                                        line: "shutil.rmtree('/var/www')",
                                        detail: 'deletes files' }],
                           warnings: [] } },
};

async function mount(engagementId = 'e1') {
  let r;
  await act(async () => { r = render(<PocReview engagementId={engagementId} />); });
  return r;
}

beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(api.poc, 'runnerHealth').mockResolvedValue({ status: 'ok', egress_locked: true });
});

describe('the queue', () => {
  it('says where each PoC came from', async () => {
    vi.spyOn(api.poc, 'list').mockResolvedValue({ items: [AUTHORED, PUBLIC_BAD] });
    await mount();
    await waitFor(() => screen.getByText('idor.py'));
    expect(within(screen.getByText('idor.py').closest('tr')).getByText('authored')).toBeTruthy();
    expect(within(screen.getByText('exploit.py').closest('tr')).getByText('public')).toBeTruthy();
  });

  it('shows in the list that a PoC will not run, before anyone opens it', async () => {
    vi.spyOn(api.poc, 'list').mockResolvedValue({ items: [AUTHORED, PUBLIC_BAD] });
    await mount();
    await waitFor(() => screen.getByText('exploit.py'));
    expect(within(screen.getByText('exploit.py').closest('tr')).getByText('refused')).toBeTruthy();
    expect(within(screen.getByText('idor.py').closest('tr')).getByText('ok')).toBeTruthy();
  });
});

describe('opening one', () => {
  it('names the offending line and says approving will not override it', async () => {
    vi.spyOn(api.poc, 'list').mockResolvedValue({ items: [PUBLIC_BAD] });
    vi.spyOn(api.poc, 'get').mockResolvedValue({ ...PUBLIC_BAD, code: "shutil.rmtree('/var/www')" });
    await mount();
    await waitFor(() => screen.getByText('exploit.py'));
    await userEvent.click(screen.getByText('exploit.py'));

    await waitFor(() => expect(screen.getByText(/this will not run/i)).toBeTruthy());
    expect(screen.getByText('deletes files')).toBeTruthy();
    expect(screen.getByText('L12')).toBeTruthy();
    expect(screen.getByText(/approving does not override this/i)).toBeTruthy();
  });

  it('tells the reviewer an authored PoC has never run', async () => {
    vi.spyOn(api.poc, 'list').mockResolvedValue({ items: [AUTHORED] });
    vi.spyOn(api.poc, 'get').mockResolvedValue({ ...AUTHORED, code: 'import requests' });
    await mount();
    await waitFor(() => screen.getByText('idor.py'));
    await userEvent.click(screen.getByText('idor.py'));

    await waitFor(() => expect(screen.getByText(/written by the model/i)).toBeTruthy());
    expect(screen.getByText(/has never run/i)).toBeTruthy();
    // It was rewritten once after a refusal, and that is worth knowing.
    expect(screen.getByText(/rewritten after 1 refusal/i)).toBeTruthy();
  });

  it('refuses to offer Run for something the backend would reject anyway', async () => {
    const approved = { ...PUBLIC_BAD, status: 'approved' };
    vi.spyOn(api.poc, 'list').mockResolvedValue({ items: [approved] });
    vi.spyOn(api.poc, 'get').mockResolvedValue({ ...approved, code: 'x' });
    await mount();
    await waitFor(() => screen.getByText('exploit.py'));
    await userEvent.click(screen.getByText('exploit.py'));
    await waitFor(() => screen.getByRole('button', { name: /run in sandbox/i }));
    expect(screen.getByRole('button', { name: /run in sandbox/i }).disabled).toBe(true);
  });

  it('offers Run for one that passed', async () => {
    const approved = { ...AUTHORED, status: 'approved' };
    vi.spyOn(api.poc, 'list').mockResolvedValue({ items: [approved] });
    vi.spyOn(api.poc, 'get').mockResolvedValue({ ...approved, code: 'import requests' });
    await mount();
    await waitFor(() => screen.getByText('idor.py'));
    await userEvent.click(screen.getByText('idor.py'));
    await waitFor(() => screen.getByRole('button', { name: /run in sandbox/i }));
    expect(screen.getByRole('button', { name: /run in sandbox/i }).disabled).toBe(false);
  });
});
