/* The engagement form's scan-identity field.
 *
 * The property worth pinning: the list of browsers comes from the BACKEND. A
 * frontend copy would drift, and an option the backend does not recognise
 * falls back to rotating with nothing shown to the operator - so they would
 * believe they had pinned Safari while the tools rotated.
 */
import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import Engagements from '../Engagements.jsx';
import { api } from '../../lib/api.js';

const IDENTITIES = {
  items: [
    { id: 'rotate', label: 'Rotate (default)', note: 'A different real browser per job.' },
    { id: 'chrome-126-windows', label: 'Google Chrome 126 on Windows',
      note: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0.0.0' },
    { id: 'custom', label: 'Custom User-Agent', note: 'Your own string.' },
    { id: 'tool', label: "Each tool's own", note: 'Send nothing.' },
  ],
  environment_default: 'rotate',
  caveat: 'This does not make a scan invisible: the source IP is in their logs.',
};

async function mount() {
  let r;
  await act(async () => {
    r = render(<MemoryRouter><Engagements /></MemoryRouter>);
  });
  return r;
}

beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(api.engagements, 'list').mockResolvedValue({ items: [] });
  vi.spyOn(api.scans, 'identities').mockResolvedValue(IDENTITIES);
  vi.spyOn(api.engagements, 'capabilities').mockResolvedValue({ items: [] });
});

describe('choosing how the tools identify themselves', () => {
  it('offers what the backend serves, not a hardcoded list', async () => {
    await mount();
    await waitFor(() => screen.getByLabelText(/how the tools identify themselves/i));
    const values = [...screen.getByLabelText(/how the tools identify themselves/i).options]
      .map((o) => o.value);
    expect(values).toEqual(['', 'rotate', 'chrome-126-windows', 'custom', 'tool']);
  });

  it('defaults to following the server, which is what existing engagements do', async () => {
    await mount();
    await waitFor(() => screen.getByLabelText(/how the tools identify themselves/i));
    expect(screen.getByLabelText(/how the tools identify themselves/i).value).toBe('');
    expect(screen.getByText(/server default \(rotate\)/i)).toBeTruthy();
  });

  it('shows the User-Agent string behind the browser you picked', async () => {
    await mount();
    await waitFor(() => screen.getByLabelText(/how the tools identify themselves/i));
    await userEvent.selectOptions(
      screen.getByLabelText(/how the tools identify themselves/i), 'chrome-126-windows');
    expect(screen.getByText(/Chrome\/126\.0\.0\.0/)).toBeTruthy();
  });

  it('asks for the string only when custom is picked', async () => {
    await mount();
    await waitFor(() => screen.getByLabelText(/how the tools identify themselves/i));
    expect(screen.queryByLabelText(/user-agent string/i)).toBeNull();
    await userEvent.selectOptions(
      screen.getByLabelText(/how the tools identify themselves/i), 'custom');
    expect(screen.getByLabelText(/user-agent string/i)).toBeTruthy();
  });

  it('says out loud that this is not evasion', async () => {
    await mount();
    await waitFor(() => screen.getByLabelText(/how the tools identify themselves/i));
    await userEvent.selectOptions(
      screen.getByLabelText(/how the tools identify themselves/i), 'tool');
    expect(screen.getByText(/does not make a scan invisible/i)).toBeTruthy();
  });

  it('sends the choice, and the string only when it is custom', async () => {
    const create = vi.spyOn(api.engagements, 'create')
      .mockResolvedValue({ engagement: { id: 'e1' } });
    await mount();
    await waitFor(() => screen.getByLabelText(/how the tools identify themselves/i));

    await userEvent.type(screen.getByPlaceholderText('https://app.example.com'),
                         'https://app.example.com');
    await userEvent.selectOptions(
      screen.getByLabelText(/how the tools identify themselves/i), 'chrome-126-windows');
    await userEvent.click(screen.getByRole('checkbox', { name: /authorized/i }));
    await userEvent.click(screen.getByRole('button', { name: /create engagement/i }));

    await waitFor(() => expect(create).toHaveBeenCalled());
    const payload = create.mock.calls[0][0];
    expect(payload.user_agent_mode).toBe('chrome-126-windows');
    expect(payload.user_agent).toBeUndefined();
  });

  it('a failed identity lookup is reported, not swallowed into an empty select', async () => {
    vi.spyOn(api.scans, 'identities').mockRejectedValue(new Error('backend restarting'));
    await mount();
    await waitFor(() => expect(screen.getByText(/backend restarting/i)).toBeTruthy());
  });
});

const CAPS = {
  items: [
    { id: 'destructive', label: 'Destructive actions',
      unlocks: 'delete files, drop or truncate tables',
      cost: 'the client loses data, and a restore is their problem',
      proves: 'arbitrary file deletion, destructive mass-assignment' },
    { id: 'denial_of_service', label: 'Availability impact',
      unlocks: 'unbounded request loops, resource exhaustion',
      cost: 'the target goes down, during business hours',
      proves: 'ReDoS, zip bombs, unbounded pagination' },
  ],
  note: 'These are declarations about what the client signed for, not settings.',
  never_grantable: 'Leaving the scope. That is the authorization itself.',
};

describe('declaring what the client authorized', () => {
  beforeEach(() => {
    vi.spyOn(api.engagements, 'capabilities').mockResolvedValue(CAPS);
  });

  it('is off by default, which is read-only proof', async () => {
    vi.spyOn(api.engagements, 'create').mockResolvedValue({ engagement: { id: 'e1' } });
    await mount();
    await waitFor(() => screen.getByText(/destructive actions/i));
    for (const box of screen.getAllByRole('checkbox')) {
      if (box.closest('label')?.textContent?.match(/destructive|availability/i)) {
        expect(box.checked).toBe(false);
      }
    }
  });

  it('puts the cost next to the box, not in a tooltip', async () => {
    /* A box labelled "destructive" with no consequences written beside it is a
       box that gets ticked. */
    await mount();
    await waitFor(() => screen.getByText(/destructive actions/i));
    expect(screen.getByText(/the client loses data/i)).toBeTruthy();
    expect(screen.getByText(/the target goes down/i)).toBeTruthy();
  });

  it('says what each one makes provable, so it is a trade and not a warning', async () => {
    await mount();
    await waitFor(() => screen.getByText(/arbitrary file deletion/i));
    expect(screen.getByText(/redos, zip bombs/i)).toBeTruthy();
  });

  it('says that scope is never grantable', async () => {
    await mount();
    await waitFor(() => expect(screen.getByText(/that is the authorization itself/i))
      .toBeTruthy());
  });

  it('sends only what was ticked', async () => {
    const create = vi.spyOn(api.engagements, 'create')
      .mockResolvedValue({ engagement: { id: 'e1' } });
    await mount();
    await waitFor(() => screen.getByText(/destructive actions/i));

    await userEvent.type(screen.getByPlaceholderText('https://app.example.com'),
                         'https://app.example.com');
    await userEvent.click(screen.getByText(/destructive actions/i));
    await userEvent.click(screen.getByRole('checkbox', { name: /authorized/i }));
    await userEvent.click(screen.getByRole('button', { name: /create engagement/i }));

    await waitFor(() => expect(create).toHaveBeenCalled());
    expect(create.mock.calls[0][0].exploit_capabilities).toEqual(['destructive']);
  });

  it('sends nothing when nothing was ticked', async () => {
    const create = vi.spyOn(api.engagements, 'create')
      .mockResolvedValue({ engagement: { id: 'e1' } });
    await mount();
    await waitFor(() => screen.getByText(/destructive actions/i));

    await userEvent.type(screen.getByPlaceholderText('https://app.example.com'),
                         'https://app.example.com');
    await userEvent.click(screen.getByRole('checkbox', { name: /authorized/i }));
    await userEvent.click(screen.getByRole('button', { name: /create engagement/i }));

    await waitFor(() => expect(create).toHaveBeenCalled());
    expect(create.mock.calls[0][0].exploit_capabilities).toBeUndefined();
  });

  it('a failed capability lookup is reported, not an empty section', async () => {
    vi.spyOn(api.engagements, 'capabilities')
      .mockRejectedValue(new Error('backend restarting'));
    await mount();
    await waitFor(() => expect(screen.getByText(/backend restarting/i)).toBeTruthy());
  });
});
