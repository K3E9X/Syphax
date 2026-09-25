/* The command palette.
 *
 * The behaviours that make it trustworthy: ⌘K opens it, it reaches live
 * engagements and findings (not just static pages), Enter routes rather than
 * acting, and it hands focus back where it came from on close.
 */
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import CommandPalette from '../CommandPalette.jsx';
import { api } from '../../lib/api.js';

const mockNavigate = vi.fn();
vi.mock('react-router-dom', async () => ({
  ...(await vi.importActual('react-router-dom')),
  useNavigate: () => mockNavigate,
}));

async function mount() {
  let r;
  await act(async () => {
    r = render(<MemoryRouter><CommandPalette /></MemoryRouter>);
  });
  return r;
}

function openPalette() {
  fireEvent.keyDown(window, { key: 'k', metaKey: true });
}

beforeEach(() => {
  vi.restoreAllMocks();
  mockNavigate.mockClear();
  vi.spyOn(api.engagements, 'list').mockResolvedValue({
    items: [{ id: 'e1', title: 'ACME prod', target_host: 'app.acme.com', status: 'authorized' }],
  });
  vi.spyOn(api.findings, 'list').mockResolvedValue({
    items: [{ id: 'f1', title: 'SQL injection on /login', target: 'https://app.acme.com/login',
              cls: 'sql_injection', severity: 'critical' }],
  });
});

it('is closed until the shortcut opens it', async () => {
  await mount();
  expect(screen.queryByRole('dialog')).toBeNull();
  await act(async () => { openPalette(); });
  expect(screen.getByRole('dialog')).toBeTruthy();
});

it('toggles shut on a second ⌘K and on Escape', async () => {
  await mount();
  await act(async () => { openPalette(); });
  await act(async () => { openPalette(); });
  expect(screen.queryByRole('dialog')).toBeNull();

  await act(async () => { openPalette(); });
  await userEvent.keyboard('{Escape}');
  expect(screen.queryByRole('dialog')).toBeNull();
});

it('opens on the custom event the nav chip dispatches', async () => {
  await mount();
  await act(async () => {
    window.dispatchEvent(new CustomEvent('syphax:command-palette'));
  });
  expect(screen.getByRole('dialog')).toBeTruthy();
});

describe('reaching things', () => {
  it('lists the static pages', async () => {
    await mount();
    await act(async () => { openPalette(); });
    expect(screen.getByText('Methodology')).toBeTruthy();
    expect(screen.getByText('Sandbox')).toBeTruthy();
  });

  it('reaches a live finding by its title and routes to it', async () => {
    await mount();
    await act(async () => { openPalette(); });
    await waitFor(() => screen.getByText('SQL injection on /login'));
    await userEvent.type(screen.getByRole('combobox'), 'sqli');
    await waitFor(() => screen.getByText('SQL injection on /login'));
    await userEvent.click(screen.getByText('SQL injection on /login'));
    expect(mockNavigate).toHaveBeenCalledWith('/findings');
  });

  it('reaches a live engagement and routes to its live view', async () => {
    await mount();
    await act(async () => { openPalette(); });
    await waitFor(() => screen.getByText('ACME prod'));
    await userEvent.click(screen.getByText('ACME prod'));
    expect(mockNavigate).toHaveBeenCalledWith('/engagements/e1/live');
  });
});

describe('keyboard', () => {
  it('Enter opens the top-ranked result', async () => {
    await mount();
    await act(async () => { openPalette(); });
    await userEvent.type(screen.getByRole('combobox'), 'settings');
    await userEvent.keyboard('{Enter}');
    expect(mockNavigate).toHaveBeenCalledWith('/settings');
  });

  it('never performs an action - it only navigates', async () => {
    /* The safety line: a fuzzy-matched Enter must not be able to start a run or
       approve a PoC. Every row is a route; the palette imports no action verb
       from the api beyond the two read-only list calls. */
    const run = vi.spyOn(api.engagements, 'run').mockResolvedValue({});
    await mount();
    await act(async () => { openPalette(); });
    await userEvent.type(screen.getByRole('combobox'), 'new engagement');
    await userEvent.keyboard('{Enter}');
    expect(mockNavigate).toHaveBeenCalledWith('/engagements');
    expect(run).not.toHaveBeenCalled();
  });

  it('shows an explicit empty state rather than a blank panel', async () => {
    await mount();
    await act(async () => { openPalette(); });
    await userEvent.type(screen.getByRole('combobox'), 'zzzznotathing');
    await waitFor(() => expect(screen.getByText(/no match/i)).toBeTruthy());
  });
});
