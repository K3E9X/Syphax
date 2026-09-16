/* The model configuration, and the screen that will not let go of the operator
 * until it exists.
 *
 * The bug this replaces: a fresh install let you press Run, the planner fell
 * back to a client with no key, every call raised, the loop caught it and
 * emitted one "degraded" event - and the run looked like a tool that found
 * nothing rather than a tool that was never configured.
 */
import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { AuthProvider } from '../../lib/auth.jsx';
import Gate from '../Gate.jsx';
import ModelRouter from '../ModelRouter.jsx';
import { api } from '../../lib/api.js';

const USER = { id: 'u1', username: 'operator', role: 'admin' };

const CATALOG = {
  items: [
    { id: 'zai', label: 'Z.ai (GLM)', base_url: 'https://api.z.ai/api/paas/v4',
      models: ['glm-5.2', 'glm-4.6'], console_url: 'https://z.ai', note: 'cheap and fast' },
    { id: 'moonshot', label: 'Moonshot (Kimi)', base_url: 'https://api.moonshot.ai/v1',
      models: ['kimi-k3'], console_url: 'https://platform.moonshot.ai', note: 'slow, strong' },
    { id: 'custom', label: 'Other (OpenAI-compatible)', base_url: '', models: [], note: '' },
  ],
  roles: [
    { role: 'planner', note: 'decides next moves', default_provider: 'moonshot' },
    { role: 'executor', note: 'drives the tools', default_provider: 'zai' },
    { role: 'validator', note: 'kills false positives', default_provider: 'zai' },
  ],
};

const UNCONFIGURED = {
  model_router: {
    planner: { base_url: '', model: '' },
    executor: { base_url: '', model: '' },
    validator: { base_url: '', model: '' },
  },
  provider_keys: { zai: 'unset', moonshot: 'unset', custom: 'unset' },
  llm: { ready: false, missing: ['planner', 'executor', 'validator'],
         summary: 'No LLM provider is configured.' , roles: [] },
};

const CONFIGURED = {
  model_router: {
    planner: { base_url: 'https://api.z.ai/api/paas/v4', model: 'glm-5.2' },
    executor: { base_url: 'https://api.z.ai/api/paas/v4', model: 'glm-5.2' },
    validator: { base_url: 'https://api.z.ai/api/paas/v4', model: 'glm-5.2' },
  },
  provider_keys: { zai: 'set', moonshot: 'unset', custom: 'unset' },
  llm: { ready: true, missing: [], summary: 'All three roles have a provider and a model.', roles: [] },
};

async function mount(ui) {
  let r;
  await act(async () => { r = render(ui); });
  return r;
}

beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(api.llm, 'providers').mockResolvedValue(CATALOG);
});

describe('the gate in front of the app', () => {
  const shellAt = (path) => (
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider><Gate><div>engagement data</div></Gate></AuthProvider>
    </MemoryRouter>
  );
  const shell = shellAt('/');

  beforeEach(() => {
    vi.spyOn(api.auth, 'status').mockResolvedValue({ authenticated: true, user: USER });
  });

  it('blocks a signed-in operator while no model is configured', async () => {
    vi.spyOn(api.llm, 'readiness').mockResolvedValue({ ready: false, missing: ['planner'] });
    vi.spyOn(api.settings, 'get').mockResolvedValue(UNCONFIGURED);
    await mount(shell);
    await waitFor(() =>
      expect(screen.getByRole('heading', { name: /connect a model/i })).toBeTruthy());
    expect(screen.queryByText('engagement data')).toBeNull();
  });

  it('lets them through once it is', async () => {
    vi.spyOn(api.llm, 'readiness').mockResolvedValue({ ready: true, missing: [] });
    await mount(shell);
    await waitFor(() => expect(screen.getByText('engagement data')).toBeTruthy());
  });

  it('lets Recon through with no model, because Recon does not use one', async () => {
    /* The page reads DNS, the registries, a certificate and one HTTP response,
       and every conclusion it draws is a pure function over those. Holding it
       behind a model would be the tool refusing to do something it is
       perfectly capable of - and it is the page someone evaluating this
       reaches for before they go and buy an API key. */
    vi.spyOn(api.llm, 'readiness').mockResolvedValue({ ready: false, missing: ['planner'] });
    vi.spyOn(api.settings, 'get').mockResolvedValue(UNCONFIGURED);
    await mount(shellAt('/recon'));
    await waitFor(() => expect(screen.getByText('engagement data')).toBeTruthy());
    expect(screen.queryByRole('heading', { name: /connect a model/i })).toBeNull();
  });

  it('says on that page that the rest of the tool is still blocked', async () => {
    /* Otherwise the operator finishes a recon, presses Create an engagement,
       and lands on a setup screen with no idea why. */
    vi.spyOn(api.llm, 'readiness').mockResolvedValue({ ready: false, missing: ['planner'] });
    vi.spyOn(api.settings, 'get').mockResolvedValue(UNCONFIGURED);
    await mount(shellAt('/recon'));
    await waitFor(() => screen.getByText('engagement data'));
    const banner = screen.getByRole('status');
    expect(banner.textContent).toMatch(/no model is connected/i);
    expect(within(banner).getByRole('link', { name: /connect a model/i })).toBeTruthy();
  });

  it('still blocks every other route', async () => {
    vi.spyOn(api.llm, 'readiness').mockResolvedValue({ ready: false, missing: ['planner'] });
    vi.spyOn(api.settings, 'get').mockResolvedValue(UNCONFIGURED);
    for (const path of ['/', '/engagements', '/findings', '/reconstruction']) {
      const { unmount } = await mount(shellAt(path));
      await waitFor(() =>
        expect(screen.getByRole('heading', { name: /connect a model/i })).toBeTruthy());
      unmount();
    }
  });

  it('shows no such banner once a model is connected', async () => {
    vi.spyOn(api.llm, 'readiness').mockResolvedValue({ ready: true, missing: [] });
    await mount(shellAt('/recon'));
    await waitFor(() => screen.getByText('engagement data'));
    expect(screen.queryByText(/no model is connected/i)).toBeNull();
  });

  it('does not lock the operator out when the check itself fails', async () => {
    /* A transient backend hiccup must not make the whole UI unusable - the run
       gate still refuses on the server side. But it has to SAY so: swallowing
       it is how "the tool found nothing" became a mystery. */
    vi.spyOn(api.llm, 'readiness').mockRejectedValue(new Error('backend restarting'));
    await mount(shell);
    await waitFor(() => expect(screen.getByText('engagement data')).toBeTruthy());
    expect(screen.getByRole('status').textContent).toMatch(/backend restarting/i);
  });
});

describe('the form', () => {
  it('offers every provider the backend serves, not a hardcoded list', async () => {
    vi.spyOn(api.settings, 'get').mockResolvedValue(UNCONFIGURED);
    await mount(<ModelRouter />);
    await waitFor(() => screen.getByLabelText('Provider'));
    const options = [...screen.getByLabelText('Provider').options].map((o) => o.value);
    expect(options).toEqual(['', 'zai', 'moonshot', 'custom']);
  });

  it('refuses to save without a key for the provider it points at', async () => {
    vi.spyOn(api.settings, 'get').mockResolvedValue(UNCONFIGURED);
    const save = vi.spyOn(api.settings, 'save');
    await mount(<ModelRouter />);
    await waitFor(() => screen.getByLabelText('Provider'));

    await userEvent.selectOptions(screen.getByLabelText('Provider'), 'zai');
    const button = screen.getByRole('button', { name: /save model router/i });
    expect(button.disabled).toBe(true);
    expect(screen.getByText(/missing a key for/i)).toBeTruthy();
    expect(save).not.toHaveBeenCalled();
  });

  it('fills the endpoint and the model from the catalog when a provider is picked', async () => {
    vi.spyOn(api.settings, 'get').mockResolvedValue(UNCONFIGURED);
    await mount(<ModelRouter />);
    await waitFor(() => screen.getByLabelText('Provider'));
    await userEvent.selectOptions(screen.getByLabelText('Provider'), 'zai');
    expect(screen.getByPlaceholderText('https://…').value)
      .toBe('https://api.z.ai/api/paas/v4');
    expect(screen.getByPlaceholderText('model').value).toBe('glm-5.2');
  });

  it('saves the router and the key together, then clears the key field', async () => {
    vi.spyOn(api.settings, 'get').mockResolvedValue(UNCONFIGURED);
    const save = vi.spyOn(api.settings, 'save').mockResolvedValue(CONFIGURED);
    const onSaved = vi.fn();
    await mount(<ModelRouter onSaved={onSaved} />);
    await waitFor(() => screen.getByLabelText('Provider'));

    await userEvent.selectOptions(screen.getByLabelText('Provider'), 'zai');
    await userEvent.type(screen.getByLabelText(/z\.ai/i), 'sk-test-key');
    await userEvent.click(screen.getByRole('button', { name: /save model router/i }));

    await waitFor(() => expect(save).toHaveBeenCalled());
    const payload = save.mock.calls[0][0];
    expect(payload.provider_keys).toEqual({ zai: 'sk-test-key' });
    expect(payload.model_router.planner.base_url).toBe('https://api.z.ai/api/paas/v4');
    // One provider for all three roles is the default path.
    expect(payload.model_router.validator.model).toBe('glm-5.2');
    await waitFor(() => expect(onSaved).toHaveBeenCalled());
    expect(screen.getByLabelText(/z\.ai/i).value).toBe('');
  });

  it('a stored key counts, so an existing install can change the model alone', async () => {
    vi.spyOn(api.settings, 'get').mockResolvedValue(CONFIGURED);
    const save = vi.spyOn(api.settings, 'save').mockResolvedValue(CONFIGURED);
    await mount(<ModelRouter />);
    await waitFor(() => screen.getByLabelText('Provider'));
    expect(screen.getByRole('button', { name: /save model router/i }).disabled).toBe(false);

    await userEvent.clear(screen.getByPlaceholderText('model'));
    await userEvent.type(screen.getByPlaceholderText('model'), 'glm-4.6');
    await userEvent.click(screen.getByRole('button', { name: /save model router/i }));
    await waitFor(() => expect(save).toHaveBeenCalled());
    expect(save.mock.calls[0][0].provider_keys).toBeUndefined();
  });

  it('keeps a deliberate per-role split instead of collapsing it on load', async () => {
    const split = {
      ...CONFIGURED,
      model_router: {
        planner: { base_url: 'https://api.moonshot.ai/v1', model: 'kimi-k3' },
        executor: { base_url: 'https://api.z.ai/api/paas/v4', model: 'glm-5.2' },
        validator: { base_url: 'https://api.z.ai/api/paas/v4', model: 'glm-5.2' },
      },
      provider_keys: { zai: 'set', moonshot: 'set', custom: 'unset' },
    };
    vi.spyOn(api.settings, 'get').mockResolvedValue(split);
    await mount(<ModelRouter />);
    await waitFor(() => screen.getByLabelText(/one provider for all three roles/i));
    expect(screen.getByLabelText(/one provider for all three roles/i).checked).toBe(false);
    // Three role blocks, not one.
    expect(screen.getAllByLabelText('Provider')).toHaveLength(3);
  });

  it('surfaces a failed settings load instead of rendering an empty form', async () => {
    vi.spyOn(api.settings, 'get').mockRejectedValue(new Error('database unavailable'));
    await mount(<ModelRouter />);
    await waitFor(() => expect(screen.getByRole('alert').textContent)
      .toMatch(/database unavailable/i));
  });
});
