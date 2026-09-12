/* The shared data layer.
 *
 * These hooks replaced eleven hand-rolled copies of the same fetch-and-store
 * logic. Three behaviours here are not obvious from reading the code and break
 * silently when they regress, which is exactly why they are pinned:
 *
 *   1. a slow response must not overwrite a newer one, nor set state after
 *      unmount;
 *   2. an error must reach `error` rather than disappear - the whole point of
 *      replacing `.catch(() => {})`;
 *   3. polling must stop while the tab is hidden and refetch on return.
 */
import { act, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { useApi, usePoll } from '../useApi.js';

function Probe({ hook }) {
  const { data, error, loading } = hook();
  return (
    <div>
      <span data-testid="data">{data == null ? '' : JSON.stringify(data)}</span>
      <span data-testid="error">{error || ''}</span>
      <span data-testid="loading">{loading ? 'yes' : 'no'}</span>
    </div>
  );
}

const txt = (id) => screen.getByTestId(id).textContent;

/* Let every pending promise settle inside act(), so a fetch that resolves in a
   microtask after a timer fires does not update state outside it. */
const flush = () => act(async () => { await Promise.resolve(); await Promise.resolve(); });

/* Advance fake timers and drain the promises the tick queued, inside ONE act()
   call: two separate ones leave a window where the poll's fetch resolves
   outside both, which is what React warns about. */
const tick = (ms) => act(async () => {
  vi.advanceTimersByTime(ms);
  await Promise.resolve();
  await Promise.resolve();
});

/* Same reasoning for a visibility change: it triggers an immediate refetch, so
   the promise it starts must settle inside the same act() call. */
const show = (state) => act(async () => {
  setVisibility(state);
  await Promise.resolve();
  await Promise.resolve();
});

/* Mounting a component that fetches in an effect updates state as soon as the
   promise settles; rendering inside act() keeps that update inside the
   assertion window instead of warning about it. */
async function mount(ui) {
  let r;
  await act(async () => { r = render(ui); });
  return r;
}

function setVisibility(state) {
  Object.defineProperty(document, 'visibilityState', {
    value: state, configurable: true,
  });
  document.dispatchEvent(new Event('visibilitychange'));
}

afterEach(() => {
  vi.useRealTimers();
  setVisibility('visible');
});

describe('useApi', () => {
  it('exposes the resolved data', async () => {
    await mount(<Probe hook={() => useApi(async () => ({ ok: 1 }), [])} />);
    await waitFor(() => expect(txt('data')).toBe('{"ok":1}'));
    expect(txt('loading')).toBe('no');
  });

  it('surfaces a rejection instead of swallowing it', async () => {
    await mount(<Probe hook={() => useApi(async () => { throw new Error('backend down'); }, [])} />);
    await waitFor(() => expect(txt('error')).toBe('backend down'));
  });

  it('clears a stale error once a retry succeeds', async () => {
    let fail = true;
    let reload;
    function P() {
      const s = useApi(async () => {
        if (fail) throw new Error('down');
        return { ok: true };
      }, []);
      reload = s.reload;
      return <span data-testid="error">{s.error || ''}</span>;
    }
    await mount(<P />);
    await waitFor(() => expect(txt('error')).toBe('down'));
    fail = false;
    await act(async () => { await reload(); });
    expect(txt('error')).toBe('');
  });

  it('drops a slow response that a newer call has superseded', async () => {
    // The race the old per-page code had no guard for: two loads in flight,
    // the FIRST resolving last and overwriting fresh data with stale data.
    const resolvers = [];
    let reload;
    function P() {
      const s = useApi(() => new Promise((res) => { resolvers.push(res); }), [],
                       { immediate: false });
      reload = s.reload;
      return <span data-testid="data">{s.data == null ? '' : String(s.data)}</span>;
    }
    await mount(<P />);
    await act(async () => { reload(); reload(); });
    await act(async () => {
      resolvers[1]('fresh');   // newer call answers first
      resolvers[0]('stale');   // older call answers last and must be ignored
    });
    expect(txt('data')).toBe('fresh');
  });

  it('does not set state after unmount', async () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    let resolve;
    function P() {
      useApi(() => new Promise((r) => { resolve = r; }), []);
      return null;
    }
    const { unmount } = await mount(<P />);
    unmount();
    await act(async () => { resolve({ late: true }); });
    expect(spy).not.toHaveBeenCalled();
  });

  it('can be told not to fetch on mount', async () => {
    const fn = vi.fn(async () => 1);
    await mount(<Probe hook={() => useApi(fn, [], { immediate: false })} />);
    await waitFor(() => expect(txt('loading')).toBe('no'));
    expect(fn).not.toHaveBeenCalled();
  });
});

describe('usePoll', () => {
  it('repeats on the interval while active', async () => {
    vi.useFakeTimers();
    const fn = vi.fn(async () => 1);
    await mount(<Probe hook={() => usePoll(fn, 1000)} />);
    await flush();
    expect(fn).toHaveBeenCalledTimes(1);
    await tick(3000);
    expect(fn.mock.calls.length).toBeGreaterThanOrEqual(3);
  });

  it('does not poll when inactive', async () => {
    vi.useFakeTimers();
    const fn = vi.fn(async () => 1);
    await mount(<Probe hook={() => usePoll(fn, 1000, { active: false })} />);
    await flush();
    const initial = fn.mock.calls.length;   // the mount fetch still happens
    await tick(5000);
    expect(fn).toHaveBeenCalledTimes(initial);
  });

  it('stops while the tab is hidden', async () => {
    // A forgotten background tab used to hammer the API for as long as it
    // stayed open, because nothing checked visibilityState.
    vi.useFakeTimers();
    const fn = vi.fn(async () => 1);
    await mount(<Probe hook={() => usePoll(fn, 1000)} />);
    await flush();
    await show('hidden');
    const whileHidden = fn.mock.calls.length;
    await tick(10000);
    expect(fn).toHaveBeenCalledTimes(whileHidden);
  });

  it('refetches immediately when the tab comes back', async () => {
    // Otherwise returning to the tab shows numbers up to one interval stale.
    vi.useFakeTimers();
    const fn = vi.fn(async () => 1);
    await mount(<Probe hook={() => usePoll(fn, 60000)} />);
    await flush();
    await show('hidden');
    const before = fn.mock.calls.length;
    await show('visible');
    expect(fn.mock.calls.length).toBe(before + 1);
  });

  it('stops polling on unmount', async () => {
    vi.useFakeTimers();
    const fn = vi.fn(async () => 1);
    const { unmount } = await mount(<Probe hook={() => usePoll(fn, 1000)} />);
    await flush();
    unmount();
    const after = fn.mock.calls.length;
    await tick(10000);
    expect(fn).toHaveBeenCalledTimes(after);
  });

  it('surfaces a polling failure like any other', async () => {
    await mount(<Probe hook={() => usePoll(async () => { throw new Error('gone'); }, 0)} />);
    await waitFor(() => expect(txt('error')).toBe('gone'));
  });
});
