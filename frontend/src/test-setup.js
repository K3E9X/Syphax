/* Vitest setup.
 *
 * React 19 only suppresses its "update not wrapped in act(...)" warning when
 * this flag is set before the first render. Testing Library sets it too, but
 * only once it is imported - which is after the module graph has already been
 * evaluated. Setting it here covers every test file.
 */
globalThis.IS_REACT_ACT_ENVIRONMENT = true;

/* Unmount every rendered tree after each test.
 *
 * Without this, components stay mounted across tests in the same file - and a
 * component that registers a global listener (the command palette listens for
 * ⌘K on window) leaves that listener behind. A later test's keystroke then
 * toggles a leftover palette too, and a query for the dialog finds one that
 * belongs to a previous test. That was an intermittent, order-dependent
 * failure that passed in isolation and flaked in the full run. Cleanup is the
 * correct baseline; it is not specific to the palette.
 */
import { cleanup } from '@testing-library/react';
import { afterEach } from 'vitest';

afterEach(() => cleanup());
