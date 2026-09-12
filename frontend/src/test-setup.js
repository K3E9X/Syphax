/* Vitest setup.
 *
 * React 19 only suppresses its "update not wrapped in act(...)" warning when
 * this flag is set before the first render. Testing Library sets it too, but
 * only once it is imported - which is after the module graph has already been
 * evaluated. Setting it here covers every test file.
 */
globalThis.IS_REACT_ACT_ENVIRONMENT = true;
