/* Lint configuration.
 *
 * Same principle as backend/ruff.toml: catch bugs, not style. The rules below
 * are the ones whose violation is invisible in a passing build:
 *
 *   no-undef            - four pages called setLoadError() without declaring
 *                         the state. `npm run build` was perfectly happy; the
 *                         page threw ReferenceError the moment it rendered.
 *   react-hooks/*       - a hook called conditionally, or an effect missing a
 *                         dependency, produces stale data rather than an error.
 *   no-unused-vars      - a variable left behind by a refactor is usually the
 *                         half of the change that did not land.
 *
 * Formatting rules are absent on purpose. Nothing here reformats code.
 */
import js from '@eslint/js';
import globals from 'globals';
import reactHooks from 'eslint-plugin-react-hooks';
import react from 'eslint-plugin-react';

export default [
  { ignores: ['dist/**', 'node_modules/**', 'design/**'] },
  js.configs.recommended,
  {
    files: ['src/**/*.{js,jsx}'],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'module',
      globals: { ...globals.browser },
      parserOptions: { ecmaFeatures: { jsx: true } },
    },
    plugins: { 'react-hooks': reactHooks, react },
    rules: {
      ...reactHooks.configs.recommended.rules,
      // Without this, every imported component reads as an unused variable:
      // core ESLint does not know that <Card/> is a use of `Card`.
      'react/jsx-uses-vars': 'error',
      // An empty catch block is how an error disappears. Six of them were
      // hiding failures in this codebase; the ones that remain are deliberate
      // and say so in a comment, which this allows for.
      'no-empty': ['error', { allowEmptyCatch: true }],
      'no-unused-vars': ['error', {
        argsIgnorePattern: '^_',
        varsIgnorePattern: '^_',
        caughtErrors: 'none',
      }],
    },
  },
  {
    files: ['src/**/*.test.{js,jsx}', 'src/test-setup.js'],
    languageOptions: { globals: { ...globals.browser, ...globals.node } },
  },
];
