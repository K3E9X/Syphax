/* Invariants over the pages themselves, not their rendering.
 *
 * Two of these were written because the mistake was actually made in this
 * codebase, twice:
 *
 *  - a page called setLoadError() without declaring the state. The bundler
 *    does not catch it (it is a runtime ReferenceError), the build passes, and
 *    the page crashes the first time the network fails - the exact moment the
 *    error message was supposed to help.
 *  - errors were swallowed with `.catch(() => ...)`, which made "nothing found"
 *    and "the backend is down" render identically.
 */
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const SRC = path.resolve(__dirname, '../..');

/* Comments describe the bugs these tests exist for - including the literal
   text `.catch(() => {})` - so they must be stripped, or the prose documenting
   a fixed bug reads as the bug. */
function stripComments(src) {
  return src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/[^\n]*/g, '$1');
}

function sources(dir) {
  return fs.readdirSync(path.join(SRC, dir))
    .filter((f) => f.endsWith('.jsx'))
    .map((f) => ({
      name: `${dir}/${f}`,
      code: stripComments(fs.readFileSync(path.join(SRC, dir, f), 'utf8')),
    }));
}

const FILES = [...sources('pages'), ...sources('components')];

describe('error state is declared where it is set', () => {
  it.each(FILES)('$name', ({ code }) => {
    const setters = code.match(/set([A-Z]\w*Error)\(/g) || [];
    for (const raw of new Set(setters)) {
      const setter = raw.slice(0, -1);                 // setLoadError
      const state = setter[3].toLowerCase() + setter.slice(4);  // loadError
      const declared = new RegExp(`\\[\\s*${state}\\s*,\\s*${setter}\\s*\\]`).test(code)
        || new RegExp(`const\\s*\\{[^}]*${setter}`).test(code)   // from a hook
        || new RegExp(`${setter}\\s*[,}]`).test(code);
      expect(declared, `${setter}() is called but ${state} is never declared`).toBe(true);
    }
  });
});

describe('no page hides why a request failed', () => {
  // TopNav's health ping sets an explicit offline state, and the two nav
  // fallbacks degrade to a valid route - those are handling, not hiding.
  const ALLOWED = /TopNav|main\.jsx/;

  it.each(FILES.filter((f) => !ALLOWED.test(f.name)))('$name', ({ code }) => {
    const swallowed = code.match(/\.catch\(\(\)\s*=>/g) || [];
    expect(swallowed, 'an ignored rejection makes "empty" and "broken" look alike').toHaveLength(0);
  });
});

describe('every rendered error has something to render', () => {
  it.each(FILES)('$name', ({ name, code }) => {
    if (!/message=\{(\w+)\}/.test(code)) return;
    const shown = [...code.matchAll(/message=\{(\w+)\}/g)].map((m) => m[1]);
    for (const v of new Set(shown)) {
      const defined = new RegExp(`\\[\\s*${v}\\s*,`).test(code)
        || new RegExp(`const\\s+${v}\\s*=`).test(code)
        || new RegExp(`\\b${v}\\s*[,}]`).test(code);
      expect(defined, `<Notice message={${v}}> but ${v} is never defined in ${name}`).toBe(true);
    }
  });
});
