// V4-13b: gates on the browser module itself, read from the BUILT files.
//
//   node wasm_module_gates.mjs mldsa_client.wasm mldsa_client.mjs web/exports.txt
//
// 1. Exports, both ways. What a page can CALL is what the module factory puts
//    on the instance, so the module is loaded here exactly as a page loads it
//    and its `_`-prefixed functions must be exactly web/exports.txt.
//    EMSCRIPTEN_KEEPALIVE exports a function whether or not the linker was
//    told to, so passing the list to the linker proves nothing on its own.
//    Underneath, the raw module is read with WebAssembly's own parser: at -O2
//    Emscripten minifies export names (and 6.0.9 will not keep them under
//    MODULARIZE), so there the check is by COUNT -- the listed functions plus
//    exactly one runtime export (the constructor hook the glue calls itself),
//    one memory, and nothing else. An extra export fails either way.
// 2. Size: .wasm + .mjs within V4-2 S6's 1.5 MB budget for a login page.
// 3. The glue contains no eval and no `new Function` (-sDYNAMIC_EXECUTION=0),
//    so a page can serve it under a CSP without 'unsafe-eval'.
//
// Dependency-free on purpose: node's built-ins only.
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const [wasmPath, mjsPath, listPath] = process.argv.slice(2);
if (!wasmPath || !mjsPath || !listPath) {
  console.log('usage: wasm_module_gates.mjs MODULE.wasm MODULE.mjs exports.txt');
  process.exit(2);
}
let fail = 0;
const check = (ok, what) => { console.log(`${ok ? 'PASS' : 'FAIL'}: ${what}`); if (!ok) fail = 1; };

const wasm = readFileSync(wasmPath);
const mjs = readFileSync(mjsPath);
const listed = readFileSync(listPath, 'utf8').split('\n')
  .map((l) => l.trim()).filter((l) => l.startsWith('_'));

const factory = (await import(pathToFileURL(mjsPath).href)).default;
const instance = await factory();
const callable = Object.keys(instance).filter((k) => k.startsWith('_') && typeof instance[k] === 'function');
const unlisted = callable.filter((n) => !listed.includes(n));
const missing = listed.filter((n) => !callable.includes(n));
check(unlisted.length === 0,
  'a page can call nothing beyond web/exports.txt' + (unlisted.length ? ` -- UNLISTED: ${unlisted.join(', ')}` : ''));
check(missing.length === 0,
  `a page can call every function web/exports.txt lists (${listed.length})` +
  (missing.length ? ` -- MISSING: ${missing.join(', ')}` : ''));
check(listed.filter((n) => n.startsWith('_ccw_')).length === 23,
  'the list names the 23 ccw_ entry points of apps/authd/client_wasm.h');

const raw = WebAssembly.Module.exports(new WebAssembly.Module(wasm));
const kinds = {};
for (const e of raw) { kinds[e.kind] = (kinds[e.kind] || 0) + 1; }
const RUNTIME_FUNCTIONS = 1;   // the constructor hook, called by the glue at instantiation
check(kinds.function === listed.length + RUNTIME_FUNCTIONS && kinds.memory === 1 &&
      Object.keys(kinds).length === 2,
  `the raw module exports ${listed.length} + ${RUNTIME_FUNCTIONS} functions and one memory, nothing else ` +
  `(found ${JSON.stringify(kinds)})`);

const BUDGET = 1500000;
const total = wasm.length + mjs.length;
check(total <= BUDGET,
  `size: ${wasm.length} B wasm + ${mjs.length} B glue = ${total} B, budget ${BUDGET} B (V4-2 S6)`);

const glue = mjs.toString('utf8');
check(!/\beval\s*\(/.test(glue) && !/\bnew\s+Function\s*\(/.test(glue),
  'the glue calls neither eval nor new Function (CSP without unsafe-eval)');

console.log(fail ? '\nFAILED' : '\nAll checks passed');
process.exit(fail);
