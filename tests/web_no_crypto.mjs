// V4-13b: "No cryptography in JavaScript" (spec 14), as a check rather than
// a sentence.
//
//   node web_no_crypto.mjs web/client web/pages
//
// Every .mjs/.js file under the directories must reach no cryptographic API:
// not WebCrypto (crypto.subtle, getRandomValues, randomUUID), not Node's
// crypto module, and not Math.random (which has no business near a key and
// is the classic way a "just this once" nonce gets written). Randomness and
// every primitive live in the wasm module, where libsodium draws from the
// host's generator on its own.
//
// Literal matching on source text, deliberately simple: this is a tripwire
// for the honest mistake, not a sandbox against a hostile author -- that is
// code review's job, and CSP's in the browser.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const roots = process.argv.slice(2);
if (roots.length === 0) { console.log('usage: web_no_crypto.mjs DIR...'); process.exit(2); }

const FORBIDDEN = [
  // The global itself, however it is reached (V4-207, F283): `crypto.subtle`
  // was the only spelling looked for, and `const { subtle } = crypto`,
  // `globalThis.crypto` and `window.crypto` name no such pair.
  [/\bcrypto\b/, 'the crypto global'],
  [/\bsubtle\b/, 'subtle'],
  [/crypto\s*\.\s*subtle/, 'crypto.subtle'],
  [/getRandomValues/, 'getRandomValues'],
  [/randomUUID/, 'randomUUID'],
  [/['"](node:)?crypto['"]/, "Node's crypto module"],
  [/\bcreateHash\b|\bcreateHmac\b|\bcreateCipheriv\b|\bpbkdf2\b|\bscrypt\b/, 'a Node crypto primitive'],
  [/Math\s*\.\s*random/, 'Math.random'],
];

const files = [];
const walk = (d) => {
  for (const n of readdirSync(d)) {
    const p = join(d, n);
    if (statSync(p).isDirectory()) { walk(p); } else if (/\.(m?js)$/.test(n)) { files.push(p); }
  }
};
let fail = 0;
for (const root of roots) {
  const before = files.length;
  walk(root);
  if (files.length === before) { console.log(`FAIL: no JavaScript found under ${root} -- the check would pass vacuously`); fail = 1; }
}

// A comment may NAME an API; only code may USE one. A comment starts at `//`
// at the start of a line or after white space -- not at the `//` of 'ws://',
// which used to end the line for this check and hide whatever followed it
// (F283).
const codeOf = (l) => l.replace(/(^|\s)\/\/.*$/, '$1');
const hitsIn = (text) => {
  const out = [];
  text.split('\n').forEach((l, i) => {
    const code = codeOf(l);
    for (const [re, what] of FORBIDDEN) { if (re.test(code)) { out.push([i + 1, what]); } }
  });
  return out;
};

// The check checks itself first (F283): each of these must be flagged, and
// each of those must not, or nothing below means anything.
{ const MUST = ['const d = await crypto.subtle.digest("SHA-256", b);',
                'const { subtle } = crypto;',
                'const k = await subtle.importKey("raw", b, "HKDF", false, ["deriveBits"]);',
                'globalThis.crypto.getRandomValues(buf);',
                'const u = `ws://${location.host}/x`; window.crypto.getRandomValues(buf);',
                "const u = 'https://example/'; const r = Math.random();",
                "import { createHash } from 'node:crypto';",
                'const id = self.crypto.randomUUID();'];
  const MUST_NOT = ['// crypto.subtle is what this file must never reach',
                    'const x = 1; // no Math.random here either',
                    "const url = `${scheme}://${location.host}/authd/v1?state=${sess.state}`;",
                    '// timed before any cryptography: whether the phone is slow',
                    'const b64 = btoa(String.fromCharCode(...b));'];
  const missed = MUST.filter((l) => hitsIn(l).length === 0);
  const wrong = MUST_NOT.filter((l) => hitsIn(l).length !== 0);
  if (missed.length || wrong.length) {
    for (const l of missed) { console.log(`FAIL: self-test: not flagged: ${l}`); }
    for (const l of wrong) { console.log(`FAIL: self-test: flagged a line that uses nothing: ${l}`); }
    fail = 1;
  } else {
    console.log(`PASS: self-test: ${MUST.length} uses are flagged and ${MUST_NOT.length} harmless lines are not`);
  }
}

for (const f of files) {
  const hits = hitsIn(readFileSync(f, 'utf8')).map(([n, what]) => `${f}:${n}: ${what}`);
  if (hits.length) { fail = 1; for (const h of hits) { console.log(`FAIL: ${h}`); } }
  else { console.log(`PASS: ${f} reaches no cryptographic API`); }
}
console.log(fail ? '\nFAILED' : `\nAll checks passed (${files.length} file(s))`);
process.exit(fail);
