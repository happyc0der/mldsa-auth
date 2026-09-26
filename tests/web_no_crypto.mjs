// V4-13b: "No cryptography in JavaScript" (spec 14), as a check rather than
// a sentence.
//
//   node web_no_crypto.mjs web/client
//
// Every .mjs/.js file under the directory must reach no cryptographic API:
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

const root = process.argv[2];
if (!root) { console.log('usage: web_no_crypto.mjs DIR'); process.exit(2); }

const FORBIDDEN = [
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
walk(root);

let fail = 0;
if (files.length === 0) { console.log(`FAIL: no JavaScript found under ${root} -- the check would pass vacuously`); fail = 1; }
for (const f of files) {
  const lines = readFileSync(f, 'utf8').split('\n');
  const hits = [];
  lines.forEach((l, i) => {
    const code = l.replace(/\/\/.*$/, '');   // a comment may NAME an API; only code may USE one
    for (const [re, what] of FORBIDDEN) { if (re.test(code)) { hits.push(`${f}:${i + 1}: ${what}`); } }
  });
  if (hits.length) { fail = 1; for (const h of hits) { console.log(`FAIL: ${h}`); } }
  else { console.log(`PASS: ${f} reaches no cryptographic API`); }
}
console.log(fail ? '\nFAILED' : `\nAll checks passed (${files.length} file(s))`);
process.exit(fail);
