// A request to the site, given up on after SITE_TIMEOUT_MS (V4-281, F461).
// No imports, so tests/site_sessions.mjs runs it under Node as the pages do.
//
// post() was a plain fetch with no deadline, and the enrollment awaits it
// while holding the identity's lock (F303): a front end that accepted
// /api/enroll and never answered left the page waiting with its button
// disabled and no message, and a Forget or a login of that key in another
// tab queued behind it for as long. Given up on, a request is NO answer --
// an error with no status -- so a key it was enrolling is kept, marked
// unconfirmed, as for any other request the site did not answer (F220).
// The site itself gives up on the daemon after 10 s; this is longer.
export const SITE_TIMEOUT_MS = 30 * 1000;

const late = (ms) => new Error(`the site did not answer in ${ms >= 1000 ? `${Math.round(ms / 1000)} s` : `${ms} ms`}; ` +
                               'nothing is assumed to have happened');

// Resolves to { r, j }: the response and its JSON body (null when the body
// is not JSON). Rejects, with no `status`, when the deadline passes first,
// whether it passes before the headers or while the body is read.
export async function siteFetch(url, init = {}, timeoutMs = SITE_TIMEOUT_MS) {
  const signal = AbortSignal.timeout(timeoutMs);
  let r;
  try { r = await fetch(url, { ...init, signal }); } catch (e) { throw signal.aborted ? late(timeoutMs) : e; }
  let j = null;
  try { j = await r.json(); } catch { if (signal.aborted) { throw late(timeoutMs); } }
  return { r, j };
}
