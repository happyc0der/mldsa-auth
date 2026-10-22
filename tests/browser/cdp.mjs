// A minimal Chrome DevTools Protocol driver (V4-13c), dependency-free: node's
// child_process and its built-in WebSocket. Enough to drive a real headless
// Chromium through the pages -- navigate, evaluate, wait for a condition,
// read network traffic -- and no more.
//
// Chromium only, deliberately (V4-13c decision): WebKit and Gecko speak other
// protocols, and a second driver would be a second thing to trust. Safari is
// checked by hand and recorded, not gated.
//
// Never a fixed sleep: every wait is for a condition, with a deadline.
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// A browser to drive: $MLDSA_BROWSER, else the usual places.
export function findBrowser() {
  const candidates = [
    process.env.MLDSA_BROWSER,
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
    '/Applications/Chromium.app/Contents/MacOS/Chromium',
    '/usr/bin/google-chrome', '/usr/bin/google-chrome-stable', '/usr/bin/chromium', '/usr/bin/chromium-browser',
  ];
  return candidates.find((p) => p && existsSync(p)) ?? null;
}

const until = async (cond, what, ms = 20000, every = 50) => {
  const end = Date.now() + ms;
  for (;;) {
    const v = await cond();
    if (v) { return v; }
    if (Date.now() > end) { throw new Error(`timed out waiting for ${what}`); }
    await new Promise((r) => setTimeout(r, every));
  }
};

export class Browser {
  static async launch(path, extraArgs = []) {
    const profile = mkdtempSync(join(tmpdir(), 'mldsa-cdp-'));
    const args = ['--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profile}`,
                  '--no-first-run', '--no-default-browser-check', '--disable-extensions', ...extraArgs,
                  'about:blank'];
    const proc = spawn(path, args, { stdio: ['ignore', 'ignore', 'pipe'] });
    let err = '';
    proc.stderr.on('data', (d) => { err += d; });
    const portFile = join(profile, 'DevToolsActivePort');
    const port = await until(() => existsSync(portFile) && readFileSync(portFile, 'utf8').split('\n')[0],
                             `the browser's DevTools port (stderr: ${err.slice(0, 200)})`);
    const list = await until(async () => {
      try { return (await (await fetch(`http://127.0.0.1:${port}/json/list`)).json()).find((t) => t.type === 'page'); }
      catch { return null; }
    }, 'a page target');
    const b = new Browser(proc, profile);
    await b.attach(list.webSocketDebuggerUrl);
    return b;
  }

  constructor(proc, profile) {
    Object.assign(this, { proc, profile, id: 0, pending: new Map(), listeners: [] });
  }

  attach(url) {
    return new Promise((resolve, reject) => {
      this.ws = new WebSocket(url);
      this.ws.onopen = resolve;
      this.ws.onerror = () => reject(new Error('DevTools WebSocket failed'));
      // V4-63 (audit F134): a connection that closes fails what was waiting on
      // it. Before, a Browser.close the browser never answered -- it dropped
      // the socket first -- left close() waiting for ever, and browser_e2e
      // ran into CTest's 600 s limit with every check passed.
      this.ws.onclose = () => {
        for (const { rej } of this.pending.values()) { rej(new Error('DevTools connection closed')); }
        this.pending.clear();
      };
      this.ws.onmessage = (ev) => {
        const m = JSON.parse(ev.data);
        if (m.id && this.pending.has(m.id)) {
          const { res, rej } = this.pending.get(m.id);
          this.pending.delete(m.id);
          if (m.error) { rej(new Error(`${m.error.message}`)); } else { res(m.result); }
        } else if (m.method) {
          for (const l of this.listeners) { l(m.method, m.params); }
        }
      };
    });
  }

  send(method, params = {}) {
    const id = ++this.id;
    return new Promise((res, rej) => {
      if (this.ws.readyState !== WebSocket.OPEN) { rej(new Error('DevTools connection closed')); return; }
      this.pending.set(id, { res, rej });
      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }

  on(fn) { this.listeners.push(fn); }

  // Evaluates in the page; awaits promises; returns the value (JSON-able).
  async eval(expression) {
    const r = await this.send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) {
      throw new Error(`page exception: ${r.exceptionDetails.exception?.description ?? r.exceptionDetails.text}`);
    }
    return r.result.value;
  }

  async navigate(url) {
    await this.send('Page.enable');
    let loaded = false;
    const onLoad = (m) => { if (m === 'Page.loadEventFired') { loaded = true; } };
    this.listeners.push(onLoad);
    await this.send('Page.navigate', { url });
    await until(() => loaded, `load of ${url}`);
    this.listeners.splice(this.listeners.indexOf(onLoad), 1);
  }

  waitFor(expression, what, ms) {
    return until(() => this.eval(expression).catch(() => false), what, ms);
  }

  // Every wait here is bounded (V4-63, F134). A browser that died by a signal
  // has a null exitCode and has already emitted 'exit', so waiting on exitCode
  // alone waited for ever; signalCode says it too.
  async close() {
    const exited = () => this.proc.exitCode !== null || this.proc.signalCode !== null;
    const gone = new Promise((r) => { if (exited()) { r(); } else { this.proc.once('exit', r); } });
    const within = (p, ms) => Promise.race([p.then(() => true, () => true),
                                            new Promise((r) => setTimeout(() => r(false), ms))]);
    await within(this.send('Browser.close'), 5000);
    if (!(await within(gone, 10000))) {
      this.proc.kill('SIGKILL');
      await gone;
    }
    try { this.ws.close(); } catch { /* already closed */ }
    rmSync(this.profile, { recursive: true, force: true });
  }
}
