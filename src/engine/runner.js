/* ════════════════════════════════════════════════════════════
   The module runner.

   It emits exactly the events the SSE stream used to emit —
   start / done / complete / stopped — so the popup, the
   renderers and the severity model carry over untouched.
   ════════════════════════════════════════════════════════════ */

import { MODULES } from './registry.js';
import { pool } from './http.js';

/* Per-module budgets — the same table as web.py's MODULE_TIMEOUTS, in ms.
   Each module is timed on its own clock, so a slow one is never killed by a
   deadline sized for another, and fast ones are never held hostage. */
const TIMEOUTS = {
  // fast / cheap
  dns: 60000, geo: 45000, whois: 75000, robots: 45000, ssl: 60000,
  headers: 60000, favicon: 90000, dorks: 30000, osint: 30000,
  // medium (single API / moderate crawling)
  shodan: 90000, censys: 90000, whatweb: 150000, wafw00f: 150000,
  ports: 240000, endpoints: 240000, wayback: 210000,
  email_harvest: 210000, screenshot: 150000, http_inspect: 90000,
  // heavy (many parallel requests / brute / enumeration)
  js_secrets: 300000, api_fuzzer: 300000, content_intel: 300000,
  cloud_buckets: 300000,
  subdomains: 360000, brute: 360000, breachintel: 360000,
  // vulnerability scanner — 358 path checks
  nuclei: 600000,
};
const DEFAULT_TIMEOUT = 180000;   // anything unlisted
const ABS_CAP = 720000;           // hard ceiling per module (12 min)

export const FAST_SKIP = new Set([
  'wayback', 'brute', 'subdomains', 'screenshot', 'email_harvest',
  'nuclei', 'cloud_buckets',
]);

/**
 * Run a scan. `emit` is called with the same event objects the server used.
 * Returns a handle with .stop().
 */
export function runScan({ domain, modules, fast = false, concurrency = 6, delayMs = 60 }, emit) {
  pool.setLimits(concurrency, delayMs);

  const ctl = new AbortController();
  const started = Date.now();

  let keys = (modules && modules.length ? modules : MODULES.map(m => m.key))
    .filter(k => MODULES.some(m => m.key === k));
  if (fast) keys = keys.filter(k => !FAST_SKIP.has(k));

  const pending = new Set(keys);
  let stopped = false;
  let timedOut = 0;

  const elapsed = () => `${((Date.now() - started) / 1000).toFixed(1)}s`;

  // Tell the UI everything that is about to run, so skeletons appear at once.
  for (const k of keys) {
    const m = MODULES.find(x => x.key === k);
    emit({ type: 'start', module: k, description: m.description });
  }

  const done = Promise.all(keys.map(async key => {
    const mod = MODULES.find(m => m.key === key);
    const budget = Math.min(TIMEOUTS[key] || DEFAULT_TIMEOUT, ABS_CAP);

    // Each module gets its own signal, chained to the scan-wide one. Without
    // this a module that blows a 10-minute budget would keep its requests in
    // flight — still hitting the target, still holding slots in the pool —
    // long after its card has been written off.
    const modCtl = new AbortController();
    const chain = () => modCtl.abort();
    ctl.signal.addEventListener('abort', chain, { once: true });

    let data;
    try {
      data = await withTimeout(
        mod.run({ domain, signal: modCtl.signal }),
        budget,
        () => {
          modCtl.abort();                              // stop the stragglers
          return { error: `Module timed out after ${Math.round(budget / 1000)}s` };
        },
      );
      if (data && data.__timedOut) { timedOut++; data = { error: data.error }; }
    } catch (e) {
      if (ctl.signal.aborted) return;                 // STOP — stay silent
      data = { error: String((e && e.message) || e) };
    } finally {
      ctl.signal.removeEventListener('abort', chain);
    }

    if (stopped) return;
    pending.delete(key);
    emit({ type: 'done', module: key, description: mod.description, data });
  }));

  done.then(() => {
    if (stopped) return;
    emit({
      type: 'complete', duration: elapsed(),
      timed_out: timedOut > 0, timed_out_count: timedOut,
    });
  });

  return {
    stop() {
      if (stopped) return;
      stopped = true;
      ctl.abort();
      emit({ type: 'stopped', duration: elapsed(), remaining: [...pending].sort() });
    },
  };
}

function withTimeout(promise, ms, onTimeout) {
  return new Promise(resolve => {
    let settled = false;
    const t = setTimeout(() => {
      if (settled) return;
      settled = true;
      resolve({ ...onTimeout(), __timedOut: true });
    }, ms);
    promise.then(v => {
      if (settled) return;
      settled = true; clearTimeout(t); resolve(v);
    }, e => {
      if (settled) return;
      settled = true; clearTimeout(t);
      resolve({ error: String((e && e.message) || e) });
    });
  });
}
