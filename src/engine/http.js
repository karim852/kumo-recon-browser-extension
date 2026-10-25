/* ════════════════════════════════════════════════════════════
   The HTTP layer for the in-browser engine.

   Every request the extension makes against a target goes through
   here, which is what makes the safety properties checkable in one
   place rather than scattered across 26 modules:

     · credentials:'omit'  — the scan NEVER carries the user's
       cookies or auth to the target. Without this, probing
       /admin while logged in would be a self-inflicted CSRF.
     · a global concurrency cap and inter-request delay, so a
       scan is a trickle rather than something that looks like
       an attack to a WAF.
     · a hard per-request timeout, because a hung socket would
       otherwise pin a module until its own deadline.
     · abort propagation, so STOP actually stops.
   ════════════════════════════════════════════════════════════ */

export const UA_NOTE = 'Kumo extension — requests are sent without credentials';

/* ── a small semaphore: N in flight, with a gap between starts ── */
class Pool {
  constructor(limit = 6, gapMs = 60) {
    this.limit = limit;
    this.gap = gapMs;
    this.active = 0;
    this.queue = [];
    this.lastStart = 0;
  }
  setLimits(limit, gapMs) {
    this.limit = Math.max(1, limit | 0);
    this.gap = Math.max(0, gapMs | 0);
  }
  run(fn) {
    return new Promise((resolve, reject) => {
      this.queue.push({ fn, resolve, reject });
      this._drain();
    });
  }
  async _drain() {
    if (this.active >= this.limit || !this.queue.length) return;
    const now = Date.now();
    const wait = Math.max(0, this.lastStart + this.gap - now);
    if (wait > 0) { setTimeout(() => this._drain(), wait); return; }

    const job = this.queue.shift();
    this.active++;
    this.lastStart = Date.now();
    try { job.resolve(await job.fn()); }
    catch (e) { job.reject(e); }
    finally { this.active--; this._drain(); }
  }
}

export const pool = new Pool();

/* ── the one request primitive ──────────────────────────────── */
export async function request(url, opts = {}) {
  const {
    method = 'GET',
    timeout = 8000,
    signal,              // the scan-wide abort signal
    headers = {},
    redirect = 'follow',
    body,
    maxBytes = 512 * 1024,
    wantBody = true,
  } = opts;

  return pool.run(async () => {
    if (signal && signal.aborted) throw new DOMException('aborted', 'AbortError');

    const ctl = new AbortController();
    const onAbort = () => ctl.abort();
    if (signal) signal.addEventListener('abort', onAbort, { once: true });

    // Track WHY we aborted. Without this the browser's own wording,
    // "signal is aborted without reason", ends up printed on a result card,
    // which tells the user nothing about what actually happened.
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; ctl.abort(); }, timeout);

    const started = Date.now();
    try {
      const res = await fetch(url, {
        method,
        headers,
        body,
        redirect,
        signal: ctl.signal,
        // The three that matter — never carry the user's session to a target.
        credentials: 'omit',
        cache: 'no-store',
        referrerPolicy: 'no-referrer',
      });

      const out = {
        ok: res.ok,
        status: res.status,
        url: res.url,
        redirected: res.redirected,
        type: res.type,
        headers: headersToObject(res.headers),
        elapsed: Date.now() - started,
        body: '',
        bytes: 0,
        truncated: false,
      };

      if (wantBody) {
        const { text, bytes, truncated } = await readCapped(res, maxBytes);
        out.body = text;
        out.bytes = bytes;
        out.truncated = truncated;
      } else {
        try { await res.body?.cancel(); } catch (_) {}
      }
      return out;
    } catch (e) {
      if (e && e.name === 'AbortError') {
        // Our own clock ran out: say so, and name the host so the card is
        // actionable.
        if (timedOut) {
          const span = timeout >= 1000 ? `${Math.round(timeout / 1000)}s` : `${timeout}ms`;
          const err = new Error(`${hostOf(url)} did not respond within ${span}`);
          err.name = 'TimeoutError';
          throw err;
        }
        // The scan was stopped, or the module blew its budget. Keep the
        // AbortError name so the runner recognises it and stays quiet.
        throw e;
      }
      // "Failed to fetch" is Chrome's catch-all for DNS failure, connection
      // refused, TLS problems and blocked requests. Make it say which host.
      if (/failed to fetch|networkerror|load failed/i.test(String(e && e.message))) {
        throw new Error(`Could not reach ${hostOf(url)} (DNS, TLS or connection refused)`);
      }
      throw e;
    } finally {
      clearTimeout(timer);
      if (signal) signal.removeEventListener('abort', onAbort);
    }
  });
}

/* A page can be enormous; read only what a matcher could need. */
async function readCapped(res, maxBytes) {
  if (!res.body) {
    const text = await res.text().catch(() => '');
    return { text, bytes: text.length, truncated: false };
  }
  const reader = res.body.getReader();
  const dec = new TextDecoder('utf-8', { fatal: false });
  let text = '', bytes = 0, truncated = false;
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    bytes += value.byteLength;
    if (text.length < maxBytes) text += dec.decode(value, { stream: true });
    if (bytes >= maxBytes) { truncated = true; try { await reader.cancel(); } catch (_) {} break; }
  }
  text += dec.decode();
  return { text, bytes, truncated };
}

function headersToObject(h) {
  const o = {};
  // An extension with host permission sees the real response headers —
  // this is the bit a plain web page cannot do.
  for (const [k, v] of h.entries()) o[k.toLowerCase()] = v;
  return o;
}

/* ── convenience wrappers ───────────────────────────────────── */
export async function getJSON(url, opts = {}) {
  const r = await request(url, { headers: { Accept: 'application/json' }, ...opts });
  if (!r.ok) throw new Error(`HTTP ${r.status} from ${hostOf(url)}`);
  try { return JSON.parse(r.body); }
  catch { throw new Error(`${hostOf(url)} did not return JSON`); }
}

/* Is a URL alive? Cheap — no body read. */
export async function head(url, opts = {}) {
  try { return await request(url, { method: 'HEAD', wantBody: false, timeout: 6000, ...opts }); }
  catch { return null; }
}

export const hostOf = u => { try { return new URL(u).host; } catch { return u; } };

/* Run jobs with a cap, collecting results; never rejects. */
/* ── which scheme the target actually answers on ──────────────
   Every module used to hard-code https://. On an http-only
   target that means ECONNREFUSED on 443, and the whole scan
   reports "did not respond" -- found by pointing the engine at a
   real WordPress served over http. engine.py tries https and
   then http, so this does too.

   Resolved once per domain per scan and cached, so the fallback
   costs a single extra request and only when https genuinely
   fails. https is still always tried first, so nothing about an
   https target changes. */
const _schemeCache = new Map();

export async function ensureScheme(domain, opts = {}) {
  if (_schemeCache.has(domain)) return _schemeCache.get(domain);
  for (const scheme of ['https', 'http']) {
    try {
      const r = await request(`${scheme}://${domain}/`,
        { signal: opts.signal, timeout: 8000, maxBytes: 2048 });
      if (r && r.status) {
        _schemeCache.set(domain, scheme);
        return scheme;
      }
    } catch { /* try the next scheme */ }
  }
  _schemeCache.set(domain, 'https');   // nothing answered; report against https
  return 'https';
}

export const schemeFor = domain => _schemeCache.get(domain) || 'https';

export function resetSchemeCache() { _schemeCache.clear(); }

export async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let i = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (true) {
      const idx = i++;
      if (idx >= items.length) return;
      try { out[idx] = await fn(items[idx], idx); }
      catch (e) { out[idx] = { __error: String(e && e.message || e) }; }
    }
  });
  await Promise.all(workers);
  return out;
}

/* ── DNS over HTTPS — the same resolver engine.py uses ───────── */
const DOH = [
  'https://cloudflare-dns.com/dns-query',
  'https://dns.google/resolve',
];

export async function dnsQuery(name, type, opts = {}) {
  for (const base of DOH) {
    try {
      const url = `${base}?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
      const j = await getJSON(url, { headers: { Accept: 'application/dns-json' }, timeout: 6000, ...opts });
      // RFC 8484 JSON: Status 0 == NOERROR; Answer carries {name,type,TTL,data}
      if (j && typeof j.Status === 'number') {
        return (j.Answer || []).map(a => ({ ...a, data: stripQuotes(a.data) }));
      }
    } catch (e) {
      if (e && e.name === 'AbortError') throw e;
      // try the next resolver
    }
  }
  return [];
}

const stripQuotes = s => typeof s === 'string' ? s.replace(/^"(.*)"$/s, '$1') : s;

/* TXT records arrive split into quoted chunks; join them. */
export const joinTxt = data => String(data || '').replace(/"\s+"/g, '').replace(/"/g, '');
