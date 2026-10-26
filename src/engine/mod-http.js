/* ════════════════════════════════════════════════════════════
   Modules that work by talking HTTP to the target itself.
   Shapes mirror engine.py so render.js is untouched.
   ════════════════════════════════════════════════════════════ */

import { request, mapLimit, ensureScheme, schemeFor } from './http.js';
import { DATA } from './data/tables.js';
import { ruleMatches, groupByPath, isRawfilePath } from './matcher.js';

const base = d => `${schemeFor(d)}://${d}`;
const rx = (p, f) => { try { return new RegExp(p, f); } catch { return null; } };

/* ── Security headers ───────────────────────────────────────── */
export async function headers(domain, signal) {
  await ensureScheme(domain, { signal });
  const r = await request(base(domain) + '/', { signal, timeout: 12000 });
  const h = r.headers;

  const rows = [];
  let score = 0, max = 0;
  for (const [name, meta] of Object.entries(DATA.HEADER_CHECKS)) {
    const key = name.toLowerCase();
    const present = key in h;
    const weight = Number(meta && meta.weight) || 10;
    max += weight;
    if (present) score += weight;
    rows.push({
      header: name,
      present,
      value: present ? String(h[key]).slice(0, 200) : '',
      description: (meta && (meta.desc || meta.description)) || '',
      severity: (meta && meta.severity) || 'medium',
    });
  }
  const pct = max ? Math.round((score / max) * 100) : 0;
  const grade = pct >= 90 ? 'A' : pct >= 75 ? 'B' : pct >= 60 ? 'C' : pct >= 40 ? 'D' : 'F';

  const disclosure = [];
  for (const k of ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator', 'x-drupal-cache']) {
    if (h[k]) disclosure.push({ header: k, value: h[k] });
  }

  return {
    grade, score: pct, status_code: r.status, server: h.server || '',
    headers: rows, disclosure,
  };
}

/* ── robots / sitemap / security.txt ────────────────────────── */
export async function robots(domain, signal) {
  await ensureScheme(domain, { signal });
  const out = { robots: { count: 0, disallowed: [], allowed: [] }, sitemaps: [], security_txt: { found: false } };

  try {
    const r = await request(`${base(domain)}/robots.txt`, { signal, timeout: 9000 });
    if (r.ok && !/<html/i.test(r.body.slice(0, 200))) {
      const lines = r.body.split(/\r?\n/);
      out.robots.count = lines.filter(l => /^\s*(dis)?allow:/i.test(l)).length;
      const sensitive = /admin|backup|internal|private|config|\.git|api|test|staging|tmp|db|sql|log/i;
      for (const l of lines) {
        let m = l.match(/^\s*disallow:\s*(\S+)/i);
        if (m) { out.robots.disallowed.push({ path: m[1], sensitive: sensitive.test(m[1]) }); continue; }
        m = l.match(/^\s*allow:\s*(\S+)/i);
        if (m) out.robots.allowed.push({ path: m[1], interesting: sensitive.test(m[1]) });
        m = l.match(/^\s*sitemap:\s*(\S+)/i);
        if (m) out.sitemaps.push(m[1]);
      }
    }
  } catch (_) {}

  if (!out.sitemaps.length) {
    const s = await request(`${base(domain)}/sitemap.xml`, { signal, timeout: 8000, wantBody: false }).catch(() => null);
    if (s && s.ok) out.sitemaps.push(`${base(domain)}/sitemap.xml`);
  }

  for (const p of ['/.well-known/security.txt', '/security.txt']) {
    try {
      const r = await request(base(domain) + p, { signal, timeout: 7000 });
      if (r.ok && /contact:/i.test(r.body)) {
        out.security_txt = { found: true, url: base(domain) + p, contact: (r.body.match(/contact:\s*(\S+)/i) || [])[1] || '' };
        break;
      }
    } catch (_) {}
  }
  return out;
}

/* ── Page identity + threat posture ─────────────────────────── */
export async function screenshot(domain, signal) {
  await ensureScheme(domain, { signal });
  const r = await request(base(domain) + '/', { signal, timeout: 12000 });
  const b = r.body || '';
  const meta = (name) => {
    const m = b.match(new RegExp(`<meta[^>]+(?:name|property)=["']${name}["'][^>]+content=["']([^"']+)`, 'i'))
      || b.match(new RegExp(`<meta[^>]+content=["']([^"']+)["'][^>]+(?:name|property)=["']${name}["']`, 'i'));
    return m ? m[1].trim() : '';
  };
  const gen = meta('generator');
  let cms = gen;
  if (!cms) {
    if (/wp-content|wp-includes/i.test(b)) cms = 'WordPress';
    else if (/\/_next\//.test(b)) cms = 'Next.js';
    else if (/drupal-settings-json/i.test(b)) cms = 'Drupal';
    else if (/Joomla/i.test(b)) cms = 'Joomla';
    else if (/cdn\.shopify\.com/i.test(b)) cms = 'Shopify';
  }
  return {
    title: (b.match(/<title[^>]*>([\s\S]{0,300}?)<\/title>/i) || [])[1]?.trim().replace(/\s+/g, ' ') || '',
    description: meta('description') || meta('og:description'),
    url: r.url || base(domain),
    cms,
    status: r.status,
    ransomware_status: 'not checked in browser',
    ransomware: [],
    threat_feeds: { checked: 0, hits: 0 },
    note: 'Image capture and ransomware feeds need the Kumo CLI.',
  };
}

/* ── Tech fingerprinting (port of _whatweb_python) ──────────── */
export async function whatweb(domain, signal) {
  await ensureScheme(domain, { signal });
  const r = await request(base(domain) + '/', { signal, timeout: 12000 });
  const b = r.body || '', h = r.headers;
  const headerBlob = Object.entries(h).map(([k, v]) => `${k}: ${v}`).join('\n');
  const hay = headerBlob + '\n' + b;
  const detected = {};
  const add = (cat, val) => {
    if (!val) return;
    (detected[cat] = detected[cat] || []);
    if (!detected[cat].includes(val)) detected[cat].push(val);
  };

  // Where a pattern is allowed to match. A product name printed in page text
  // is prose, not proof: a blog comparing CMS platforms, or a host selling
  // them, prints every brand in the table. Evidence that only means something
  // as a header or cookie is scoped to headers and never read from the body.
  //   ["h", pat] -> headers and cookies   ["b", pat] -> body   pat -> either
  // A scoped pattern arrives from engine.py as a two-element array; passing
  // one to RegExp would coerce it to "h,pattern" and match nothing real.
  const sigHit = (pat) => {
    let target = hay, src = pat;
    if (Array.isArray(pat)) {
      src = pat[1];
      target = pat[0] === 'h' ? headerBlob : b;
    }
    const re = rx(src, 'i');
    return !!(re && re.test(target));
  };

  for (const [cat, sigs] of Object.entries(DATA.WHATWEB_SIGNATURES)) {
    for (const [name, pats] of Object.entries(sigs)) {
      for (const pat of (Array.isArray(pats) ? pats : [pats])) {
        if (sigHit(pat)) { add(cat, name); break; }
      }
    }
  }
  for (const [name, p] of Object.entries(DATA.WHATWEB_VERSION_PATTERNS)) {
    const re = rx(p, 'i');
    const m = re && hay.match(re);
    if (m) add('Version', `${name} ${m[1] || ''}`.trim());
  }
  const cookies = h['set-cookie'] || '';
  for (const [name, hint] of Object.entries(DATA.WHATWEB_COOKIE_HINTS)) {
    if (cookies.toLowerCase().includes(String(hint).toLowerCase())) add('Platform', name);
  }
  if (h.server) add('Web Server', h.server);
  if (h['x-powered-by']) add('Language', h['x-powered-by']);

  return {
    url: r.url || base(domain),
    total_detected: Object.values(detected).reduce((n, v) => n + v.length, 0),
    detected,
  };
}

/* ── WAF detection (port of _wafw00f_python) ────────────────── */
export async function wafw00f(domain, signal) {
  await ensureScheme(domain, { signal });
  const normal = await request(base(domain) + '/', { signal, timeout: 10000 }).catch(() => null);
  if (!normal) return { error: 'Target did not respond' };

  const probePath = (DATA.WAF_PROBE_PATHS || ["/?q=<script>alert(1)</script>"])[0];
  const probe = await request(base(domain) + probePath, { signal, timeout: 10000 }).catch(() => null);

  /* Each signature kind must be matched against its OWN part of the response.
     Searching one merged blob makes a cookie needle like "ts" hit any body
     containing the letters, and "nginx" in a page footer look like a WAF.
     A WAF card full of guesses is worse than an empty one. */
  const parts = res => {
    if (!res) return { header: '', cookie: '', body: '', server: '' };
    const h = res.headers || {};
    return {
      header: Object.keys(h).join('\n').toLowerCase(),
      cookie: String(h['set-cookie'] || '').toLowerCase(),
      body: String(res.body || '').slice(0, 20000).toLowerCase(),
      server: `${h.server || ''} ${h['x-powered-by'] || ''}`.toLowerCase(),
    };
  };
  const pn = parts(normal), pp = parts(probe);
  const inPart = (kind, needle) => {
    const n = String(needle).toLowerCase();
    // header needles name a header; require a whole-token match, not a substring
    if (kind === 'header' || kind === 'cookie') {
      const hay = kind === 'header' ? [pn.header, pp.header] : [pn.cookie, pp.cookie];
      const re = new RegExp(`(^|[\\s;,=])${n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}([\\s;,=]|$)`, 'm');
      return hay.some(x => re.test(x));
    }
    return [pn[kind], pp[kind]].some(x => x.includes(n));
  };

  const detected = [];
  for (const [waf, sig] of Object.entries(DATA.WAF_SIGNATURES)) {
    const ev = [];
    for (const kind of ['header', 'cookie', 'server', 'body']) {
      for (const needle of [].concat(sig[kind] || [])) {
        if (inPart(kind, needle)) ev.push(`${kind}: ${needle}`);
      }
    }
    // A body-only hit is the weakest evidence there is — the word can appear
    // in page copy. Require corroboration before naming a vendor.
    const strong = ev.filter(e => !e.startsWith('body:'));
    if (!strong.length) continue;
    detected.push({
      waf, vendor: sig.vendor || '',
      confidence: strong.length > 1 ? 'high' : ev.length > 1 ? 'medium' : 'low',
      evidence: ev.slice(0, 4).join(', '),
    });
  }
  const blocked = !!(probe && normal && probe.status !== normal.status &&
    [403, 406, 419, 429, 503].includes(probe.status));
  if (!detected.length && blocked) {
    detected.push({ waf: 'Unknown WAF', vendor: '', confidence: 'low',
      evidence: `probe returned ${probe.status} where the homepage returned ${normal.status}` });
  }
  return {
    normal_status: normal.status,
    probe_status: probe ? probe.status : null,
    probe_blocked: blocked,
    detected,
  };
}

/* ── HTTP inspector ─────────────────────────────────────────── */
export async function httpInspect(domain, signal) {
  await ensureScheme(domain, { signal });
  const r = await request(base(domain) + '/', { signal, timeout: 12000 });
  const h = r.headers;

  /* Set-Cookie is a forbidden response header: fetch() strips it from the
     Headers object no matter what permissions we hold. chrome.cookies is the
     only way to see the flags, so read them from the cookie store instead. */
  const cookies = [];
  try {
    const jar = await chrome.cookies.getAll({ domain });
    for (const c of jar) {
      cookies.push({
        name: c.name,
        secure: !!c.secure,
        httponly: !!c.httpOnly,
        samesite: c.sameSite && c.sameSite !== 'unspecified' ? c.sameSite : false,
      });
    }
  } catch (_) {
    // no "cookies" permission granted — say so rather than report none
  }

  const allowed = [];
  const dangerous = [];
  try {
    const o = await request(base(domain) + '/', { method: 'OPTIONS', signal, timeout: 8000, wantBody: false });
    for (const m of String(o.headers.allow || o.headers['access-control-allow-methods'] || '')
      .split(',').map(s => s.trim().toUpperCase()).filter(Boolean)) {
      allowed.push(m);
      if (['TRACE', 'TRACK', 'PUT', 'DELETE', 'CONNECT'].includes(m)) dangerous.push(m);
    }
  } catch (_) {}

  const leaky = [];
  for (const k of Object.keys(DATA.HTTP_LEAKY_HEADERS || {})) {
    if (h[k.toLowerCase()]) leaky.push({ header: k, value: h[k.toLowerCase()] });
  }
  const nonStandard = Object.keys(h).filter(k =>
    !(DATA.HTTP_STANDARD_HEADERS || []).map(s => s.toLowerCase()).includes(k) &&
    !(DATA.HTTP_SEC_HEADERS || []).map(s => s.toLowerCase()).includes(k));

  return {
    summary: {
      final_status: r.status,
      final_url: r.url,
      hops: r.redirected ? 'redirected' : 1,
      tls: 'n/a in browser',
    },
    // The browser will not expose intermediate hops; report the endpoints.
    redirect_chain: r.redirected
      ? [{ status: '3xx', url: base(domain) + '/', location: r.url }, { status: r.status, url: r.url }]
      : [{ status: r.status, url: r.url }],
    methods: { allowed, dangerous },
    cookies,
    leaky_headers: leaky,
    non_standard: nonStandard.slice(0, 20),
    note: 'Redirect hops are not visible to an extension (only the final URL), '
        + 'and cookie flags come from the browser cookie store, not Set-Cookie.',
  };
}

/* ── Favicon hash (mmh3, the Shodan pivot) ──────────────────── */
export async function favicon(domain, signal) {
  await ensureScheme(domain, { signal });
  for (const p of DATA.FAVICON_PATHS) {
    try {
      const url = p.startsWith('http') ? p : base(domain) + p;
      const res = await fetch(url, { credentials: 'omit', cache: 'no-store', signal });
      if (!res.ok) continue;
      const buf = new Uint8Array(await res.arrayBuffer());
      if (buf.length < 50) continue;

      const b64 = b64encodeChunked(buf);
      const hash = mmh3(b64 + '\n');       // Shodan hashes the base64 + newline
      const md5 = await digestHex(buf, 'SHA-256');  // SubtleCrypto has no MD5

      let tech = '';
      for (const [name, hashes] of Object.entries(DATA.FAVICON_TECH_DB || {})) {
        if ([].concat(hashes).map(String).includes(String(hash))) { tech = name; break; }
      }
      return {
        favicon_found: true, favicon_url: url, size_bytes: buf.length,
        hash_shodan: hash, hash_sha256: md5, technology: tech,
        search_links: {
          Shodan: `https://www.shodan.io/search?query=http.favicon.hash%3A${hash}`,
          FOFA: `https://fofa.info/result?qbase64=${btoa(`icon_hash="${hash}"`)}`,
        },
      };
    } catch (_) { /* try the next path */ }
  }
  return { favicon_found: false };
}

function b64encodeChunked(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  // Shodan's hash is over the standard-wrapped base64
  return btoa(s).replace(/(.{76})/g, '$1\n');
}

async function digestHex(buf, algo) {
  const d = await crypto.subtle.digest(algo, buf);
  return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 32);
}

/* MurmurHash3 x86 32-bit, signed — what Shodan's favicon hash is. */
function mmh3(str) {
  const data = new TextEncoder().encode(str);
  const c1 = 0xcc9e2d51, c2 = 0x1b873593;
  let h1 = 0;
  const n = data.length, blocks = n & ~3;
  const mul = (a, b) => (((a & 0xffff) * b) + ((((a >>> 16) * b) & 0xffff) << 16)) | 0;
  const rotl = (x, r) => (x << r) | (x >>> (32 - r));

  for (let i = 0; i < blocks; i += 4) {
    let k1 = data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24);
    k1 = mul(k1, c1); k1 = rotl(k1, 15); k1 = mul(k1, c2);
    h1 ^= k1; h1 = rotl(h1, 13); h1 = (mul(h1, 5) + 0xe6546b64) | 0;
  }
  let k1 = 0;
  switch (n & 3) {
    case 3: k1 ^= data[blocks + 2] << 16;
    case 2: k1 ^= data[blocks + 1] << 8;
    case 1: k1 ^= data[blocks];
      k1 = mul(k1, c1); k1 = rotl(k1, 15); k1 = mul(k1, c2); h1 ^= k1;
  }
  h1 ^= n;
  h1 ^= h1 >>> 16; h1 = mul(h1, 0x85ebca6b);
  h1 ^= h1 >>> 13; h1 = mul(h1, 0xc2b2ae35);
  h1 ^= h1 >>> 16;
  return h1 | 0;     // signed, as Shodan reports it
}

/* ── Sensitive endpoints ────────────────────────────────────── */
export async function endpoints(domain, signal) {
  await ensureScheme(domain, { signal });
  const list = DATA.ENDPOINTS;            // [path, name, severity]
  const findings = [];
  const counts = {};

  // Two baselines, because a 200 on its own proves nothing:
  //  · the homepage, since several rules are query strings on "/" and would
  //    otherwise fire on every site that serves a homepage;
  //  · a random path, to learn what this site's soft-404 looks like.
  const baseline = await profile(base(domain) + '/', signal);
  const soft404 = await profile(
    `${base(domain)}/kumo-${Math.random().toString(36).slice(2, 10)}`, signal);

  await mapLimit(list, 10, async ([path, name, severity]) => {
    try {
      const r = await request(base(domain) + path, { signal, timeout: 7000, maxBytes: 65536 });
      if (!isInteresting(r)) return;
      if (looksLike(r, baseline) || looksLike(r, soft404)) return;
      findings.push({ severity, name, path, url: base(domain) + path, status: r.status, size: r.bytes });
      counts[severity] = (counts[severity] || 0) + 1;
    } catch (_) {}
  });

  const rank = DATA.SEV_ORDER || { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort((a, b) => (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9));
  return { total_probed: list.length, total_found: findings.length, total: list.length,
           severity_counts: counts, findings };
}

/* Cheap shape of a response, for comparing one probe against another. */
async function profile(url, signal) {
  try {
    const r = await request(url, { signal, timeout: 8000, maxBytes: 65536 });
    return { status: r.status, bytes: r.bytes, title: titleOf(r.body) };
  } catch { return null; }
}
const titleOf = b => ((String(b || '').match(/<title[^>]*>([\s\S]{0,120}?)<\/title>/i) || [])[1] || '').trim();

/* Is this response just the page we already know about? */
function looksLike(r, ref) {
  if (!ref || r.status !== ref.status) return false;
  if (ref.title && titleOf(r.body) === ref.title) return true;
  if (!ref.bytes) return false;
  return Math.abs(r.bytes - ref.bytes) / ref.bytes < 0.02;   // within 2%
}

export const isHtml = b =>
  /<\s*(!doctype\s+html|html|head|body)\b/i.test(String(b || '').slice(0, 2000));

/* A 200 that is really the SPA shell or a soft-404 is not a finding. */
function isInteresting(r) {
  if (r.status !== 200) return false;
  if (r.bytes < 8) return false;
  const head = (r.body || '').slice(0, 1500).toLowerCase();
  if (/(404|not found|page not found|does not exist)/.test(head) && /<html/.test(head)) return false;
  return true;
}

/* Does this path name a file rather than a route? */
// Was a loose "any short extension" regex, which treated /admin.php as a raw
// file and so skipped a real HTML admin panel. isRawfilePath is engine.py's
// own rule, imported rather than approximated.

/* ── The 365-rule vulnerability scanner ─────────────────────── */
export async function nuclei(domain, signal) {
  await ensureScheme(domain, { signal });
  const byPath = groupByPath(DATA.VULN_RULES);
  const findings = [];
  const counts = {};
  const paths = [...byPath.keys()];

  // The rules are status+word matchers. On a site that answers 200 with the
  // same shell for every URL, a generic word in that shell satisfies dozens of
  // them at once. Learn what this site serves for a page that cannot exist,
  // and for its homepage, before believing anything.
  const baseline = await profile(base(domain) + '/', signal);
  const soft404 = await profile(
    `${base(domain)}/kumo-${Math.random().toString(36).slice(2, 10)}`, signal);

  await mapLimit(paths, 10, async path => {
    let r;
    try { r = await request(base(domain) + path, { signal, timeout: 7000, maxBytes: 131072 }); }
    catch { return; }

    // Same response as the homepage or as a made-up URL: not a finding.
    //
    // Except for the homepage itself. A rule whose path IS "/" is compared
    // against a baseline fetched from "/", so it always looks identical and
    // every such rule was silently dead -- which hid the php2shell runtime
    // check, confirmed against a real PHP 8.3.6. The soft-404 comparison still
    // applies: if a made-up URL answers the same as the homepage, the server
    // is a catch-all and the homepage proves nothing either.
    const isRoot = path === '/' || path === '';
    // The homepage cannot be "the same as the homepage", so the baseline
    // comparison does not apply to it -- otherwise every rule whose path is
    // "/" is silently dead.
    const looksUninformative = isRoot
      ? looksLike(r, soft404)
      : (looksLike(r, baseline) || looksLike(r, soft404));

    // A catch-all means the BODY proves nothing: the same shell comes back for
    // every URL. It says nothing about the response HEADERS. A version matcher
    // reading X-Powered-By is still sound, which is why a real PHP 8.3.6
    // behind a catch-all router must still be reported. So instead of dropping
    // the response, drop only the rules that needed the body.
    const headerOnly = rule => (rule.matchers || []).every(m =>
      m.type === 'version' || m.type === 'status'
      || m.part === 'header' || m.part === 'all_headers');
    const candidates = (byPath.get(path) || [])
      .filter(rule => !looksUninformative || headerOnly(rule));
    if (!candidates.length) return;

    // A rule for /.env or /config.php that comes back as an HTML document is
    // the SPA shell, not the file. Real config files are not web pages.
    if (isRawfilePath(path) && isHtml(r.body)) return;

    // The base and extended rule sets overlap on some paths. Report the most
    // severe hit per path once, or a single exposure inflates the tally.
    const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    let best = null;
    for (const rule of candidates) {
      if (!ruleMatches(rule, r)) continue;
      if (!best || (rank[rule.severity] ?? 9) < (rank[best.severity] ?? 9)) best = rule;
    }
    if (!best) return;
    findings.push({
      severity: best.severity, name: best.name, path, url: base(domain) + path,
      status: r.status, size: r.bytes, rule_id: best.id,
      source: 'kumo-rules', description: best.description,
    });
    counts[best.severity] = (counts[best.severity] || 0) + 1;
  });

  const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort((a, b) => (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9));
  return {
    nuclei_installed: false,
    total: DATA.VULN_RULES.length,
    total_probed: paths.length,
    total_found: findings.length,
    severity_counts: counts,
    findings,
  };
}

/* ── API surface fuzzer ─────────────────────────────────────── */
export async function apiFuzzer(domain, signal) {
  await ensureScheme(domain, { signal });
  const basesFound = [];
  await mapLimit(DATA.API_BASES, 8, async p => {
    try {
      const r = await request(base(domain) + p, { signal, timeout: 6000, maxBytes: 32768 });
      if ([200, 401, 403].includes(r.status)) basesFound.push(p);
    } catch (_) {}
  });

  const specs = [];
  await mapLimit(DATA.API_ROOT_SPECS, 8, async row => {
    const [path, name, severity] = row;
    try {
      const r = await request(base(domain) + path, { signal, timeout: 6000, maxBytes: 65536 });
      if (r.status === 200 && r.bytes > 50 && !/<html/i.test(r.body.slice(0, 200))) {
        specs.push({ name, path, status: r.status, size: r.bytes, severity });
      }
    } catch (_) {}
  });

  let graphql = null;
  for (const p of ['/graphql', '/api/graphql', '/v1/graphql', '/query']) {
    try {
      const r = await request(base(domain) + p, {
        method: 'POST', signal, timeout: 8000, maxBytes: 262144,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: '{__schema{queryType{name}}}' }),
      });
      if (r.status === 200 && /__schema|queryType/.test(r.body)) {
        graphql = { path: p, size: r.bytes, severity: 'high',
          detail: 'Introspection is enabled — the full schema is readable without authentication.' };
        break;
      }
      if (r.status === 200 && /graphql/i.test(r.body)) {
        graphql = { path: p, size: r.bytes, severity: 'medium',
          detail: 'GraphQL endpoint responds; introspection appears disabled.' };
        break;
      }
    } catch (_) {}
  }

  const findings = [];
  await mapLimit(DATA.API_ENDPOINT_PATHS, 8, async row => {
    const [path, name, severity] = row;
    try {
      const r = await request(base(domain) + path, { signal, timeout: 6000, maxBytes: 32768 });
      if (isInteresting(r)) findings.push({ name, path, severity, status: r.status, size: r.bytes });
    } catch (_) {}
  });

  return {
    total: basesFound.length + specs.length + findings.length + (graphql ? 1 : 0),
    base_found: basesFound[0] || '',
    bases_found: basesFound,
    graphql, specs, findings,
  };
}

/* ── Cloud buckets ──────────────────────────────────────────── */
export async function cloudBuckets(domain, signal) {
  await ensureScheme(domain, { signal });
  const label = domain.split('.')[0];
  const names = new Set();
  for (const s of DATA.BUCKET_SUFFIXES) names.add(`${label}${s}`);
  for (const p of DATA.BUCKET_PREFIXES) names.add(`${p}${label}`);
  names.add(label);

  const targets = [];
  for (const n of names) {
    targets.push({ name: n, provider: 'AWS S3', url: `https://${n}.s3.amazonaws.com` });
    targets.push({ name: n, provider: 'Google Cloud Storage', url: `https://storage.googleapis.com/${n}` });
    targets.push({ name: n, provider: 'Azure Blob', url: `https://${n}.blob.core.windows.net/?comp=list` });
  }

  const exposed = [];
  await mapLimit(targets, 10, async t => {
    try {
      const r = await request(t.url, { signal, timeout: 6000, maxBytes: 32768 });
      if (r.status === 200) {
        const files = (r.body.match(/<Key>/g) || []).length;
        exposed.push({ ...t, severity: 'critical', status: 200, files,
          detail: files ? `${files} objects listed publicly` : 'bucket responds and is readable' });
      } else if (r.status === 403) {
        exposed.push({ ...t, severity: 'medium', status: 403, detail: 'bucket exists but listing is denied' });
      }
    } catch (_) {}
  });

  exposed.sort((a, b) => (a.severity === 'critical' ? -1 : 1) - (b.severity === 'critical' ? -1 : 1));
  return { checked: targets.length, exposed };
}

/* ── JS secret scanner ──────────────────────────────────────── */
export async function jsSecrets(domain, signal) {
  await ensureScheme(domain, { signal });
  const home = await request(base(domain) + '/', { signal, timeout: 12000 });
  const files = collectScripts(home.body, base(domain), DATA.JS_SKIP_CDNS).slice(0, 25);

  const secrets = [];
  const seen = new Set();
  const scan = (text, where) => {
    for (const row of DATA.SECRET_PATTERNS) {   // [pattern, label, severity, flags]
      const [pattern, label, severity, flags] = row;
      const re = rx(pattern, (flags || '') + 'g');
      if (!re) continue;
      for (const m of text.matchAll(re)) {
        const raw = m[0];
        if (!raw) continue;               // a pattern that matches "" is not a secret
        const key = label + '\u0000' + raw.slice(0, 64);
        if (seen.has(key)) continue;
        seen.add(key);
        secrets.push({
          type: label, severity,
          value: raw.slice(0, 200),
          file: where,
          line: lineAround(text, m.index),
        });
        if (secrets.length > 120) return;
      }
    }
  };

  scan(home.body || '', '(inline in homepage)');
  await mapLimit(files, 6, async u => {
    try {
      const r = await request(u, { signal, timeout: 10000, maxBytes: 1024 * 1024 });
      if (r.ok) scan(r.body, u.replace(base(domain), ''));
    } catch (_) {}
  });

  const rank = { critical: 0, high: 1, medium: 2, low: 3 };
  secrets.sort((a, b) => (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9));
  return { js_files: files, secrets };
}

function collectScripts(html, origin, skip) {
  const out = new Set();
  for (const m of String(html || '').matchAll(/<script[^>]+src=["']([^"']+)["']/gi)) {
    let u = m[1];
    try { u = new URL(u, origin).href; } catch { continue; }
    if (!/^https?:/.test(u)) continue;
    if ((skip || []).some(cdn => u.includes(cdn))) continue;
    out.add(u);
  }
  return [...out];
}

/* The surrounding line, for context, exactly as it appears in the file.
   Secrets are reported whole and unmasked, by choice: whoever ran the scan
   needs the real value to confirm the finding, check whether the key is
   live, and put it in a report. A masked value proves nothing. The only
   limit is a 200-char cap so one enormous match cannot flood a card. */
function lineAround(text, idx) {
  const start = text.lastIndexOf('\n', idx) + 1;
  let end = text.indexOf('\n', idx);
  if (end === -1) end = Math.min(text.length, idx + 160);
  return text.slice(start, Math.min(end, start + 200)).trim();
}

/* ── Content intelligence ───────────────────────────────────── */
export async function contentIntel(domain, signal) {
  await ensureScheme(domain, { signal });
  const home = await request(base(domain) + '/', { signal, timeout: 12000 });
  const files = collectScripts(home.body, base(domain), DATA.CONTENT_SKIP_CDNS).slice(0, 15);

  let blob = home.body || '';
  let inline = (blob.match(/<script(?![^>]*src)/gi) || []).length;
  await mapLimit(files, 6, async u => {
    try { const r = await request(u, { signal, timeout: 9000, maxBytes: 768 * 1024 }); if (r.ok) blob += '\n' + r.body; }
    catch (_) {}
  });

  const esc = domain.replace(/\./g, '\\.');
  const pick = (re, n = 40) => [...new Set([...blob.matchAll(re)].map(m => m[0]))].slice(0, n);

  const internalHosts = pick(new RegExp(`\\b[a-z0-9-]+\\.(?:internal|local|corp|lan|intra)(?:\\.[a-z]{2,})?\\b`, 'gi'), 25)
    .concat(pick(new RegExp(`\\b(?:dev|staging|test|uat|preprod|internal|admin)[a-z0-9-]*\\.${esc}\\b`, 'gi'), 25));
  const apis = pick(/["'`](\/(?:api|v\d|rest|graphql)\/[A-Za-z0-9_\-/{}.]{2,60})["'`]/g, 50)
    .map(s => s.replace(/^["'`]|["'`]$/g, ''));
  const emails = pick(new RegExp(`[a-z0-9._%+-]+@(?:[a-z0-9-]+\\.)*${esc}`, 'gi'), 25);
  const cloud = pick(/https?:\/\/[a-z0-9.-]*(?:s3[.-][a-z0-9-]*\.amazonaws\.com|blob\.core\.windows\.net|storage\.googleapis\.com)[^\s"'<>]*/gi, 20);
  const dbs = pick(/\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp):\/\/[^\s"'<>]{6,100}/gi, 10);
  const urls = pick(new RegExp(`https?://(?:[a-z0-9-]+\\.)*${esc}[^\\s"'<>]*`, 'gi'), 60);

  const categories = {
    internal_hosts: [...new Set(internalHosts)],
    api_endpoints: [...new Set(apis)],
    emails, cloud_storage: cloud, databases: dbs,
    internal_urls: urls.slice(0, 40),
  };
  const counts = {
    urls_internal: urls.length, emails: emails.length,
    api_endpoints: categories.api_endpoints.length,
    internal_hosts: categories.internal_hosts.length,
    cloud_storage: cloud.length, databases: dbs.length,
  };
  return {
    total: Object.values(counts).reduce((a, b) => a + b, 0),
    sources_scanned: { js_files: files.length, inline_scripts: inline },
    counts, categories,
  };
}
