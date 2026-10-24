/* ════════════════════════════════════════════════════════════
   DNS, registration and third-party-intel modules.
   Output shapes match engine.py exactly so the renderers in
   render.js need no changes.
   ════════════════════════════════════════════════════════════ */

import { request, getJSON, dnsQuery, joinTxt, mapLimit, hostOf } from './http.js';
import { DATA } from './data/tables.js';

/* ── DNS + email security ───────────────────────────────────── */
export async function dns(domain, signal) {
  const q = (t, name = domain) => dnsQuery(name, t, { signal }).catch(() => []);
  const [a, aaaa, mx, ns, txt, caa, soa, dmarc, dkim] = await Promise.all([
    q('A'), q('AAAA'), q('MX'), q('NS'), q('TXT'), q('CAA'), q('SOA'),
    q('TXT', `_dmarc.${domain}`),
    q('TXT', `default._domainkey.${domain}`),
  ]);

  const v4 = a.map(r => r.data);
  const v6 = aaaa.map(r => r.data);
  const txts = txt.map(r => joinTxt(r.data));

  const spfRec = txts.find(t => /^v=spf1/i.test(t.trim()));
  const dmarcRec = dmarc.map(r => joinTxt(r.data)).find(t => /^v=DMARC1/i.test(t.trim()));
  const dkimRec = dkim.map(r => joinTxt(r.data)).find(t => /v=DKIM1|p=/i.test(t));

  return {
    ips: { v4, v6 },
    records: {
      A: v4,
      AAAA: v6,
      // MX data is "10 mail.example.com" — keep it readable
      MX: mx.map(r => r.data).sort(),
      NS: ns.map(r => r.data.replace(/\.$/, '')),
      TXT: txts,
      CAA: caa.map(r => r.data),
      SOA: soa.map(r => r.data),
    },
    email_security: {
      spf: spfRec ? { found: true, record: spfRec, policy: spfPolicy(spfRec) } : { found: false },
      dmarc: dmarcRec ? { found: true, record: dmarcRec, policy: dmarcPolicy(dmarcRec) } : { found: false },
      dkim: dkimRec ? { found: true, record: String(dkimRec).slice(0, 80) } : { found: false },
    },
  };
}

const spfPolicy = r => (r.match(/([~\-+?])all\b/) || [])[1] === '-' ? 'strict (-all)'
  : /~all/.test(r) ? 'softfail (~all)' : /\+all/.test(r) ? 'permissive (+all)' : 'no all mechanism';
const dmarcPolicy = r => ((r.match(/\bp=(\w+)/i) || [])[1] || 'none').toLowerCase();

/* ── IP geolocation & ASN ───────────────────────────────────── */
export async function geo(domain, signal) {
  const a = await dnsQuery(domain, 'A', { signal });
  const ip = (a[0] || {}).data;
  if (!ip) return { error: 'No A record to locate' };

  // ipwho.is needs no key and answers with a flat JSON object.
  const j = await getJSON(`https://ipwho.is/${ip}`, { signal, timeout: 8000 });
  if (j && j.success === false) return { ip, error: j.message || 'lookup failed' };

  const conn = j.connection || {};
  return {
    ip,
    city: j.city, region: j.region, country: j.country,
    country_code: j.country_code,
    flag: (j.flag && j.flag.emoji) || '',
    lat: j.latitude, lon: j.longitude,
    timezone: (j.timezone && j.timezone.id) || '',
    isp: conn.isp || conn.org || '',
    asn: conn.asn ? `AS${conn.asn} ${conn.org || ''}`.trim() : '',
    is_hosting: !!(j.security && j.security.hosting),
  };
}

/* ── WHOIS via RDAP ─────────────────────────────────────────────
   rdap.org is a redirector, and it answers 404 for every TLD whose
   registry runs no RDAP server at all. Many ccTLDs are in that group,
   so asking it blindly produced a red "HTTP 404" card for domains that
   are perfectly fine. Resolve the TLD through the IANA bootstrap
   registry first, and when a registry genuinely has no RDAP service,
   say that plainly instead of reporting an error. */
let bootstrapCache = null;

async function rdapBasesFor(tld, signal) {
  if (!bootstrapCache) {
    try {
      const j = await getJSON('https://data.iana.org/rdap/dns.json',
        { signal, timeout: 10000, maxBytes: 1024 * 1024 });
      const map = new Map();
      for (const [labels, urls] of (j.services || [])) {
        for (const l of labels) map.set(String(l).toLowerCase(), urls);
      }
      bootstrapCache = map;
    } catch (_) {
      bootstrapCache = new Map();          // fall through to rdap.org
    }
  }
  const urls = bootstrapCache.get(tld) || [];
  // RFC 9224: prefer HTTPS, and every base URL ends with a slash.
  return urls.filter(u => /^https:/i.test(u)).concat(urls.filter(u => !/^https:/i.test(u)));
}

export async function whois(domain, signal) {
  const tld = domain.split('.').pop().toLowerCase();
  const bases = await rdapBasesFor(tld, signal);

  let j = null, lastErr = '';
  for (const base of [...bases, 'https://rdap.org/']) {
    try {
      j = await getJSON(`${base.replace(/\/+$/, '')}/domain/${encodeURIComponent(domain)}`,
        { signal, timeout: 10000 });
      if (j && (j.ldhName || j.events || j.nameservers)) break;
      j = null;
    } catch (e) {
      lastErr = String((e && e.message) || e);
      if (e && e.name === 'AbortError') throw e;
    }
  }

  if (!j) {
    // Not an error the user can act on: the registry simply has no RDAP.
    return {
      domain,
      rdap_available: false,
      note: bases.length
        ? `The RDAP server for .${tld} did not return a record for this domain. (${lastErr})`
        : `.${tld} has no RDAP service in the IANA registry, so registration data `
          + 'is only available over classic WHOIS, which a browser cannot speak.',
      links: {
        'ICANN Lookup': `https://lookup.icann.org/lookup/en/whois/results?q=${encodeURIComponent(domain)}`,
        'IANA TLD info': `https://www.iana.org/domains/root/db/${encodeURIComponent(tld)}.html`,
        'who.is': `https://who.is/whois/${encodeURIComponent(domain)}`,
      },
    };
  }

  const ev = {};
  for (const e of (j.events || [])) ev[e.eventAction] = e.eventDate;
  const exp = ev.expiration || ev['expiration date'];
  const days = exp ? Math.round((Date.parse(exp) - Date.now()) / 86400000) : null;

  return {
    domain: j.ldhName || domain,
    registration: fmtDate(ev.registration),
    expiration: fmtDate(exp),
    days_until_expiry: days,
    last_changed: fmtDate(ev['last changed'] || ev.lastChanged),
    status: j.status || [],
    nameservers: (j.nameservers || []).map(n => String(n.ldhName || '').toLowerCase()),
    entities: (j.entities || []).map(e => ({
      role: (e.roles || []).join(', '),
      name: vcardName(e.vcardArray) || e.handle || '',
    })).filter(e => e.name),
  };
}

const fmtDate = d => d ? String(d).slice(0, 10) : '';
function vcardName(v) {
  try {
    for (const f of v[1]) if (f[0] === 'fn') return f[3];
  } catch (_) {}
  return '';
}


/* ── Certificate Transparency, via crt.sh ───────────────────────
   crt.sh is the only free CT source worth querying, and it is often slow or
   rate limited. One retry, and a message that names the cause, because a
   silent empty result reads as "this domain has no certificates". */
async function ctLogs(query, signal, { timeout = 25000, maxBytes = 6 * 1024 * 1024 } = {}) {
  let last = '';
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const rows = await getJSON(
        `https://crt.sh/?q=${encodeURIComponent(query)}&output=json`,
        { signal, timeout, maxBytes });
      if (Array.isArray(rows)) return rows;
      last = 'crt.sh returned something that was not a certificate list';
    } catch (e) {
      if (e && e.name === 'AbortError') throw e;
      last = String((e && e.message) || e);
    }
  }
  const err = new Error(`Certificate Transparency lookup failed: ${last}`);
  err.ctFailed = true;
  throw err;
}

/* ── Certificates via crt.sh (CT logs) ──────────────────────────
   A browser cannot read the negotiated cipher, but Certificate
   Transparency gives issuer, validity and SANs — most of the card. */
export async function ssl(domain, signal) {
  const rows = await ctLogs(domain, signal, { timeout: 20000, maxBytes: 3 * 1024 * 1024 });

  if (!rows.length) {
    return { error: 'No current certificate found in CT logs for this name' };
  }
  // newest first
  rows.sort((a, b) => Date.parse(b.not_before || 0) - Date.parse(a.not_before || 0));
  const c = rows[0];
  const days = Math.round((Date.parse(c.not_after) - Date.now()) / 86400000);

  const sans = new Set();
  for (const n of String(c.name_value || '').split(/\n/)) if (n.trim()) sans.add(n.trim());

  return {
    common_name: c.common_name || domain,
    issuer: cleanIssuer(c.issuer_name),
    valid_from: fmtDate(c.not_before),
    valid_until: fmtDate(c.not_after),
    days_left: days,
    serial: c.serial_number,
    protocol: 'n/a in browser',
    cipher: 'n/a in browser',
    sans: [...sans].slice(0, 60),
    total_certs: rows.length,
    source: 'Certificate Transparency (crt.sh)',
    note: 'Live TLS protocol and cipher need a socket — run the Kumo CLI for those.',
  };
}
const cleanIssuer = s => ((String(s || '').match(/O=([^,]+)/) || [])[1] || s || '').trim();

/* ── Subdomains from CT logs ────────────────────────────────── */
export async function subdomains(domain, signal) {
  const rows = await ctLogs('%.' + domain, signal);

  const names = new Set();
  for (const r of rows) {
    for (const n of String(r.name_value || '').split(/\n/)) {
      const h = n.trim().toLowerCase().replace(/^\*\./, '');
      if (h.endsWith(domain) && /^[a-z0-9.-]+$/.test(h)) names.add(h);
    }
  }
  names.delete(domain);
  const all = [...names].sort();

  const isSensitive = h => DATA.SENSITIVE_PREFIXES.some(p => h.split('.')[0].includes(p));
  const ctSensitive = all.filter(isSensitive);

  // Resolve a bounded sample — DoH is quick but not free.
  const sample = [...ctSensitive, ...all.filter(h => !isSensitive(h))].slice(0, 60);
  const resolved = [];
  await mapLimit(sample, 8, async h => {
    const a = await dnsQuery(h, 'A', { signal }).catch(() => []);
    if (a.length) resolved.push({ subdomain: h, ip: a[0].data });
  });
  resolved.sort((a, b) => a.subdomain.localeCompare(b.subdomain));

  return {
    total: all.length,
    ct_total: all.length,
    alive_count: resolved.length,
    sources_failed: [],
    sensitive: resolved.filter(r => isSensitive(r.subdomain)),
    ct_sensitive: ctSensitive.filter(h => !resolved.some(r => r.subdomain === h)).slice(0, 25),
    resolved,
    note: all.length > sample.length
      ? `${all.length} names in CT; resolved the first ${sample.length}.` : undefined,
  };
}

/* ── Subdomain brute force over DoH ─────────────────────────── */
export async function brute(domain, signal) {
  const words = DATA.BRUTE_WORDLIST;
  const resolved = [];
  await mapLimit(words, 12, async w => {
    const h = `${w}.${domain}`;
    const a = await dnsQuery(h, 'A', { signal }).catch(() => []);
    if (a.length) resolved.push({ subdomain: h, ip: a[0].data });
  });
  resolved.sort((a, b) => a.subdomain.localeCompare(b.subdomain));
  const isSensitive = h => DATA.SENSITIVE_PREFIXES.some(p => h.split('.')[0].includes(p));
  return {
    total: resolved.length,
    alive_count: resolved.length,
    tried: words.length,
    sensitive: resolved.filter(r => isSensitive(r.subdomain)),
    resolved,
  };
}

/* ── Shodan InternetDB (no key) ─────────────────────────────── */
export async function shodan(domain, signal) {
  const a = await dnsQuery(domain, 'A', { signal });
  const ips = a.map(r => r.data).slice(0, 4);
  if (!ips.length) return { error: 'No A record to look up' };

  const out = {};
  let ports = 0, cves = 0;
  await mapLimit(ips, 3, async ip => {
    try {
      const j = await getJSON(`https://internetdb.shodan.io/${ip}`, { signal, timeout: 9000 });
      // InternetDB returns vulns as plain CVE id strings.
      const vulns = (j.vulns || []).map(v => (typeof v === 'string' ? { id: v } : v));
      out[ip] = { ports: j.ports || [], tags: j.tags || [], hostnames: j.hostnames || [], cves: vulns };
      ports += (j.ports || []).length;
      cves += vulns.length;
    } catch (e) {
      out[ip] = { ports: [], cves: [], error: String(e.message || e) };
    }
  });

  return {
    api_key_used: false,
    summary: { total_ports: ports, total_cves: cves, critical_cves: [] },
    ips: out,
    note: 'InternetDB has no CVSS scores; severity is unrated here.',
  };
}

/* ── Ports, observed rather than scanned ─────────────────────
   A browser cannot open a TCP socket, so this is not a port scan:
   it is Shodan's record of what its own crawlers last saw open on
   the resolved IPs, enriched with the CLI's service/risk table.

   That difference matters and the card says so. Shodan's view can
   be stale, is bounded by where its crawlers reach, and a port
   absent here is "not seen by Shodan", never "closed". For a live
   answer, run the CLI, which does connect. */
export async function ports(domain, signal) {
  const a = await dnsQuery(domain, 'A', { signal });
  const ips = a.map(r => r.data).slice(0, 4);
  if (!ips.length) return { error: 'No A record to look up' };

  const open = [];
  const seen = new Set();
  const perIp = {};
  let reached = 0;

  await mapLimit(ips, 3, async ip => {
    try {
      const j = await getJSON(`https://internetdb.shodan.io/${ip}`, { signal, timeout: 9000 });
      reached++;
      const list = (j.ports || []).slice().sort((x, y) => x - y);
      perIp[ip] = list;
      // CPEs name the software behind a port; keep them as version hints.
      const cpes = (j.cpes || []).map(c => String(c).replace(/^cpe:2\.3:[ao]:/, '').replace(/:[-*:]+$/, ''));
      for (const p of list) {
        if (seen.has(p)) continue;
        seen.add(p);
        const known = (DATA.KNOWN_PORTS || {})[p] || (DATA.KNOWN_PORTS || {})[String(p)];
        open.push({
          port: p,
          service: known ? known[0] : 'unknown',
          risk: known ? known[1] : 'info',
          version: cpes.length ? cpes.slice(0, 2).join(', ') : '',
          banner: `seen on ${ip}${(j.tags || []).length ? ` · ${j.tags.join(', ')}` : ''}`,
        });
      }
    } catch (_) {
      perIp[ip] = null;     // Shodan has no record, or did not answer
    }
  });

  if (!reached) {
    return { error: 'Shodan InternetDB returned nothing for these IPs — no record, or the service is unreachable.' };
  }

  const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  open.sort((x, y) => (rank[x.risk] ?? 9) - (rank[y.risk] ?? 9) || x.port - y.port);

  return {
    open,
    ips: perIp,
    total_scanned: 0,                 // nothing was probed from here
    source: 'Shodan InternetDB (passive)',
    passive: true,
    note: 'Observed by Shodan, not probed from your browser. A port missing '
        + 'here means Shodan has not seen it — not that it is closed. '
        + 'Run the Kumo CLI for a live scan.',
  };
}

/* ── Censys — needs a key, so give the pivot links ──────────── */
export async function censys(domain, signal) {
  const a = await dnsQuery(domain, 'A', { signal });
  const ips = a.map(r => r.data);
  let certs = [];
  let ctError = '';
  try {
    const rows = await ctLogs(domain, signal, { timeout: 15000, maxBytes: 2 * 1024 * 1024 });
    certs = rows.slice(0, 6).map(c => ({
      subject: c.common_name,
      issuer: cleanIssuer(c.issuer_name),
      validity: `${fmtDate(c.not_before)} → ${fmtDate(c.not_after)}`,
    }));
  } catch (e) {
    if (e && e.name === 'AbortError') throw e;
    ctError = String((e && e.message) || e);
  }
  return {
    api_used: false,
    ips,
    certificates: certs,
    ct_error: ctError || undefined,
    links: {
      Censys: ips[0] ? `https://search.censys.io/hosts/${ips[0]}` : `https://search.censys.io/search?q=${domain}`,
      'crt.sh': `https://crt.sh/?q=${encodeURIComponent(domain)}`,
    },
  };
}

/* ── Wayback Machine ────────────────────────────────────────── */
export async function wayback(domain, signal) {
  const cdx = `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(domain)}/*`
    + `&output=json&limit=4000&collapse=urlkey&fl=timestamp,original,statuscode`;
  const rows = await getJSON(cdx, { signal, timeout: 22000, maxBytes: 4 * 1024 * 1024 });
  if (!Array.isArray(rows) || rows.length < 2) return { total: 0, interesting: [] };

  const body = rows.slice(1);
  const stamps = body.map(r => String(r[0])).filter(Boolean).sort();
  const juicy = /\.(sql|bak|old|zip|tar|gz|env|log|config|ya?ml|json|xls|csv|pem|key)(\?|$)|\/(admin|backup|internal|debug|test|staging|api\/v\d|\.git)/i;

  return {
    total: body.length,
    range: stamps.length ? `${stamps[0].slice(0, 4)} → ${stamps[stamps.length - 1].slice(0, 4)}` : '',
    snapshot: {
      timestamp: fmtStamp(stamps[stamps.length - 1]),
      url: `https://web.archive.org/web/${stamps[stamps.length - 1] || ''}/https://${domain}`,
    },
    interesting: [...new Set(body.map(r => r[1]).filter(u => juicy.test(u)))].slice(0, 20),
  };
}
const fmtStamp = s => !s ? '' :
  `${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)} ${s.slice(8, 10)}:${s.slice(10, 12)}`;

/* ── Email harvesting from CT + archives + homepage ─────────── */
export async function emailHarvest(domain, signal) {
  const emails = new Set();
  const used = [];
  const rxMail = new RegExp(`[a-z0-9._%+\\-]+@(?:[a-z0-9-]+\\.)*${domain.replace(/\./g, '\\.')}`, 'gi');

  try {
    const r = await request(`https://${domain}/`, { signal, timeout: 10000 });
    for (const m of (r.body || '').matchAll(rxMail)) emails.add(m[0].toLowerCase());
    used.push('homepage crawl');
  } catch (_) {}

  for (const p of ['/contact', '/about', '/contact-us', '/impressum', '/legal']) {
    if (emails.size > 25) break;
    try {
      const r = await request(`https://${domain}${p}`, { signal, timeout: 8000 });
      if (r.ok) for (const m of (r.body || '').matchAll(rxMail)) emails.add(m[0].toLowerCase());
    } catch (_) {}
  }
  if (used.length) used.push('common contact pages');

  try {
    const rows = await getJSON(
      `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(domain)}/*&output=json&limit=400&collapse=urlkey&fl=original`,
      { signal, timeout: 15000 });
    for (const r of (rows || []).slice(1)) {
      for (const m of String(r[0]).matchAll(rxMail)) emails.add(m[0].toLowerCase());
    }
    used.push('wayback');
  } catch (_) {}

  return { domain, sources_used: used, emails: [...emails].sort().slice(0, 60) };
}

/* ── Breach intel via Hudson Rock's free OSINT endpoint ─────────
   Field names confirmed against the documented response:
   total, employees, users, third_parties, and the last-compromised dates. */
export async function breachIntel(domain, signal) {
  const blank = {
    total_infostealer_hits: 0, total_employees_leaked: 0,
    total_clients_leaked: 0, total_emails_found: 0, critical_findings: [],
  };

  let j;
  try {
    j = await getJSON(
      `https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain=${encodeURIComponent(domain)}`,
      { signal, timeout: 20000 });
  } catch (e) {
    if (e && e.name === 'AbortError') throw e;
    // Say the lookup failed. Reporting zeros would read as "nothing found".
    return { summary: blank, source: 'Hudson Rock', reachable: false,
             error: `Hudson Rock lookup failed: ${e.message || e}` };
  }

  const d = (j && j.data) || j || {};
  const n = v => Number(v) || 0;
  const stealer = n(d.total);
  const employees = n(d.employees);
  const users = n(d.users);
  const third = n(d.third_parties);

  const critical = [];
  if (employees) {
    critical.push({ source: 'Hudson Rock', type: 'Employee credentials exposed',
      detail: `${employees} employee credential set(s) recovered from infostealer logs`
        + (d.last_employee_compromised ? `, most recently ${String(d.last_employee_compromised).slice(0, 10)}.` : '.') });
  }
  if (users) {
    critical.push({ source: 'Hudson Rock', type: 'User credentials exposed',
      detail: `${users} user credential set(s) for this domain appear in stealer logs`
        + (d.last_user_compromised ? `, most recently ${String(d.last_user_compromised).slice(0, 10)}.` : '.') });
  }
  if (third) {
    critical.push({ source: 'Hudson Rock', type: 'Third-party exposure',
      detail: `${third} credential set(s) for third-party services used by this domain.` });
  }

  return {
    summary: {
      total_infostealer_hits: stealer,
      total_employees_leaked: employees,
      total_clients_leaked: users,
      total_emails_found: 0,
      critical_findings: critical,
    },
    third_parties: third,
    source: 'Hudson Rock (free OSINT endpoint)',
    reachable: true,
    note: stealer || employees || users
      ? undefined
      : 'Hudson Rock answered, and has no infostealer records for this domain.',
  };
}
