/* ════════════════════════════════════════════════════════════
   Modules 28 and 29 — CMS deep scan and hosting control panels.
   Ports of engine.py's scan_cms and scan_control_panels.

   The CMS module carries over whole: it is plain HTTP against
   the target's own origin, which is exactly what the extension
   can do.

   The panel module cannot. engine.py connects to ports 2083,
   8443, 10000 and the rest; a page cannot open a TCP socket, and
   the panels that answer on those ports almost always present a
   self-signed certificate, which fetch() rejects with no way to
   continue. So this side asks Shodan which panel ports are open
   — the same passive route the `ports` module already takes —
   and only then tries to confirm the interface over HTTP. Each
   panel is reported with how it was established, so a port that
   Shodan saw but the browser could not reach is never presented
   as a confirmed panel.
   ════════════════════════════════════════════════════════════ */

import { DATA } from './data/tables.js';
import { request, getJSON, mapLimit, dnsQuery } from './http.js';

const base = d => `https://${d}`;
const rx = (p, f) => { try { return new RegExp(p, f); } catch { return null; } };
const cmsName = c => (DATA.CMS_NAMES || {})[c] || (c || '');

/* Headers as one "k: v" blob, which is what the scoped patterns expect. */
const hblob = h => Object.entries(h || {}).map(([k, v]) => `${k}: ${v}`).join('\n');

/* ── platform fingerprint (shared with whatweb) ──────────────── */
export function platformFingerprint(body, headers) {
  const hb = hblob(headers);
  const both = body + hb;
  const out = new Set();
  for (const table of [DATA.WW_CMS_SIGS || {}, DATA.WW_ECOM_SIGS || {}]) {
    for (const [name, pats] of Object.entries(table)) {
      for (const pat of (Array.isArray(pats) ? pats : [pats])) {
        let src = pat, target = both;
        if (Array.isArray(pat)) { src = pat[1]; target = pat[0] === 'h' ? hb : body; }
        const re = rx(src, 'i');
        if (re && re.test(target)) { out.add(name); break; }
      }
    }
  }
  if (out.has('WordPress (login)') && out.has('WordPress')) out.delete('WordPress (login)');
  return [...out].sort();
}

/* ── detection ───────────────────────────────────────────────
   Weighted signals: 3 is conclusive on its own, 1 needs
   corroboration, threshold 3. Every signal is structural, so a
   page that merely writes about a CMS scores nothing. */
function detect(body, headers) {
  const hb = hblob(headers);
  const scores = {};
  const signals = {};
  for (const [cms, sigs] of Object.entries(DATA.CMS_SIGNALS || {})) {
    let score = 0;
    const hits = [];
    for (const [weight, where, pattern, proves] of sigs) {
      const re = rx(pattern, 'i');
      if (!re) continue;
      if (re.test(where === 'header' ? hb : body)) { score += weight; hits.push(proves); }
    }
    if (score) { scores[cms] = score; signals[cms] = hits; }
  }
  const ranked = Object.entries(scores).sort((a, b) => b[1] - a[1]);
  if (!ranked.length || ranked[0][1] < 3) {
    return { cms: null, confidence: 'none', score: 0, signals: [], candidates: scores };
  }
  const [cms, score] = ranked[0];
  return {
    cms, score, signals: signals[cms],
    confidence: score >= 6 ? 'high' : score >= 3 ? 'medium' : 'low',
    candidates: scores,
  };
}

/* ── version ────────────────────────────────────────────────── */
async function readVersion(domain, cms, home, signal) {
  for (const [path, pattern] of (DATA.CMS_VERSION_SOURCES || {})[cms] || []) {
    let body;
    if (path === '/' && home) {
      body = home.body || '';
    } else {
      try {
        const r = await request(base(domain) + path, { signal, timeout: 7000, maxBytes: 65536 });
        if (r.status !== 200) continue;
        body = r.body || '';
      } catch { continue; }
    }
    const re = rx(pattern, 'i');
    const m = re && re.exec(body);
    if (m && m[1]) return { version: m[1], source: path };
  }
  return { version: null, source: null };
}

/* ── path probing ───────────────────────────────────────────── */
async function probePaths(domain, cms, refs, findings, signal) {
  const rows = (DATA.CMS_PATHS || {})[cms] || [];
  let probed = 0;
  await mapLimit(rows, 6, async ([path, label, severity]) => {
    let r;
    try { r = await request(base(domain) + path, { signal, timeout: 7000, maxBytes: 65536 }); }
    catch { return; }
    probed++;
    if (r.status !== 200) return;
    // Same answer as the homepage or as a path that cannot exist: not a find.
    if (refs.some(ref => ref && r.status === ref.status
        && Math.abs(r.bytes - ref.bytes) < 64)) return;

    // Where engine.py states what proves this path, require it. A 200 alone is
    // not evidence: plenty of sites answer 200 for everything.
    const markers = (DATA.CMS_PATH_MARKERS || {})[path];
    if (markers && markers.length) {
      const body = r.body || '';
      if (!markers.some(mk => body.includes(mk))) return;
    }
    findings.push({
      name: `${cmsName(cms)} ${label}`, severity, path,
      url: base(domain) + path, status: r.status, size: r.bytes,
      detail: `${label} reachable at ${path}`,
      confidence: 'confirmed',
    });
  });
  return probed;
}

/* ── WordPress enumeration ──────────────────────────────────── */
async function enumerateWordPress(domain, home, findings, signal) {
  const users = [];
  try {
    const j = await getJSON(`${base(domain)}/wp-json/wp/v2/users`, { signal, timeout: 8000 });
    if (Array.isArray(j)) {
      for (const u of j) if (u && u.slug) users.push(u.slug);
    }
  } catch { /* closed REST API is the normal case */ }
  if (users.length) {
    findings.push({
      name: 'WordPress users enumerable via REST API', severity: 'medium',
      path: '/wp-json/wp/v2/users', url: `${base(domain)}/wp-json/wp/v2/users`,
      detail: `${users.length} account name(s) readable without authentication: `
        + users.slice(0, 8).join(', '),
      confidence: 'confirmed',
    });
  }

  const body = (home && home.body) || '';
  const plugins = {};
  const themes = {};
  for (const m of body.matchAll(/\/wp-content\/plugins\/([a-z0-9._-]+)\/[^"')\s]*?(?:\?ver=([\d.]+))?["')\s]/gi)) {
    plugins[m[1]] = plugins[m[1]] || m[2] || '';
  }
  for (const m of body.matchAll(/\/wp-content\/themes\/([a-z0-9._-]+)\/[^"')\s]*?(?:\?ver=([\d.]+))?["')\s]/gi)) {
    themes[m[1]] = themes[m[1]] || m[2] || '';
  }
  return { users, plugins, themes };
}

/* ── module 28 ──────────────────────────────────────────────── */
export async function cms(domain, signal) {
  let home = null;
  try { home = await request(base(domain) + '/', { signal, timeout: 10000, maxBytes: 131072 }); }
  catch { return { error: 'Target did not respond' }; }

  const det = detect(home.body || '', home.headers || {});
  const platforms = platformFingerprint(home.body || '', home.headers || {});
  const ecom = new Set(Object.keys(DATA.WW_ECOM_SIGS || {}));
  const deep = new Set(DATA.CMS_DEEP_SCANNED || []);

  const result = {
    cms: det.cms, cms_name: det.cms ? cmsName(det.cms) : null,
    confidence: det.confidence, detection_score: det.score,
    signals: det.signals, candidates: det.candidates,
    platforms,
    addons: platforms.filter(p => ecom.has(p)),
    not_deep_scanned: platforms.filter(p => !deep.has(p) && !ecom.has(p)),
    version: null, version_source: null,
    findings: [], users: [], plugins: {}, themes: {},
    paths_probed: 0, severity_counts: {},
  };

  if (!det.cms) {
    // A platform may be identified without deep checks existing for it. Saying
    // "no CMS" there would be wrong, and an empty card reads as a clean result.
    if (result.not_deep_scanned.length) {
      const n = result.not_deep_scanned;
      result.note = `${n.join(', ')} identified, but Kumo has no deep checks for `
        + `${n.length === 1 ? 'it' : 'them'} yet. `
        + 'Deep checks cover WordPress, Joomla and Drupal.';
    } else {
      const cands = Object.entries(result.candidates).map(([k, v]) => `${k}=${v}`).join(', ');
      result.note = cands ? `No CMS identified. Weak signals: ${cands}` : 'No CMS identified.';
    }
    return result;
  }

  if (platforms.includes(result.cms_name)) {
    result.corroborated_by = 'platform fingerprint';
    result.signals = [...result.signals, 'platform fingerprint agrees'];
  } else if (result.not_deep_scanned.length) {
    result.platform_conflict = `detected ${result.cms_name}, but fingerprinting also `
      + `matched ${result.not_deep_scanned.join(', ')}`;
  }

  const ver = await readVersion(domain, det.cms, home, signal);
  result.version = ver.version;
  result.version_source = ver.source;
  if (ver.version) {
    result.findings.push({
      name: `${result.cms_name} version disclosed`, severity: 'low',
      path: ver.source, detail: `${result.cms_name} ${ver.version} (from ${ver.source})`,
      // read from what the site states; a backported patch may not change it
      confidence: 'version-inference',
    });
  }

  // References for the catch-all guard: the homepage, and a path that cannot
  // exist. Without these, a site answering 200 for everything reports every path.
  let soft404 = null;
  try {
    soft404 = await request(
      `${base(domain)}/kumo-${Math.random().toString(36).slice(2, 10)}`,
      { signal, timeout: 7000, maxBytes: 32768 });
  } catch { /* a hard 404 is the good case */ }

  result.paths_probed = await probePaths(
    domain, det.cms, [home, soft404], result.findings, signal);

  if (det.cms === 'wordpress') {
    const e = await enumerateWordPress(domain, home, result.findings, signal);
    result.users = e.users; result.plugins = e.plugins; result.themes = e.themes;
  }

  for (const f of result.findings) {
    result.severity_counts[f.severity] = (result.severity_counts[f.severity] || 0) + 1;
  }
  result.total_findings = result.findings.length;
  return result;
}

/* ── module 29 ──────────────────────────────────────────────── */
export async function panels(domain, signal) {
  const panelDefs = DATA.PANELS || {};
  const proxied = new Set((DATA.CDN_PROXIED_PANEL_PORTS || []).map(Number));
  const panelPorts = new Set();
  for (const def of Object.values(panelDefs)) {
    for (const p of def.ports || []) panelPorts.add(Number(p));
  }

  const result = {
    domain, panels: [], findings: [], ports_open: [], ports_seen_passive: [],
    unconfirmed: [], unexplained_ports: [], cdn_note: '',
    method: 'passive port discovery (Shodan InternetDB), then HTTP confirmation',
  };

  // Step 1 — which panel ports are open, passively. A page cannot port-scan.
  const a = await dnsQuery(domain, 'A', { signal });
  const ips = a.map(r => r.data).slice(0, 2);
  if (!ips.length) return { ...result, error: 'No A record to look up' };

  const seen = new Set();
  const tags = new Set();
  for (const ip of ips) {
    try {
      const j = await getJSON(`https://internetdb.shodan.io/${ip}`, { signal, timeout: 9000 });
      for (const p of j.ports || []) if (panelPorts.has(Number(p))) seen.add(Number(p));
      for (const t of j.tags || []) tags.add(t);
    } catch { /* no record for this address is normal */ }
  }

  // Cloudflare proxies 2082-2096 and 8443 for every domain it fronts, so an
  // open port there is the edge and not this target's panel.
  const onCdn = [...tags].some(t => /cloudflare|cdn/i.test(t));
  let candidates = [...seen].sort((x, y) => x - y);
  if (onCdn) {
    const skipped = candidates.filter(p => proxied.has(p));
    candidates = candidates.filter(p => !proxied.has(p));
    if (skipped.length) {
      result.cdn_note = `ports ${skipped.join(', ')} are proxied by the CDN edge, `
        + 'not this host — excluded';
    }
  }
  result.ports_seen_passive = candidates;

  // Step 2 — confirm the interface where the browser can reach it. Most panels
  // use a self-signed certificate, which fetch() refuses outright, so a failure
  // here says nothing about whether a panel is there.
  await mapLimit(candidates, 4, async port => {
    const defs = Object.entries(panelDefs)
      .filter(([, d]) => (d.ports || []).map(Number).includes(port));
    let confirmed = false;
    for (const [name, def] of defs) {
      for (const path of (def.paths && def.paths.length ? def.paths : ['/'])) {
        for (const scheme of ['https', 'http']) {
          let r;
          try {
            r = await request(`${scheme}://${domain}:${port}${path}`,
              { signal, timeout: 6000, maxBytes: 65536 });
          } catch { continue; }
          const body = r.body || '', hb = hblob(r.headers);
          const hits = [];
          for (const [where, pattern, proves] of def.sig || []) {
            const re = rx(pattern, 'i');
            if (re && re.test(where === 'header' ? hb : body)) hits.push(proves);
          }
          if (!hits.length) continue;
          let version = null;
          if (def.version) {
            const vre = rx(def.version, 'i');
            const vm = vre && vre.exec(body);
            if (vm && vm[1]) version = vm[1];
          }
          result.panels.push({
            panel: name, port, url: `${scheme}://${domain}:${port}${path}`,
            signals: hits, version, confidence: 'confirmed',
          });
          result.findings.push({
            name: `${name} control panel reachable`, severity: def.severity || 'high',
            path, url: `${scheme}://${domain}:${port}${path}`,
            detail: `${name}${version ? ' ' + version : ''} login interface is reachable `
              + `from the internet on port ${port}. A control panel runs the server, `
              + 'not just the site — restrict it by IP.',
            confidence: 'confirmed',
          });
          confirmed = true;
          break;
        }
        if (confirmed) break;
      }
      if (confirmed) break;
    }
    if (confirmed) {
      result.ports_open.push(port);
    } else {
      // Shodan saw it open; the browser could not read it. Say exactly that.
      result.unconfirmed.push({
        port,
        candidates: defs.map(([n]) => n),
        reason: 'port reported open, but the browser could not read a login '
          + 'interface — usually a self-signed certificate, which a page cannot bypass',
      });
    }
  });

  result.ports_open.sort((x, y) => x - y);
  if (!candidates.length) {
    result.note = onCdn && result.cdn_note
      ? 'No non-proxied panel ports seen on this host.'
      : 'No control panel ports seen open on this host.';
  }
  return result;
}
